use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
#[cfg(feature = "gcp-confidential-space")]
use relay_attest::gcp_confidential_space::{
    GcpConfidentialSpacePolicy, GcpConfidentialSpaceVerifier,
};
use relay_attest::quote::{extract_evidence_from_cert, extract_spki_from_cert};
#[cfg(feature = "sev-snp")]
use relay_attest::sev_snp::SevSnpVerifier;
use relay_attest::traits::Verifier;
use relay_attest::types::TeeType;
use relay_core::config::{ProviderConfig, RelayConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::verify_tls12_signature as crypto_verify_tls12;
use rustls::crypto::verify_tls13_signature as crypto_verify_tls13;
use rustls::pki_types::ServerName;
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha384};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

const REPORT_DATA_OFFSET: usize = 0x50;
const REPORT_DATA_LEN: usize = 64;
const MEASUREMENT_OFFSET: usize = 0x90;
const MEASUREMENT_LEN: usize = 48;
const POLICY_OFFSET: usize = 0x08;
const REPORTED_TCB_OFFSET: usize = 0x180;
const CHIP_ID_OFFSET: usize = 0x1A0;
const CHIP_ID_LEN: usize = 64;
const POLICY_DEBUG_ALLOWED_BIT: u64 = 1 << 19;

#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    /// Verify real evidence and TLS key binding, but do not pin workload identity/config.
    Audit,
    /// Verify real evidence, TLS key binding, workload identity, and config hash.
    Strict,
}

#[derive(Clone, Debug, ValueEnum)]
enum Backend {
    SevSnp,
    GcpConfidentialSpace,
}

#[derive(Debug, Parser)]
#[command(
    name = "trusted-relay-online-check",
    about = "Verify a live Trusted Relay endpoint with real attestation"
)]
struct Cli {
    /// Relay HTTPS endpoint, for example https://127.0.0.1:9443.
    #[arg(long)]
    endpoint: String,

    /// Verification backend.
    #[arg(long, value_enum, default_value_t = Backend::SevSnp)]
    backend: Backend,

    /// Verification mode.
    #[arg(long, value_enum, default_value_t = Mode::Audit)]
    mode: Mode,

    /// Expected SEV-SNP MEASUREMENT hex. Required in strict mode unless --print-only is used.
    #[arg(long)]
    expected_measurement: Option<String>,

    /// Expected RelayConfig::config_hash hex. Required in strict mode unless config inputs are supplied.
    #[arg(long)]
    expected_config_hash: Option<String>,

    /// Compute expected config hash from these server config inputs.
    #[arg(long, default_value = "https://api.openai.com")]
    upstream: String,

    /// Allowed upstream URL. May be repeated. If omitted, mirrors server behavior by allowing --upstream.
    #[arg(long)]
    allowed_upstream: Vec<String>,

    /// Optional model-prefix route in the form prefix=base_url or prefix=base_url|/path.
    #[arg(long)]
    route: Vec<String>,

    /// Maximum request body size used by the server config hash.
    #[arg(long, default_value_t = 1_048_576)]
    max_request_bytes: usize,

    /// Published release/workload artifact sha256 digest used by the server config hash.
    #[arg(long)]
    release_artifact_digest: Option<String>,

    /// Upstream timeout seconds used by the server config hash.
    #[arg(long, default_value_t = 120)]
    upstream_timeout_secs: u64,

    /// Only fetch and print measurement/config/report details; do not enforce strict pins.
    #[arg(long)]
    print_only: bool,

    /// Confidential Space custom audience.
    #[arg(long, default_value = "trusted-relay-attested-tls")]
    gcp_cs_audience: String,

    /// Expected Confidential Space workload container image digest (`sha256:...`).
    #[arg(long)]
    gcp_cs_image_digest: Option<String>,

    /// Expected Confidential Space workload container image reference.
    #[arg(long)]
    gcp_cs_image_reference: Option<String>,

    /// Expected Confidential Space container signature key ID. Can be repeated.
    #[arg(long, value_delimiter = ',')]
    gcp_cs_signature_key_id: Vec<String>,

    /// Expected GCP service account running the Confidential Space workload.
    #[arg(long)]
    gcp_cs_service_account: Option<String>,

    /// Expected GCP project ID for the Confidential Space VM.
    #[arg(long)]
    gcp_cs_project_id: Option<String>,

    /// Expected GCP zone for the Confidential Space VM.
    #[arg(long)]
    gcp_cs_zone: Option<String>,

    /// Send a minimal HTTP GET /health after attestation succeeds.
    #[arg(long)]
    health: bool,
}

#[derive(Debug)]
struct CapturedCert {
    der: Vec<u8>,
    health_response: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let endpoint = Url::parse(&cli.endpoint).context("--endpoint must be a valid URL")?;
    if endpoint.scheme() != "https" {
        anyhow::bail!("--endpoint must use https://");
    }

    let expected_measurement = parse_optional_hex::<MEASUREMENT_LEN>(
        cli.expected_measurement.as_deref(),
        "--expected-measurement",
    )?;
    let expected_config_hash = match cli.expected_config_hash.as_deref() {
        Some(raw) => Some(parse_hex_array::<32>(raw, "--expected-config-hash")?),
        None => {
            if matches!(cli.mode, Mode::Strict) || cli.print_only {
                Some(compute_expected_config_hash(&cli)?)
            } else {
                None
            }
        }
    };

    if matches!(cli.mode, Mode::Strict) && !cli.print_only {
        if matches!(cli.backend, Backend::SevSnp) && expected_measurement.is_none() {
            anyhow::bail!("strict SEV-SNP mode requires --expected-measurement");
        }
        if matches!(cli.backend, Backend::GcpConfidentialSpace)
            && cli.gcp_cs_image_digest.is_none()
            && cli.gcp_cs_signature_key_id.is_empty()
        {
            anyhow::bail!(
                "strict GCP Confidential Space mode requires --gcp-cs-image-digest or --gcp-cs-signature-key-id"
            );
        }
        if expected_config_hash.is_none() {
            anyhow::bail!(
                "strict mode requires --expected-config-hash or enough config inputs to compute it"
            );
        }
    }

    let cert = fetch_cert_with_optional_health(&endpoint, cli.health).await?;
    let evidence = extract_evidence_from_cert(&cert.der).context("certificate lacks evidence")?;
    let expected_tee_type = match cli.backend {
        Backend::SevSnp => TeeType::SevSnp,
        Backend::GcpConfidentialSpace => TeeType::GcpConfidentialSpace,
    };
    if evidence.tee_type != expected_tee_type {
        anyhow::bail!(
            "expected {:?} evidence, got {:?}",
            expected_tee_type,
            evidence.tee_type
        );
    }

    let spki = extract_spki_from_cert(&cert.der).context("failed to extract cert SPKI")?;
    let cert_spki_hash = Sha384::digest(&spki);
    let subject = certificate_subject(&cert.der).unwrap_or_else(|_| "<unparseable>".to_string());

    match cli.backend {
        Backend::SevSnp => {
            let details = report_details(&evidence.data)?;
            print_report(
                &subject,
                cert.der.len(),
                &cert_spki_hash,
                &details,
                expected_config_hash,
            );
        }
        Backend::GcpConfidentialSpace => {
            print_gcp_confidential_space_token(
                &subject,
                cert.der.len(),
                &cert_spki_hash,
                &evidence.data,
            )?;
        }
    }

    if cli.print_only {
        print_health(cert.health_response.as_deref());
        return Ok(());
    }

    let verifier = verifier_for_backend(&cli)?;
    let expected_reportdata = expected_reportdata(&cert_spki_hash, expected_config_hash);
    let expected_attestation_data = match cli.backend {
        Backend::SevSnp => match cli.mode {
            Mode::Audit => None,
            Mode::Strict => expected_measurement.map(Vec::from),
        },
        Backend::GcpConfidentialSpace => Some(expected_reportdata.to_vec()),
    };
    let config_hash_for_verify = match cli.mode {
        Mode::Audit => None,
        Mode::Strict => expected_config_hash,
    };

    let reportdata = verifier
        .verify(&evidence, expected_attestation_data.as_deref())
        .context("attestation evidence verification failed")?;
    verify_reportdata(&reportdata, &cert_spki_hash, config_hash_for_verify)?;

    println!(
        "RESULT: OK - {:?}/{:?} verification succeeded",
        cli.backend, cli.mode
    );
    print_health(cert.health_response.as_deref());
    Ok(())
}

fn verifier_for_backend(cli: &Cli) -> Result<Arc<dyn Verifier>> {
    match cli.backend {
        Backend::SevSnp => {
            #[cfg(feature = "sev-snp")]
            {
                Ok(Arc::new(SevSnpVerifier) as Arc<dyn Verifier>)
            }
            #[cfg(not(feature = "sev-snp"))]
            {
                anyhow::bail!("backend=sev-snp requires the sev-snp feature")
            }
        }
        Backend::GcpConfidentialSpace => {
            #[cfg(feature = "gcp-confidential-space")]
            {
                let mut policy = GcpConfidentialSpacePolicy::new(cli.gcp_cs_audience.clone());
                policy.image_digest = cli.gcp_cs_image_digest.clone();
                policy.image_reference = cli.gcp_cs_image_reference.clone();
                policy.signature_key_ids = cli.gcp_cs_signature_key_id.clone();
                policy.service_account = cli.gcp_cs_service_account.clone();
                policy.project_id = cli.gcp_cs_project_id.clone();
                policy.zone = cli.gcp_cs_zone.clone();
                if matches!(cli.mode, Mode::Audit) {
                    Ok(Arc::new(GcpConfidentialSpaceVerifier::new_audit(policy))
                        as Arc<dyn Verifier>)
                } else {
                    Ok(Arc::new(GcpConfidentialSpaceVerifier::new(policy)?) as Arc<dyn Verifier>)
                }
            }
            #[cfg(not(feature = "gcp-confidential-space"))]
            {
                anyhow::bail!(
                    "backend=gcp-confidential-space requires the gcp-confidential-space feature"
                )
            }
        }
    }
}

fn expected_reportdata(cert_spki_hash: &[u8], expected_config_hash: Option<[u8; 32]>) -> [u8; 64] {
    let mut reportdata = [0u8; 64];
    reportdata[..48].copy_from_slice(&cert_spki_hash[..48]);
    if let Some(hash) = expected_config_hash {
        reportdata[48..64].copy_from_slice(&hash[..16]);
    }
    reportdata
}

fn print_gcp_confidential_space_token(
    subject: &str,
    cert_len: usize,
    cert_spki_hash: &[u8],
    token: &[u8],
) -> Result<()> {
    let token = std::str::from_utf8(token).context("Confidential Space token is not UTF-8")?;
    let claims = decode_jwt_claims_without_verification(token)?;
    println!("certificate.subject={subject}");
    println!("certificate.der_len={cert_len}");
    println!("certificate.spki_sha384={}", hex::encode(cert_spki_hash));
    println!("token.issuer={}", json_string(&claims, "iss"));
    println!("token.audience={}", json_string(&claims, "aud"));
    println!("token.swname={}", json_string(&claims, "swname"));
    println!("token.dbgstat={}", json_string(&claims, "dbgstat"));
    println!(
        "token.service_accounts={}",
        json_value(&claims, "google_service_accounts")
    );
    if let Some(submods) = claims.get("submods") {
        if let Some(container) = submods.get("container") {
            println!(
                "token.container.image_digest={}",
                json_string(container, "image_digest")
            );
            println!(
                "token.container.image_reference={}",
                json_string(container, "image_reference")
            );
            println!(
                "token.container.image_signatures={}",
                container
                    .get("image_signatures")
                    .map(serde_json::Value::to_string)
                    .unwrap_or_else(|| "null".to_string())
            );
        }
        if let Some(gce) = submods.get("gce") {
            println!("token.gce.project_id={}", json_string(gce, "project_id"));
            println!("token.gce.zone={}", json_string(gce, "zone"));
            println!(
                "token.gce.instance_name={}",
                json_string(gce, "instance_name")
            );
        }
    }
    Ok(())
}

fn decode_jwt_claims_without_verification(token: &str) -> Result<serde_json::Value> {
    let payload = token
        .split('.')
        .nth(1)
        .context("JWT lacks payload segment")?;
    let bytes = base64_url_decode(payload)?;
    serde_json::from_slice(&bytes).context("JWT payload is not JSON")
}

fn base64_url_decode(raw: &str) -> Result<Vec<u8>> {
    let mut input = raw.replace('-', "+").replace('_', "/");
    while input.len() % 4 != 0 {
        input.push('=');
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .context("invalid base64url")
}

fn json_string(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>")
        .to_string()
}

fn json_value(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| "null".to_string())
}

fn compute_expected_config_hash(cli: &Cli) -> Result<[u8; 32]> {
    let mut routes = BTreeMap::new();
    for raw in &cli.route {
        let (prefix, rest) = raw
            .split_once('=')
            .with_context(|| format!("invalid --route '{raw}', expected prefix=base_url"))?;
        let (base_url, path) = rest
            .split_once('|')
            .map(|(base, path)| (base.to_string(), Some(path.to_string())))
            .unwrap_or_else(|| (rest.to_string(), None));
        routes.insert(prefix.to_string(), ProviderConfig { base_url, path });
    }

    let allowed_upstreams = if cli.allowed_upstream.is_empty() {
        vec![cli.upstream.clone()]
    } else {
        cli.allowed_upstream.clone()
    };

    let config = RelayConfig {
        listen_addr: "0.0.0.0:8443".to_string(),
        default_upstream: cli.upstream.clone(),
        routes,
        allowed_upstreams,
        max_request_bytes: cli.max_request_bytes,
        release_artifact_digest: cli.release_artifact_digest.clone(),
        upstream_timeout_secs: cli.upstream_timeout_secs,
    };
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("provided config inputs are invalid: {e}"))?;
    Ok(config.config_hash())
}

async fn fetch_cert_with_optional_health(endpoint: &Url, health: bool) -> Result<CapturedCert> {
    let host = endpoint
        .host_str()
        .context("endpoint must include host")?
        .to_string();
    let port = endpoint
        .port_or_known_default()
        .context("endpoint must include or imply port")?;
    let addr = format!("{host}:{port}");
    let server_name = ServerName::try_from(host.clone()).context("invalid TLS server name")?;

    let tls_config = capture_client_config();
    let connector = TlsConnector::from(tls_config);
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("failed to connect to {addr}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("attested TLS handshake failed")?;

    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .context("server did not present a certificate")?;

    let health_response = if health {
        let path = health_path(endpoint);
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await?;
        Some(String::from_utf8_lossy(&response).to_string())
    } else {
        None
    };

    Ok(CapturedCert {
        der: cert,
        health_response,
    })
}

#[derive(Debug)]
struct CaptureOnlyVerifier;

impl ServerCertVerifier for CaptureOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let provider = rustls::crypto::ring::default_provider();
        crypto_verify_tls12(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let provider = rustls::crypto::ring::default_provider();
        crypto_verify_tls13(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn capture_client_config() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CaptureOnlyVerifier))
            .with_no_client_auth(),
    )
}

fn health_path(endpoint: &Url) -> String {
    let mut path = endpoint.path().trim_end_matches('/').to_string();
    if path.is_empty() {
        path.push('/');
    }
    if path == "/" {
        "/health".to_string()
    } else {
        format!("{path}/health")
    }
}

fn report_details(report: &[u8]) -> Result<ReportDetails> {
    let reportdata = slice(report, REPORT_DATA_OFFSET, REPORT_DATA_LEN, "REPORTDATA")?;
    let measurement = slice(report, MEASUREMENT_OFFSET, MEASUREMENT_LEN, "MEASUREMENT")?;
    let policy = u64::from_le_bytes(slice(report, POLICY_OFFSET, 8, "POLICY")?.try_into()?);
    let reported_tcb =
        u64::from_le_bytes(slice(report, REPORTED_TCB_OFFSET, 8, "REPORTED_TCB")?.try_into()?);
    let chip_id = slice(report, CHIP_ID_OFFSET, CHIP_ID_LEN, "CHIP_ID")?;

    Ok(ReportDetails {
        reportdata: reportdata.to_vec(),
        measurement: measurement.to_vec(),
        policy,
        debug_allowed: policy & POLICY_DEBUG_ALLOWED_BIT != 0,
        reported_tcb,
        chip_id_prefix: hex::encode(&chip_id[..8]),
    })
}

#[derive(Debug)]
struct ReportDetails {
    reportdata: Vec<u8>,
    measurement: Vec<u8>,
    policy: u64,
    debug_allowed: bool,
    reported_tcb: u64,
    chip_id_prefix: String,
}

fn print_report(
    subject: &str,
    cert_len: usize,
    cert_spki_hash: &[u8],
    details: &ReportDetails,
    expected_config_hash: Option<[u8; 32]>,
) {
    println!("certificate.subject={subject}");
    println!("certificate.der_len={cert_len}");
    println!("certificate.spki_sha384={}", hex::encode(cert_spki_hash));
    println!("report.measurement={}", hex::encode(&details.measurement));
    println!("report.reportdata={}", hex::encode(&details.reportdata));
    println!(
        "report.reportdata_spki={}",
        hex::encode(&details.reportdata[..48])
    );
    println!(
        "report.reportdata_config16={}",
        hex::encode(&details.reportdata[48..64])
    );
    println!("report.policy=0x{:016x}", details.policy);
    println!("report.debug_allowed={}", details.debug_allowed);
    println!("report.reported_tcb=0x{:016x}", details.reported_tcb);
    println!("report.chip_id_prefix={}", details.chip_id_prefix);
    if let Some(hash) = expected_config_hash {
        println!("expected.config_hash={}", hex::encode(hash));
        println!("expected.config_hash16={}", hex::encode(&hash[..16]));
    }
}

fn print_health(response: Option<&str>) {
    if let Some(response) = response {
        let status_line = response.lines().next().unwrap_or("<empty>");
        let body = response.rsplit("\r\n\r\n").next().unwrap_or("").trim();
        println!("health.status={status_line}");
        println!("health.body={body}");
    }
}

fn verify_reportdata(
    actual: &[u8; 64],
    cert_spki_hash: &[u8],
    expected_config_hash: Option<[u8; 32]>,
) -> Result<()> {
    if actual[..48] != cert_spki_hash[..48] {
        anyhow::bail!(
            "REPORTDATA SPKI binding mismatch: expected {}, actual {}",
            hex::encode(&cert_spki_hash[..48]),
            hex::encode(&actual[..48])
        );
    }

    if let Some(config_hash) = expected_config_hash {
        if actual[48..64] != config_hash[..16] {
            anyhow::bail!(
                "REPORTDATA config hash mismatch: expected {}, actual {}",
                hex::encode(&config_hash[..16]),
                hex::encode(&actual[48..64])
            );
        }
    }

    Ok(())
}

fn certificate_subject(cert_der: &[u8]) -> Result<String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("failed to parse certificate: {e}"))?;
    Ok(cert.subject().to_string())
}

fn parse_optional_hex<const N: usize>(raw: Option<&str>, label: &str) -> Result<Option<[u8; N]>> {
    raw.map(|value| parse_hex_array(value, label)).transpose()
}

fn parse_hex_array<const N: usize>(raw: &str, label: &str) -> Result<[u8; N]> {
    let clean = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let bytes = hex::decode(clean).with_context(|| format!("{label} is not valid hex"))?;
    if bytes.len() != N {
        anyhow::bail!(
            "{label} must decode to {N} bytes, got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes.try_into().expect("length checked"))
}

fn slice<'a>(buf: &'a [u8], offset: usize, len: usize, label: &str) -> Result<&'a [u8]> {
    buf.get(offset..offset + len)
        .with_context(|| format!("report too short for {label}"))
}
