use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, ValueEnum};
use relay_attest::traits::Verifier;
use relay_core::secrets::ProviderCredential;
use relay_secret::{verify_secret_request, SecretRequest, SecretResponse};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

#[derive(Clone, Debug, ValueEnum)]
enum AttestationBackend {
    SevSnp,
    GcpConfidentialSpace,
    Mock,
}

#[derive(Debug, Parser)]
#[command(
    name = "trusted-relay-secret-broker",
    about = "Attestation-gated provider secret broker"
)]
struct Cli {
    /// Listen address for the broker HTTP API.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,

    /// Attestation backend to verify.
    #[arg(long, value_enum, default_value_t = AttestationBackend::SevSnp)]
    backend: AttestationBackend,

    /// Expected TEE measurement hex. Required for SEV-SNP strict mode; ignored for GCP Confidential Space.
    #[arg(long, default_value = "")]
    expected_measurement: String,

    /// Expected relay config hash hex. Required unless --allow-audit is used.
    #[arg(long, default_value = "", required_unless_present = "allow_audit")]
    expected_config_hash: String,

    /// Confidential Space custom audience.
    #[arg(
        long,
        env = "TRUSTED_RELAY_GCP_CS_AUDIENCE",
        default_value = "trusted-relay-attested-tls"
    )]
    gcp_cs_audience: String,

    /// Expected Confidential Space workload container image digest (`sha256:...`).
    #[arg(long, env = "TRUSTED_RELAY_GCP_CS_IMAGE_DIGEST")]
    gcp_cs_image_digest: Option<String>,

    /// Expected Confidential Space workload container image reference.
    #[arg(long, env = "TRUSTED_RELAY_GCP_CS_IMAGE_REFERENCE")]
    gcp_cs_image_reference: Option<String>,

    /// Expected Confidential Space container signature key ID. Can be repeated.
    #[arg(
        long,
        env = "TRUSTED_RELAY_GCP_CS_SIGNATURE_KEY_ID",
        value_delimiter = ','
    )]
    gcp_cs_signature_key_id: Vec<String>,

    /// Expected GCP service account running the Confidential Space workload.
    #[arg(long, env = "TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT")]
    gcp_cs_service_account: Option<String>,

    /// Expected GCP project ID for the Confidential Space VM.
    #[arg(long, env = "TRUSTED_RELAY_GCP_CS_PROJECT_ID")]
    gcp_cs_project_id: Option<String>,

    /// Expected GCP zone for the Confidential Space VM.
    #[arg(long, env = "TRUSTED_RELAY_GCP_CS_ZONE")]
    gcp_cs_zone: Option<String>,

    /// Allow audit mode without measurement/config pins. Do not use for production secrets.
    #[arg(long)]
    allow_audit: bool,

    /// Provider token to release after attestation succeeds.
    #[arg(long, env = "TRUSTED_RELAY_PROVIDER_TOKEN")]
    provider_token: String,

    /// Provider authorization scheme.
    #[arg(long, default_value = "Bearer")]
    provider_auth_scheme: String,

    /// Require one-time nonces and remember them in memory.
    #[arg(
        long,
        env = "TRUSTED_RELAY_REQUIRE_FRESH_NONCE",
        default_value_t = true
    )]
    require_fresh_nonce: bool,

    /// PEM certificate chain for HTTPS broker mode.
    #[arg(long, env = "TRUSTED_RELAY_SECRET_BROKER_TLS_CERT_PEM")]
    tls_cert_pem: Option<String>,

    /// PEM private key for HTTPS broker mode.
    #[arg(long, env = "TRUSTED_RELAY_SECRET_BROKER_TLS_KEY_PEM")]
    tls_key_pem: Option<String>,

    /// Allow cleartext HTTP broker mode. Development only.
    #[arg(
        long,
        env = "TRUSTED_RELAY_SECRET_BROKER_ALLOW_HTTP",
        default_value_t = false
    )]
    allow_http: bool,
}

#[derive(Clone)]
struct AppState {
    verifier: Arc<dyn Verifier>,
    expected_measurement: Option<Vec<u8>>,
    expected_config_hash: Option<[u8; 32]>,
    provider_credential: ProviderCredential,
    require_fresh_nonce: bool,
    seen_nonces: Arc<Mutex<HashSet<String>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let verifier = verifier_for_backend(&cli)?;
    let expected_measurement = match cli.backend {
        AttestationBackend::GcpConfidentialSpace => None,
        _ if cli.allow_audit && cli.expected_measurement.is_empty() => None,
        _ if cli.expected_measurement.is_empty() => {
            anyhow::bail!(
                "--expected-measurement is required for {:?} unless --allow-audit is used",
                cli.backend
            )
        }
        _ => Some(
            parse_hex_vec(&cli.expected_measurement).context("invalid --expected-measurement")?,
        ),
    };
    let expected_config_hash = if cli.allow_audit {
        if cli.expected_config_hash.is_empty() {
            None
        } else {
            Some(
                parse_hash32(&cli.expected_config_hash)
                    .context("invalid --expected-config-hash")?,
            )
        }
    } else {
        Some(parse_hash32(&cli.expected_config_hash).context("invalid --expected-config-hash")?)
    };

    if cli.allow_audit {
        tracing::warn!(
            "secret broker audit mode enabled; provider secrets may be released without measurement/config pins"
        );
    }

    let state = AppState {
        verifier,
        expected_measurement,
        expected_config_hash,
        provider_credential: ProviderCredential {
            auth_scheme: cli.provider_auth_scheme.clone(),
            token: cli.provider_token.clone(),
        },
        require_fresh_nonce: cli.require_fresh_nonce,
        seen_nonces: Arc::new(Mutex::new(HashSet::new())),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/secret/provider", post(issue_secret))
        .with_state(state);

    let addr: SocketAddr = cli.listen.parse().context("invalid --listen")?;
    let listener = TcpListener::bind(addr).await?;
    let tls_acceptor = broker_tls_acceptor(&cli)?;
    validate_transport_security(&cli, tls_acceptor.is_some())?;

    tracing::info!(
        %addr,
        backend = ?cli.backend,
        tls = tls_acceptor.is_some(),
        "secret broker listening"
    );

    match tls_acceptor {
        Some(tls_acceptor) => serve_tls(listener, app, tls_acceptor).await?,
        None => axum::serve(listener, app).await?,
    }
    Ok(())
}

async fn serve_tls(listener: TcpListener, app: Router, tls_acceptor: TlsAcceptor) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        tracing::debug!(%peer_addr, error = %e, "broker connection ended");
                    }
                }
                Err(e) => tracing::debug!(%peer_addr, error = %e, "broker TLS handshake failed"),
            }
        });
    }
}

fn validate_transport_security(cli: &Cli, tls_enabled: bool) -> Result<()> {
    if !tls_enabled && !cli.allow_http {
        anyhow::bail!(
            "secret broker must use HTTPS; provide --tls-cert-pem/--tls-key-pem or set --allow-http only for local dev"
        );
    }
    Ok(())
}

fn broker_tls_acceptor(cli: &Cli) -> Result<Option<TlsAcceptor>> {
    match (&cli.tls_cert_pem, &cli.tls_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let (cert_chain, private_key) = load_cert_chain_and_key(cert_pem, key_pem)?;
            let mut server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .context("invalid broker TLS certificate/key")?;
            server_config.send_tls13_tickets = 0;
            Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
        }
        (None, None) => Ok(None),
        _ => anyhow::bail!("broker TLS requires both certificate and private key PEM"),
    }
}

fn load_cert_chain_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_chain = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("broker TLS certificate PEM is invalid")?;
    if cert_chain.is_empty() {
        anyhow::bail!("broker TLS certificate PEM does not contain certificates");
    }

    let private_key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.as_bytes()))
        .context("broker TLS private key PEM is invalid")?
        .context("broker TLS private key PEM does not contain a private key")?;
    Ok((cert_chain, private_key))
}

async fn issue_secret(
    State(state): State<AppState>,
    Json(request): Json<SecretRequest>,
) -> Result<Json<SecretResponse>, (StatusCode, String)> {
    if state.require_fresh_nonce {
        let nonce = request.nonce.trim().to_string();
        if nonce.len() < 16 {
            tracing::warn!("secret request rejected due to short nonce");
            return Err((
                StatusCode::FORBIDDEN,
                "secret request nonce must be at least 16 characters".to_string(),
            ));
        }
    }

    verify_secret_request(
        &request,
        state.verifier.clone(),
        state.expected_measurement.as_deref(),
        state.expected_config_hash,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "secret request rejected");
        (StatusCode::FORBIDDEN, format!("attestation rejected: {e}"))
    })?;

    if state.require_fresh_nonce {
        let nonce = request.nonce.trim().to_string();
        let mut seen = state.seen_nonces.lock().await;
        if !seen.insert(nonce) {
            tracing::warn!("secret request rejected due to replayed nonce");
            return Err((
                StatusCode::FORBIDDEN,
                "secret request nonce was already used".to_string(),
            ));
        }
    }

    tracing::info!(nonce = %request.nonce, "secret request accepted");
    Ok(Json(SecretResponse {
        provider_credential: state.provider_credential,
    }))
}

fn verifier_for_backend(cli: &Cli) -> Result<Arc<dyn Verifier>> {
    match &cli.backend {
        AttestationBackend::SevSnp => {
            #[cfg(feature = "sev-snp")]
            {
                Ok(Arc::new(relay_attest::sev_snp::SevSnpVerifier))
            }
            #[cfg(not(feature = "sev-snp"))]
            {
                anyhow::bail!("backend=sev-snp requires the sev-snp feature")
            }
        }
        AttestationBackend::GcpConfidentialSpace => {
            #[cfg(feature = "gcp-confidential-space")]
            {
                let mut policy =
                    relay_attest::gcp_confidential_space::GcpConfidentialSpacePolicy::new(
                        cli.gcp_cs_audience.clone(),
                    );
                policy.image_digest = cli.gcp_cs_image_digest.clone();
                policy.image_reference = cli.gcp_cs_image_reference.clone();
                policy.signature_key_ids = cli.gcp_cs_signature_key_id.clone();
                policy.service_account = cli.gcp_cs_service_account.clone();
                policy.project_id = cli.gcp_cs_project_id.clone();
                policy.zone = cli.gcp_cs_zone.clone();
                if cli.allow_audit {
                    Ok(Arc::new(
                        relay_attest::gcp_confidential_space::GcpConfidentialSpaceVerifier::new_audit(
                            policy,
                        ),
                    ))
                } else {
                    Ok(Arc::new(
                        relay_attest::gcp_confidential_space::GcpConfidentialSpaceVerifier::new(
                            policy,
                        )?,
                    ))
                }
            }
            #[cfg(not(feature = "gcp-confidential-space"))]
            {
                anyhow::bail!(
                    "backend=gcp-confidential-space requires the gcp-confidential-space feature"
                )
            }
        }
        AttestationBackend::Mock => {
            #[cfg(feature = "mock")]
            {
                Ok(Arc::new(relay_attest::mock::MockVerifier))
            }
            #[cfg(not(feature = "mock"))]
            {
                anyhow::bail!("backend=mock requires the mock feature")
            }
        }
    }
}

fn parse_hex_vec(raw: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(strip_0x(raw))?)
}

fn parse_hash32(raw: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(strip_0x(raw))?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte hash, got {} bytes", bytes.len());
    }
    Ok(bytes.try_into().expect("length checked"))
}

fn strip_0x(raw: &str) -> &str {
    raw.strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn broker_bin() -> PathBuf {
        std::env::var_os("CARGO_BIN_EXE_trusted-relay-secret-broker")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join("target/debug/trusted-relay-secret-broker")
            })
    }

    #[test]
    fn broker_cli_requires_pins_unless_audit_is_explicit() {
        let output = Command::new(broker_bin())
            .env("TRUSTED_RELAY_PROVIDER_TOKEN", "dummy")
            .output()
            .unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--expected-measurement"), "{stderr}");
        assert!(stderr.contains("--expected-config-hash"), "{stderr}");
    }

    #[test]
    fn broker_cli_allows_pinless_mode_only_with_audit_flag() {
        let output = Command::new(broker_bin())
            .env("TRUSTED_RELAY_PROVIDER_TOKEN", "dummy")
            .arg("--allow-audit")
            .arg("--listen")
            .arg("127.0.0.1:0")
            .output()
            .unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("required arguments were not provided"),
            "{stderr}"
        );
    }

    #[test]
    fn broker_requires_tls_unless_http_is_explicitly_allowed() {
        let mut cli = Cli {
            listen: "127.0.0.1:8787".to_string(),
            backend: AttestationBackend::SevSnp,
            expected_measurement: String::new(),
            expected_config_hash: String::new(),
            gcp_cs_audience: "trusted-relay-attested-tls".to_string(),
            gcp_cs_image_digest: None,
            gcp_cs_image_reference: None,
            gcp_cs_signature_key_id: Vec::new(),
            gcp_cs_service_account: None,
            gcp_cs_project_id: None,
            gcp_cs_zone: None,
            allow_audit: true,
            provider_token: "dummy".to_string(),
            provider_auth_scheme: "Bearer".to_string(),
            require_fresh_nonce: true,
            tls_cert_pem: None,
            tls_key_pem: None,
            allow_http: false,
        };

        let err = validate_transport_security(&cli, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must use HTTPS"), "{err}");

        cli.allow_http = true;
        assert!(validate_transport_security(&cli, false).is_ok());
        cli.allow_http = false;
        assert!(validate_transport_security(&cli, true).is_ok());
    }
}
