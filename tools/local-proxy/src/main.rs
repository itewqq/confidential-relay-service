use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use relay_attest::traits::Verifier;
use tracing_subscriber::EnvFilter;
use trusted_relay_local::RunConfig;

#[derive(Clone, Debug, ValueEnum)]
enum AttestationBackend {
    SevSnp,
    GcpConfidentialSpace,
    Mock,
}

#[derive(Debug, Parser)]
#[command(
    name = "trusted-relay-local",
    about = "Local OpenAI-compatible proxy with remote CVM attestation"
)]
struct Cli {
    /// Local HTTP listen address for local apps.
    #[arg(long, default_value = "127.0.0.1:11434")]
    listen: String,

    /// Attested relay endpoint, for example https://relay.internal:8443.
    #[arg(long)]
    relay_endpoint: String,

    /// Optional HTTP CONNECT gateway address host:port.
    #[arg(long)]
    gateway_addr: Option<String>,

    /// Gateway bearer token for CONNECT authentication.
    #[arg(long, env = "TRUSTED_RELAY_GATEWAY_TOKEN")]
    gateway_token: Option<String>,

    /// Attestation verifier backend.
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

    /// Allow audit mode without measurement/config pins. Do not use for production traffic.
    #[arg(long)]
    allow_audit: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let listen: SocketAddr = cli.listen.parse().context("invalid --listen")?;
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
        tracing::warn!("local proxy audit mode enabled; measurement/config pins are not enforced");
    }

    trusted_relay_local::run(RunConfig {
        listen,
        relay_endpoint: cli.relay_endpoint,
        gateway_addr: cli.gateway_addr,
        gateway_token: cli.gateway_token,
        verifier,
        expected_measurement,
        expected_config_hash,
    })
    .await
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
