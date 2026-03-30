//! Trusted Relay server binary.
//!
//! Starts an attested TLS server that proxies OpenAI-compatible API requests.
//! In development mode (--mock), uses mock attestation that works on any platform.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use relay_attest::Attester;
use relay_core::config::RelayConfig;
use relay_core::proxy::AppState;
use relay_core::router::build_router;
use relay_tls::server::AttestedTlsServer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "trusted-relay-server", about = "Confidential LLM API proxy")]
struct Cli {
    /// Listen address (e.g. 0.0.0.0:8443)
    #[arg(short, long, default_value = "0.0.0.0:8443")]
    listen: String,

    /// Default upstream URL
    #[arg(short, long, default_value = "https://api.openai.com")]
    upstream: String,

    /// Allowed upstream URL origins. Can be specified multiple times.
    /// Only these origins will be forwarded to. If none are given the default
    /// upstream is automatically added to the allowlist.
    /// Example: --allowed-upstream https://api.openai.com --allowed-upstream https://api.anthropic.com
    #[arg(long)]
    allowed_upstream: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Install the rustls crypto provider (ring) before any TLS operations.
    // This must happen before AttestedTlsServer::new() which calls rustls::ServerConfig::builder().
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider — was it already installed?");

    let cli = Cli::parse();

    // Select attester based on available TEE.
    let attester: Box<dyn Attester> = select_attester();
    tracing::info!("attestation backend: {}", attester_name(&*attester));

    // Build relay config and app state.
    // Build the upstream allowlist. If the user didn't provide any explicit
    // entries, automatically allowlist the default upstream so the server
    // doesn't silently accept arbitrary destinations.
    let allowed_upstreams = if cli.allowed_upstream.is_empty() {
        tracing::info!(
            default = %cli.upstream,
            "no --allowed-upstream flags given; auto-allowing the default upstream"
        );
        vec![cli.upstream.clone()]
    } else {
        cli.allowed_upstream
    };

    let config = Arc::new(RelayConfig {
        listen_addr: cli.listen.clone(),
        default_upstream: cli.upstream,
        allowed_upstreams,
        ..Default::default()
    });

    // Validate configuration at startup (catches disallowed upstreams early).
    config.validate().map_err(|e| anyhow::anyhow!("config validation failed: {e}"))?;

    // Compute the config hash for attestation binding.
    // This binds the relay's upstream configuration into the attestation REPORTDATA,
    // so clients can verify which upstreams the relay is permitted to contact.
    let config_hash = config.config_hash();
    tracing::info!(
        config_hash = %hex::encode(config_hash),
        "computed configuration hash for attestation binding"
    );

    // Build attested TLS server config with config hash bound into REPORTDATA.
    let tls_server = AttestedTlsServer::new(&*attester, Some(&config_hash))?;
    let tls_acceptor = TlsAcceptor::from(tls_server.server_config());

    tracing::info!(
        cert_len = tls_server.cert_der().len(),
        "attested TLS certificate generated"
    );

    let http_client = reqwest::Client::builder()
        .build()
        .expect("failed to create HTTP client");

    let state = AppState {
        config: config.clone(),
        http_client,
    };

    let app = build_router(state);

    // Bind and serve.
    let addr: SocketAddr = cli.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "trusted-relay listening");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    tracing::debug!(%peer_addr, "TLS handshake complete");

                    // Serve the request using hyper.
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service =
                        hyper_util::service::TowerToHyperService::new(app);

                    if let Err(e) =
                        hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(%peer_addr, error = %e, "connection ended");
                    }
                }
                Err(e) => {
                    tracing::debug!(%peer_addr, error = %e, "TLS handshake failed");
                }
            }
        });
    }
}

/// Select the attestation backend based on available features and runtime
/// environment.
fn select_attester() -> Box<dyn Attester> {
    // Try real TEE backends first (runtime detection).
    #[cfg(feature = "tee-tdx")]
    if std::path::Path::new("/dev/tdx_guest").exists()
        || std::path::Path::new("/dev/tdx-guest").exists()
    {
        tracing::info!("TDX device detected");
        return Box::new(relay_attest::tdx::TdxAttester);
    }

    #[cfg(feature = "tee-sev-snp")]
    if std::path::Path::new("/dev/sev-guest").exists()
        || std::path::Path::new("/dev/sev").exists()
    {
        tracing::info!("SEV-SNP device detected");
        return Box::new(relay_attest::sev_snp::SevSnpAttester);
    }

    // Fall back to mock.
    #[cfg(feature = "tee-mock")]
    {
        tracing::warn!("no TEE hardware detected, using MOCK attestation (development only!)");
        return Box::new(relay_attest::mock::MockAttester);
    }

    #[allow(unreachable_code)]
    {
        panic!("no attestation backend available — enable at least one tee-* feature");
    }
}

fn attester_name(attester: &dyn Attester) -> &'static str {
    // Use type_name for a quick label.
    let name = std::any::type_name_of_val(attester);
    if name.contains("Mock") {
        "mock (DEVELOPMENT ONLY)"
    } else if name.contains("Tdx") {
        "Intel TDX"
    } else if name.contains("SevSnp") {
        "AMD SEV-SNP"
    } else {
        "unknown"
    }
}
