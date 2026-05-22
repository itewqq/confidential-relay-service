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
use relay_core::secrets::{ProviderCredential, ProviderCredentialStore};
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
    #[arg(
        short,
        long,
        env = "TRUSTED_RELAY_UPSTREAM",
        default_value = "https://api.openai.com"
    )]
    upstream: String,

    /// Maximum request body size in bytes.
    #[arg(
        long,
        env = "TRUSTED_RELAY_MAX_REQUEST_BYTES",
        default_value_t = 1_048_576
    )]
    max_request_bytes: usize,

    /// Upstream request timeout in seconds.
    #[arg(
        long,
        env = "TRUSTED_RELAY_UPSTREAM_TIMEOUT_SECS",
        default_value_t = 120
    )]
    upstream_timeout_secs: u64,

    /// Allowed upstream URL origins. Can be specified multiple times.
    /// Only these origins will be forwarded to. If none are given the default
    /// upstream is automatically added to the allowlist.
    /// Example: --allowed-upstream https://api.openai.com --allowed-upstream https://api.anthropic.com
    #[arg(
        long,
        env = "TRUSTED_RELAY_ALLOWED_UPSTREAM",
        value_delimiter = ',',
        allow_hyphen_values = true
    )]
    allowed_upstream: Vec<String>,

    /// Provider authorization token to use for upstream calls. Prefer --secret-broker-url in production.
    #[arg(long, env = "TRUSTED_RELAY_PROVIDER_TOKEN")]
    provider_token: Option<String>,

    /// Provider authorization scheme for --provider-token.
    #[arg(
        long,
        env = "TRUSTED_RELAY_PROVIDER_AUTH_SCHEME",
        default_value = "Bearer"
    )]
    provider_auth_scheme: String,

    /// Secret broker endpoint. If set, the relay fetches the provider credential after attested TLS is created.
    #[arg(long, env = "TRUSTED_RELAY_SECRET_BROKER_URL")]
    secret_broker_url: Option<String>,

    /// PEM bundle containing the private CA roots used to authenticate the secret broker.
    #[arg(long, env = "TRUSTED_RELAY_SECRET_BROKER_CA_PEM")]
    secret_broker_ca_pem: Option<String>,

    /// One-time nonce included in the secret broker request. Required with --secret-broker-url.
    #[arg(long, env = "TRUSTED_RELAY_SECRET_NONCE")]
    secret_nonce: Option<String>,

    /// Published release/workload artifact sha256 digest to bind into config_hash/REPORTDATA.
    #[arg(long, env = "TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST")]
    release_artifact_digest: Option<String>,
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
    if cli.provider_token.is_some() && cli.secret_broker_url.is_some() {
        anyhow::bail!(
            "use either --provider-token or --secret-broker-url, not both; production should use --secret-broker-url"
        );
    }

    // Select attester based on available TEE.
    let attester: Box<dyn Attester> = select_attester();
    tracing::info!("attestation backend: {}", attester.name());

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
        max_request_bytes: cli.max_request_bytes,
        release_artifact_digest: cli.release_artifact_digest,
        secret_broker_url: cli.secret_broker_url.clone(),
        secret_broker_ca_sha256: cli
            .secret_broker_ca_pem
            .as_deref()
            .map(|pem| relay_secret::sha256_hex_bytes(pem.as_bytes())),
        upstream_timeout_secs: cli.upstream_timeout_secs,
        ..Default::default()
    });

    // Validate configuration at startup (catches disallowed upstreams early).
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("config validation failed: {e}"))?;

    // Compute the config hash for attestation binding.
    // This binds the relay's upstream configuration into the attestation REPORTDATA,
    // so clients can verify which upstreams the relay is permitted to contact.
    let config_hash = config.config_hash();
    tracing::info!(
        config_hash = %hex::encode(config_hash),
        "computed configuration hash for attestation binding"
    );

    let tls_server = AttestedTlsServer::new(&*attester, Some(&config_hash))
        .map_err(|e| anyhow::anyhow!("attested TLS setup failed: {e:#}"))?;
    let tls_acceptor = TlsAcceptor::from(tls_server.server_config());

    tracing::info!(
        cert_len = tls_server.cert_der().len(),
        "attested TLS certificate generated"
    );

    let provider_credentials = ProviderCredentialStore::new();
    if let Some(provider_token) = cli.provider_token {
        provider_credentials
            .set(ProviderCredential {
                auth_scheme: cli.provider_auth_scheme.clone(),
                token: provider_token,
            })
            .await;
        tracing::info!("provider credential loaded from runtime token source");
    }
    if let Some(secret_broker_url) = cli.secret_broker_url.as_deref() {
        let secret_nonce = cli.secret_nonce.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "--secret-nonce or TRUSTED_RELAY_SECRET_NONCE is required with --secret-broker-url"
            )
        })?;
        if secret_nonce.trim().len() < 16 {
            anyhow::bail!(
                "--secret-nonce must be a fresh high-entropy value of at least 16 characters"
            );
        }
        let credential = relay_secret::fetch_provider_credential(
            secret_broker_url,
            cli.secret_broker_ca_pem.as_deref(),
            tls_server.cert_der(),
            config_hash,
            secret_nonce.to_string(),
        )
        .await?;
        provider_credentials.set(credential).await;
        tracing::info!("provider credential fetched from attested secret broker");
    }

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.upstream_timeout_secs))
        .build()
        .expect("failed to create HTTP client");

    let state = AppState {
        config: config.clone(),
        http_client,
        provider_credentials,
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
                    let service = hyper_util::service::TowerToHyperService::new(app);

                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
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
    // Confidential Space token attestation is the preferred production route on GCP.
    #[cfg(feature = "tee-gcp-confidential-space")]
    {
        let socket_path = std::env::var("TRUSTED_RELAY_GCP_CS_SOCKET")
            .unwrap_or_else(|_| "/run/container_launcher/teeserver.sock".to_string());
        if std::env::var_os("TRUSTED_RELAY_GCP_CONFIDENTIAL_SPACE").is_some() {
            tracing::info!(
                %socket_path,
                "GCP Confidential Space attestation explicitly enabled"
            );
            return Box::new(
                relay_attest::gcp_confidential_space::GcpConfidentialSpaceAttester::from_env(),
            );
        }
        if relay_attest::gcp_confidential_space::can_connect_launcher_socket(&socket_path) {
            tracing::info!(%socket_path, "GCP Confidential Space launcher detected");
            return Box::new(
                relay_attest::gcp_confidential_space::GcpConfidentialSpaceAttester::from_env(),
            );
        }
    }

    // Try real TEE backends first (runtime detection).
    #[cfg(feature = "tee-tdx")]
    if std::path::Path::new("/dev/tdx_guest").exists()
        || std::path::Path::new("/dev/tdx-guest").exists()
    {
        tracing::info!("TDX device detected");
        return Box::new(relay_attest::tdx::TdxAttester);
    }

    #[cfg(feature = "tee-sev-snp")]
    if std::path::Path::new("/dev/sev-guest").exists() || std::path::Path::new("/dev/sev").exists()
    {
        #[cfg(feature = "tee-mock")]
        if std::env::var_os("TRUSTED_RELAY_ALLOW_MOCK_FALLBACK_IN_SNP").is_some()
            && std::env::var_os("TRUSTED_RELAY_DEV_MOCK").is_some()
        {
            tracing::warn!(
                "real SEV-SNP device detected, but explicit non-production mock fallback override is set"
            );
            return Box::new(relay_attest::mock::MockAttester);
        }

        tracing::info!("SEV-SNP device detected");
        return Box::new(relay_attest::sev_snp::SevSnpAttester);
    }

    // Fall back to mock.
    #[cfg(feature = "tee-mock")]
    {
        if std::env::var_os("TRUSTED_RELAY_DEV_MOCK").is_some() {
            tracing::warn!(
                "TRUSTED_RELAY_DEV_MOCK is set; using MOCK attestation (development only!)"
            );
            return Box::new(relay_attest::mock::MockAttester);
        }

        panic!(
            "mock attestation is compiled in but disabled. \
             Set TRUSTED_RELAY_DEV_MOCK=1 for local development, or run in real TEE mode."
        );
    }

    #[allow(unreachable_code)]
    {
        panic!("no attestation backend available — enable at least one tee-* feature");
    }
}
