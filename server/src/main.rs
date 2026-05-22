//! Trusted Relay server binary.
//!
//! Starts an attested TLS server that proxies OpenAI-compatible API requests.
//! In development mode (--mock), uses mock attestation that works on any platform.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use relay_attest::Attester;
use relay_core::config::RelayConfig;
use relay_core::proxy::{build_upstream_http_client, AppState};
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

    /// Upstream TLS leaf certificate pin in ORIGIN=sha256:<64-hex> form. Repeatable.
    #[arg(
        long,
        env = "TRUSTED_RELAY_UPSTREAM_TLS_LEAF_SHA256",
        value_delimiter = ',',
        allow_hyphen_values = true
    )]
    upstream_tls_leaf_sha256: Vec<String>,

    /// Development-only provider authorization token to use for upstream calls.
    /// Production should inject this through --admin-listen on a private network.
    #[arg(long, env = "TRUSTED_RELAY_PROVIDER_TOKEN")]
    provider_token: Option<String>,

    /// Provider authorization scheme for --provider-token.
    #[arg(
        long,
        env = "TRUSTED_RELAY_PROVIDER_AUTH_SCHEME",
        default_value = "Bearer"
    )]
    provider_auth_scheme: String,

    /// Private HTTP admin listen address for one-shot provider credential injection.
    /// Bind this only on localhost or a private subnet and protect it with firewall rules.
    #[arg(long, env = "TRUSTED_RELAY_ADMIN_LISTEN")]
    admin_listen: Option<String>,

    /// Development escape hatch: forward client Authorization if no provider credential was injected.
    #[arg(long, env = "TRUSTED_RELAY_ALLOW_CLIENT_PROVIDER_AUTH")]
    allow_client_provider_auth: bool,

    /// Published release/workload artifact sha256 digest to bind into config_hash/REPORTDATA.
    #[arg(long, env = "TRUSTED_RELAY_RELEASE_ARTIFACT_DIGEST")]
    release_artifact_digest: Option<String>,
}

#[derive(Clone)]
struct AdminState {
    provider_credentials: ProviderCredentialStore,
}

#[derive(serde::Serialize)]
struct AdminHealth {
    ok: bool,
    provider_credential_loaded: bool,
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
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let require_provider_credential = !cli.allow_client_provider_auth;
    if cli.allow_client_provider_auth {
        tracing::warn!(
            "TRUSTED_RELAY_ALLOW_CLIENT_PROVIDER_AUTH is enabled; this is development-only"
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
        upstream_timeout_secs: cli.upstream_timeout_secs,
        upstream_tls_leaf_sha256: parse_upstream_tls_pins(&cli.upstream_tls_leaf_sha256)?,
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
        tracing::warn!(
            "provider credential loaded from CLI/env; use private admin injection in production"
        );
    }

    let http_client = build_upstream_http_client(&config)?;

    let state = AppState {
        config: config.clone(),
        http_client,
        provider_credentials: provider_credentials.clone(),
        require_provider_credential,
    };

    let app = build_router(state);
    if let Some(admin_listen) = cli.admin_listen.as_deref() {
        let admin_addr: SocketAddr = admin_listen.parse()?;
        if !is_private_admin_ip(admin_addr.ip()) {
            tracing::warn!(
                %admin_addr,
                "private admin endpoint is bound to a non-private address; protect it with firewall/IAP controls"
            );
        }
        let admin_listener = TcpListener::bind(admin_addr).await?;
        let admin_app = build_admin_router(provider_credentials.clone());
        tracing::info!(
            %admin_addr,
            "private admin injection endpoint listening; protect this address with VPC/firewall"
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(admin_listener, admin_app).await {
                tracing::error!(error = %e, "private admin server stopped");
            }
        });
    } else if provider_credentials.is_loaded().await {
        tracing::info!(
            "private admin injection endpoint disabled; provider credential already loaded"
        );
    } else if require_provider_credential {
        tracing::warn!(
            "private admin injection endpoint disabled and no provider credential loaded; data-plane requests will fail closed"
        );
    }

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

fn parse_upstream_tls_pins(raw: &[String]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut pins = BTreeMap::<String, Vec<String>>::new();
    for item in raw {
        let (origin, pin) = item
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("upstream TLS pin must be ORIGIN=sha256:<64-hex>"))?;
        pins.entry(origin.to_string())
            .or_default()
            .push(pin.to_string());
    }
    Ok(pins)
}

fn is_private_admin_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip == Ipv4Addr::UNSPECIFIED
                || ip.is_private()
                || ip.octets()[0] == 169 && ip.octets()[1] == 254
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip == Ipv6Addr::UNSPECIFIED
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn build_admin_router(provider_credentials: ProviderCredentialStore) -> Router {
    let state = AdminState {
        provider_credentials,
    };
    Router::new()
        .route("/admin/health", get(admin_health))
        .route(
            "/admin/provider-credential",
            post(inject_provider_credential),
        )
        .with_state(state)
}

async fn admin_health(State(state): State<AdminState>) -> Json<AdminHealth> {
    Json(AdminHealth {
        ok: true,
        provider_credential_loaded: state.provider_credentials.is_loaded().await,
    })
}

async fn inject_provider_credential(
    State(state): State<AdminState>,
    Json(credential): Json<ProviderCredential>,
) -> StatusCode {
    if let Err(e) = credential.validate() {
        tracing::warn!(error = %e, "rejected invalid provider credential injection");
        return StatusCode::BAD_REQUEST;
    }

    match state.provider_credentials.set_once(credential).await {
        Ok(()) => {
            tracing::info!("provider credential injected through private admin endpoint");
            StatusCode::NO_CONTENT
        }
        Err(_) => {
            tracing::warn!("rejected duplicate provider credential injection");
            StatusCode::CONFLICT
        }
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
