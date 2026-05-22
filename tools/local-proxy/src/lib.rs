use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as AnyhowContext, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use relay_attest::traits::Verifier;
use relay_tls::client::attested_client_config;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Runtime configuration for the local compatibility proxy.
pub struct RunConfig {
    pub listen: SocketAddr,
    pub relay_endpoint: String,
    pub gateway_addr: Option<String>,
    pub gateway_token: Option<String>,
    pub verifier: Arc<dyn Verifier>,
    pub expected_measurement: Option<Vec<u8>>,
    pub expected_config_hash: Option<[u8; 32]>,
}

#[derive(Clone)]
struct AppState {
    client: Client<AttestedConnector, Body>,
    relay_base: Url,
}

/// Run the local OpenAI-compatible proxy until the listener exits.
pub async fn run(config: RunConfig) -> Result<()> {
    let relay_base = Url::parse(&config.relay_endpoint).context("invalid relay endpoint")?;
    if relay_base.scheme() != "https" {
        anyhow::bail!("relay endpoint must use https://");
    }

    let tls_config = attested_client_config(
        config.verifier,
        config.expected_measurement,
        config.expected_config_hash,
    );
    let connector = AttestedConnector {
        relay_base: relay_base.clone(),
        gateway_addr: config.gateway_addr.clone(),
        gateway_token: config.gateway_token.clone(),
        tls_config,
    };
    let client = Client::builder(TokioExecutor::new()).build(connector);

    let state = AppState { client, relay_base };
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .fallback(any(proxy_request))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(addr = %config.listen, relay = %config.relay_endpoint, gateway = ?config.gateway_addr, "local proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy_request(
    State(state): State<AppState>,
    mut request: Request<Body>,
) -> Result<Response, LocalProxyError> {
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let relay_authority = relay_authority(&state.relay_base)
        .map_err(|e| LocalProxyError::internal(format!("invalid relay endpoint: {e}")))?;
    let upstream_uri: Uri = format!(
        "{}://{}{}",
        state.relay_base.scheme(),
        relay_authority,
        path_and_query
    )
    .parse()
    .map_err(|e| LocalProxyError::internal(format!("failed to build relay URI: {e}")))?;
    *request.uri_mut() = upstream_uri;

    sanitize_local_headers(request.headers_mut());

    let response = state
        .client
        .request(request)
        .await
        .map_err(|e| LocalProxyError::bad_gateway(format!("relay request failed: {e}")))?;
    Ok(response.map(Body::new))
}

fn sanitize_local_headers(headers: &mut HeaderMap) {
    // Local app API keys are for local UX compatibility only. The CVM uses its
    // own attested provider credential, so do not forward local Authorization.
    headers.remove(axum::http::header::AUTHORIZATION);
    headers.remove(axum::http::header::HOST);
}

#[derive(Clone)]
struct AttestedConnector {
    relay_base: Url,
    gateway_addr: Option<String>,
    gateway_token: Option<String>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl tower::Service<Uri> for AttestedConnector {
    type Response = TokioIo<AttestedIo>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _dst: Uri) -> Self::Future {
        let relay_base = self.relay_base.clone();
        let gateway_addr = self.gateway_addr.clone();
        let gateway_token = self.gateway_token.clone();
        let tls_config = self.tls_config.clone();
        Box::pin(async move {
            let tcp = connect_transport(
                &relay_base,
                gateway_addr.as_deref(),
                gateway_token.as_deref(),
            )
            .await?;
            let server_name = ServerName::try_from(
                relay_base
                    .host_str()
                    .context("relay endpoint missing host")?
                    .to_string(),
            )
            .context("invalid relay TLS server name")?;
            let tls = TlsConnector::from(tls_config)
                .connect(server_name, tcp)
                .await
                .context("attested TLS connection to relay failed")?;
            Ok(TokioIo::new(AttestedIo(tls)))
        })
    }
}

async fn connect_transport(
    relay_base: &Url,
    gateway_addr: Option<&str>,
    gateway_token: Option<&str>,
) -> Result<TcpStream> {
    match gateway_addr {
        Some(gateway_addr) => {
            let mut stream = TcpStream::connect(gateway_addr)
                .await
                .with_context(|| format!("failed to connect gateway {gateway_addr}"))?;
            let relay_authority = relay_authority(relay_base)?;
            let token = gateway_token.context("gateway token is required with gateway addr")?;
            let request = format!(
                "CONNECT {relay_authority} HTTP/1.1\r\nHost: {relay_authority}\r\nAuthorization: Bearer {token}\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await?;
            let mut reader = BufReader::new(stream);
            let mut status = String::new();
            reader.read_line(&mut status).await?;
            if !status.contains(" 200 ") {
                anyhow::bail!("gateway CONNECT failed: {}", status.trim());
            }
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await? == 0 {
                    anyhow::bail!("gateway closed before tunnel establishment");
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            Ok(reader.into_inner())
        }
        None => {
            let addr = relay_authority(relay_base)?;
            TcpStream::connect(&addr)
                .await
                .with_context(|| format!("failed to connect relay {addr}"))
        }
    }
}

fn relay_authority(url: &Url) -> Result<String> {
    let host = url.host_str().context("relay endpoint missing host")?;
    let port = url
        .port_or_known_default()
        .context("relay endpoint missing port")?;
    Ok(format!("{host}:{port}"))
}

struct AttestedIo(TlsStream<TcpStream>);

impl AsyncRead for AttestedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for AttestedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for AttestedIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[derive(Debug)]
struct LocalProxyError {
    status: StatusCode,
    message: String,
}

impl LocalProxyError {
    fn internal(message: String) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }

    fn bad_gateway(message: String) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
        }
    }
}

impl IntoResponse for LocalProxyError {
    fn into_response(self) -> Response {
        let safe_message = redact_sensitive(&self.message);
        tracing::warn!(status = %self.status, error = %safe_message, "local proxy request failed");
        (
            self.status,
            format!(
                r#"{{"error":{{"message":"{}","type":"local_proxy_error"}}}}"#,
                safe_message.replace('"', "'")
            ),
        )
            .into_response()
    }
}

fn redact_sensitive(raw: &str) -> String {
    raw.split_whitespace()
        .map(redact_sensitive_part)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_sensitive_part(part: &str) -> String {
    let lower = part.to_ascii_lowercase();
    if lower.starts_with("authorization")
        || lower.starts_with("bearer")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api_key")
    {
        return "<redacted>".to_string();
    }

    if let Some(pos) = part.find("sk-") {
        let (prefix, rest) = part.split_at(pos);
        let token_len = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .map(char::len_utf8)
            .sum::<usize>();
        if token_len >= 8 {
            let suffix = &rest[token_len..];
            return format!("{prefix}<redacted>{suffix}");
        }
    }

    part.to_string()
}
