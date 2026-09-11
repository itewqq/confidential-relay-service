//! Reverse proxy handler: receives OpenAI-compatible requests and forwards them
//! to the configured upstream LLM provider.
//!
//! **Security invariants:**
//! - No filesystem writes of request/response data
//! - No payload-derived content in logs
//! - Final upstream URLs are constructed as paths on attested base URLs and
//!   checked against the allowlist immediately before use
//! - Redirects are not followed, so an allowed upstream cannot redirect a
//!   request body to a different origin
//! - All request/response data lives in memory and is dropped after the handler returns

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use sha2::Digest;

use crate::config::RelayConfig;
use crate::error::AppError;
use crate::secrets::ProviderCredentialStore;

const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "anthropic-version",
    "anthropic-beta",
    "authorization",
    "openai-beta",
    "x-stainless-arch",
    "x-stainless-lang",
    "x-stainless-os",
    "x-stainless-package-version",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
];

const FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "openai-processing-ms",
    "openai-version",
    "request-id",
    "x-request-id",
];

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RelayConfig>,
    pub http_client: reqwest::Client,
    pub provider_credentials: ProviderCredentialStore,
    pub require_provider_credential: bool,
}

/// Build the upstream HTTP client with normal WebPKI/hostname validation and,
/// when configured, handshake-time leaf-certificate pin checks.
///
/// Redirects are deliberately disabled. A provider redirect is a new egress
/// decision and must be represented in the attested configuration instead of
/// being followed implicitly by the HTTP client.
pub fn build_upstream_http_client(config: &RelayConfig) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.upstream_timeout_secs))
        .redirect(reqwest::redirect::Policy::none());

    let pins_by_host = config
        .upstream_tls_pin_hosts()
        .map_err(|e| anyhow::anyhow!("invalid upstream TLS pin config: {e}"))?;
    if !pins_by_host.is_empty() {
        let tls_config = pinned_rustls_client_config(pins_by_host)?;
        builder = builder.use_preconfigured_tls(tls_config);
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("failed to create upstream HTTP client: {e}"))
}

/// POST /v1/chat/completions — proxy to upstream.
///
/// Flow:
/// 1. Extract the model name from the JSON body for routing only
/// 2. Resolve attested upstream base/path configuration
/// 3. Construct and allowlist-check the final URL without URL-reference joining
/// 4. Forward the request body verbatim to the upstream
/// 5. Stream the response back to the client (supports SSE for streaming)
///
/// No request or response body content, including the payload-derived model
/// value, is logged or persisted.
pub async fn proxy_chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let start = Instant::now();

    if body.len() > state.config.max_request_bytes {
        return Err(AppError::PayloadTooLarge {
            limit: state.config.max_request_bytes,
        });
    }

    // Minimal JSON parsing: extract model name for routing only. Do not log it.
    let model = extract_model_name(&body).unwrap_or_default();

    let (upstream_base, path_override) = state.config.resolve_upstream(&model);
    let upstream_path = path_override.unwrap_or("/v1/chat/completions");
    let upstream_url = state
        .config
        .build_upstream_url(upstream_base, upstream_path)
        .map_err(|e| {
            tracing::error!("blocked request with invalid or disallowed final upstream URL");
            AppError::Internal(format!("upstream not allowed: {e}"))
        })?;

    let provider_credential = state.provider_credentials.get().await;
    let using_injected_provider_credential = provider_credential.is_some();
    if state.require_provider_credential && provider_credential.is_none() {
        tracing::warn!("rejecting data-plane request before provider credential injection");
        return Err(AppError::MissingProviderCredential);
    }

    // Forward only a small allowlist of provider-relevant headers. Do not copy
    // hop-by-hop or tracing headers that could leak client metadata. In
    // production, the injected provider credential replaces any client
    // Authorization header so provider keys stay in operator-controlled scope.
    let mut upstream_headers = reqwest::header::HeaderMap::new();
    for header_name in FORWARDED_REQUEST_HEADERS {
        if *header_name == "authorization" && provider_credential.is_some() {
            continue;
        }
        if let Some(value) = headers.get(*header_name) {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(header_name.as_bytes()) {
                if let Ok(value) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                    upstream_headers.insert(name, value);
                }
            }
        }
    }
    if let Some(credential) = provider_credential {
        let value = credential.authorization_value().map_err(|e| {
            AppError::Internal(format!("invalid injected provider credential: {e}"))
        })?;
        upstream_headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    upstream_headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );

    let upstream_resp = state
        .http_client
        .post(upstream_url.clone())
        .headers(upstream_headers)
        .body(body)
        .send()
        .await?;

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let response_headers = filtered_response_headers(upstream_resp.headers());

    // Log non-payload metadata only. The upstream URL is attested config-derived.
    let latency = start.elapsed();
    tracing::info!(
        upstream = %upstream_url,
        status = %status.as_u16(),
        latency_ms = %latency.as_millis(),
        "proxied request"
    );

    let provider_auth_failed =
        using_injected_provider_credential && matches!(status.as_u16(), 401 | 403);

    let is_streaming = content_type.contains("text/event-stream");

    if is_streaming {
        let stream = upstream_resp.bytes_stream();
        let body = Body::from_stream(stream);

        let mut builder = Response::builder()
            .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
        builder = builder.header("content-type", "text/event-stream");
        builder = builder.header("cache-control", "no-cache");

        for (name, value) in &response_headers {
            builder = builder.header(name.as_str(), value.as_slice());
        }

        let response = builder
            .body(body)
            .map_err(|e| AppError::Internal(format!("failed to build response: {e}")))?;

        Ok(response)
    } else {
        let resp_body = upstream_resp
            .bytes()
            .await
            .map_err(|e| AppError::Internal(format!("failed to read upstream body: {e}")))?;

        let axum_status =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if provider_auth_failed {
            return Response::builder()
                .status(axum_status)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"error":{"message":"upstream provider authentication failed","type":"relay_error"}}"#,
                ))
                .map_err(|e| AppError::Internal(format!("failed to build response: {e}")));
        }

        let mut response = Response::builder().status(axum_status).header(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(&content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/json")),
        );

        for (name, value) in &response_headers {
            if name == "content-type" {
                continue;
            }
            response = response.header(name.as_str(), value.as_slice());
        }

        response
            .body(Body::from(resp_body))
            .map_err(|e| AppError::Internal(format!("failed to build response: {e}")))
    }
}

/// Extract the "model" field from a JSON body without fully deserializing it.
fn extract_model_name(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("model")?.as_str().map(|s| s.to_string())
}

/// Health check endpoint.
pub async fn health() -> &'static str {
    "ok"
}

pub fn body_limit(config: &RelayConfig) -> DefaultBodyLimit {
    DefaultBodyLimit::max(config.max_request_bytes)
}

fn filtered_response_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, Vec<u8>)> {
    FORWARDED_RESPONSE_HEADERS
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .map(|value| ((*name).to_string(), value.as_bytes().to_vec()))
        })
        .collect()
}

fn pinned_rustls_client_config(
    pins_by_host: std::collections::BTreeMap<String, Vec<String>>,
) -> anyhow::Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let delegate = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build WebPKI verifier: {e}"))?;
    let verifier = PinnedServerCertVerifier {
        delegate,
        pins_by_host,
    };

    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

#[derive(Debug)]
struct PinnedServerCertVerifier {
    delegate: Arc<rustls::client::WebPkiServerVerifier>,
    pins_by_host: std::collections::BTreeMap<String, Vec<String>>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.delegate.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        let host = server_name.to_str().to_ascii_lowercase();
        if let Some(expected_pins) = self.pins_by_host.get(host.as_ref() as &str) {
            let actual = leaf_sha256_pin(end_entity.as_ref());
            if !expected_pins.iter().any(|pin| pin == &actual) {
                return Err(rustls::Error::General(format!(
                    "upstream TLS leaf certificate pin mismatch for {host}: got {actual}"
                )));
            }
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

fn leaf_sha256_pin(cert_der: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(cert_der)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::client::danger::ServerCertVerifier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pinned_verifier_for_localhost() -> (PinnedServerCertVerifier, Vec<u8>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.der().to_vec();
        let cert = rustls::pki_types::CertificateDer::from(cert_der.clone());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let delegate = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut pins_by_host = std::collections::BTreeMap::new();
        pins_by_host.insert("localhost".to_string(), vec![leaf_sha256_pin(&cert_der)]);

        (
            PinnedServerCertVerifier {
                delegate,
                pins_by_host,
            },
            cert_der,
        )
    }

    #[test]
    fn pinned_verifier_accepts_matching_leaf_pin() {
        let (verifier, cert_der) = pinned_verifier_for_localhost();
        let cert = rustls::pki_types::CertificateDer::from(cert_der);

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );

        assert!(result.is_ok(), "matching pin should verify: {result:?}");
    }

    #[test]
    fn pinned_verifier_rejects_changed_leaf_pin() {
        let (mut verifier, cert_der) = pinned_verifier_for_localhost();
        verifier.pins_by_host.insert(
            "localhost".to_string(),
            vec![
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ],
        );
        let cert = rustls::pki_types::CertificateDer::from(cert_der);

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );

        assert!(
            result.is_err(),
            "wrong pin must fail during TLS verification"
        );
    }

    #[tokio::test]
    async fn upstream_client_does_not_follow_redirects() {
        let target_hits = Arc::new(AtomicUsize::new(0));
        let hits = target_hits.clone();
        let target_app = axum::Router::new().route(
            "/steal",
            axum::routing::post(move || {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    "unexpected"
                }
            }),
        );
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(target_listener, target_app).await.unwrap();
        });

        let location = format!("http://{target_addr}/steal");
        let source_app = axum::Router::new().route(
            "/start",
            axum::routing::post(move || {
                let location = location.clone();
                async move {
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header(axum::http::header::LOCATION, location)
                        .body(Body::empty())
                        .unwrap()
                }
            }),
        );
        let source_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let source_addr = source_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(source_listener, source_app).await.unwrap();
        });

        let client = build_upstream_http_client(&RelayConfig::default()).unwrap();
        let response = client
            .post(format!("http://{source_addr}/start"))
            .body("secret prompt")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        tokio::task::yield_now().await;
        assert_eq!(target_hits.load(Ordering::SeqCst), 0);
    }
}
