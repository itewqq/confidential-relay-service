//! Reverse proxy handler: receives OpenAI-compatible requests and forwards them
//! to the configured upstream LLM provider.
//!
//! **Security invariants:**
//! - No filesystem writes of request/response data
//! - No payload content in logs (only metadata: timestamp, model, status code)
//! - All request/response data lives in memory and is dropped after the handler returns

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use bytes::Bytes;

use crate::config::RelayConfig;
use crate::error::AppError;
use crate::secrets::ProviderCredentialStore;

const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "anthropic-version",
    "anthropic-beta",
    "authorization",
    "openai-beta",
    "openai-organization",
    "openai-project",
    "x-stainless-arch",
    "x-stainless-lang",
    "x-stainless-os",
    "x-stainless-package-version",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
];

const FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "openai-organization",
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

/// POST /v1/chat/completions — proxy to upstream.
///
/// Flow:
/// 1. Extract the model name from the JSON body (minimal parsing)
/// 2. Resolve upstream URL from config
/// 3. Forward the request body verbatim to the upstream
/// 4. Stream the response back to the client (supports SSE for streaming)
///
/// No request or response body content is logged or persisted.
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

    // Minimal JSON parsing: extract model name for routing.
    // We parse only what we need and avoid holding the full parsed structure.
    let model = extract_model_name(&body).unwrap_or_default();

    // Resolve upstream.
    let (upstream_base, path_override) = state.config.resolve_upstream(&model);
    let upstream_path = path_override.unwrap_or("/v1/chat/completions");
    let upstream_url = format!("{}{}", upstream_base.trim_end_matches('/'), upstream_path);

    // Security check: verify the resolved upstream is in the allowlist.
    state
        .config
        .check_upstream_allowed(upstream_base)
        .map_err(|e| {
            tracing::error!(upstream = %upstream_base, "blocked request to disallowed upstream");
            AppError::Internal(format!("upstream not allowed: {e}"))
        })?;

    let provider_credential = state.provider_credentials.get().await;
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

    // Send to upstream.
    let upstream_resp = state
        .http_client
        .post(&upstream_url)
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

    // Log metadata only (never payload).
    let latency = start.elapsed();
    tracing::info!(
        model = %model,
        upstream = %upstream_url,
        status = %status.as_u16(),
        latency_ms = %latency.as_millis(),
        "proxied request"
    );

    // Check if this is a streaming response (SSE).
    let is_streaming = content_type.contains("text/event-stream");

    if is_streaming {
        // Stream SSE chunks back without buffering the full response.
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
        // Non-streaming: read full response and forward.
        let resp_body = upstream_resp
            .bytes()
            .await
            .map_err(|e| AppError::Internal(format!("failed to read upstream body: {e}")))?;

        let axum_status =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

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
