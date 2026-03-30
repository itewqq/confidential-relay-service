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
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use crate::config::RelayConfig;
use crate::error::AppError;

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RelayConfig>,
    pub http_client: reqwest::Client,
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

    // Minimal JSON parsing: extract model name for routing.
    // We parse only what we need and avoid holding the full parsed structure.
    let model = extract_model_name(&body).unwrap_or_default();

    // Resolve upstream.
    let (upstream_base, path_override) = state.config.resolve_upstream(&model);
    let upstream_path = path_override.unwrap_or("/v1/chat/completions");
    let upstream_url = format!("{}{}", upstream_base.trim_end_matches('/'), upstream_path);

    // Security check: verify the resolved upstream is in the allowlist.
    state.config.check_upstream_allowed(upstream_base).map_err(|e| {
        tracing::error!(upstream = %upstream_base, "blocked request to disallowed upstream");
        AppError::Internal(format!("upstream not allowed: {e}"))
    })?;

    // Forward the Authorization header from the client.
    let mut upstream_headers = reqwest::header::HeaderMap::new();
    if let Some(auth) = headers.get("authorization") {
        if let Ok(v) = reqwest::header::HeaderValue::from_bytes(auth.as_bytes()) {
            upstream_headers.insert(reqwest::header::AUTHORIZATION, v);
        }
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

        let response = Response::builder()
            .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK))
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .header("connection", "keep-alive")
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

        Ok((
            axum_status,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/json")),
            )],
            resp_body,
        )
            .into_response())
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
