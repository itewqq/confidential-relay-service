//! Error types for the relay proxy.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Application-level error that can be returned from axum handlers.
#[derive(Debug)]
pub enum AppError {
    /// The upstream provider returned an error.
    Upstream { status: StatusCode, body: String },
    /// The client request body exceeded the configured limit.
    PayloadTooLarge { limit: usize },
    /// The relay has not received its runtime upstream provider credential yet.
    MissingProviderCredential,
    /// Internal error in the relay.
    Internal(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Upstream { status, body } => write!(f, "upstream {status}: {body}"),
            AppError::PayloadTooLarge { limit } => {
                write!(f, "request body exceeds configured limit of {limit} bytes")
            }
            AppError::MissingProviderCredential => write!(f, "provider credential not loaded"),
            AppError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Upstream { status, body } => (status, body).into_response(),
            AppError::PayloadTooLarge { .. } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":{"message":"request body too large","type":"relay_error"}}"#,
            )
                .into_response(),
            AppError::MissingProviderCredential => (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":{"message":"provider credential not loaded","type":"relay_error"}}"#,
            )
                .into_response(),
            AppError::Internal(msg) => {
                // Don't leak internal details to the client.
                tracing::error!(error = %redact_sensitive(&msg), "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    r#"{"error":{"message":"internal relay error","type":"relay_error"}}"#,
                )
                    .into_response()
            }
        }
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Internal(format!("upstream request failed: {e}"))
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
        || lower.contains("api_key")
        || lower.contains("token")
        || lower.contains("secret")
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
