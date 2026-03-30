//! Error types for the relay proxy.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Application-level error that can be returned from axum handlers.
#[derive(Debug)]
pub enum AppError {
    /// The upstream provider returned an error.
    Upstream { status: StatusCode, body: String },
    /// Internal error in the relay.
    Internal(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Upstream { status, body } => write!(f, "upstream {status}: {body}"),
            AppError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Upstream { status, body } => (status, body).into_response(),
            AppError::Internal(msg) => {
                // Don't leak internal details to the client.
                tracing::error!("internal error: {msg}");
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
