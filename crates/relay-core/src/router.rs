//! Axum router setup for the relay.

use axum::routing::{get, post};
use axum::Router;

use crate::proxy::{health, proxy_chat_completions, AppState};

/// Build the axum Router for the relay server.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(proxy_chat_completions))
        .route("/health", get(health))
        .with_state(state)
}
