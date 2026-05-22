//! Trusted Relay SDK — client library for connecting to a confidential LLM proxy
//! with automatic attestation verification.
//!
//! # Example
//!
//! ```rust,no_run
//! use relay_sdk::client::TrustedRelayClient;
//! use relay_sdk::verify::VerificationPolicy;
//! use relay_sdk::types::ChatRequest;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let client = TrustedRelayClient::builder()
//!     .endpoint("https://relay.example.com:8443")
//!     .api_key(std::env::var("TRUSTED_RELAY_LOCAL_TOKEN")?)
//!     .verification(VerificationPolicy::MockDev)
//!     .build()?;
//!
//! let response = client.chat_completions(
//!     ChatRequest::simple("gpt-4", "Hello, world!")
//! ).await?;
//!
//! println!("{:?}", response);
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod types;
pub mod verify;

// Re-exports.
pub use client::TrustedRelayClient;
pub use types::{ChatRequest, ChatResponse};
pub use verify::VerificationPolicy;
