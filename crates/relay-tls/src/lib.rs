//! Attested TLS layer for Trusted Relay.
//!
//! - [`server`]: Generates a TLS certificate with embedded attestation evidence.
//! - [`client`]: Custom `rustls` verifier that checks attestation during handshake.

pub mod client;
pub mod server;
