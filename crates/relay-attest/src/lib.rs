//! Attestation abstraction layer for Trusted Relay.
//!
//! Provides trait-based attestation with pluggable backends:
//! - `mock` — Ed25519-based fake attestation for local development
//! - `tdx` — Intel TDX (stub, needs real hardware)
//! - `sev_snp` — AMD SEV-SNP (stub, needs real hardware)
//! - `gcp_confidential_space` — Google Cloud Confidential Space OIDC attestation
//!
//! The [`quote`] module handles embedding/extracting attestation evidence in
//! X.509 certificates for attested TLS.

pub mod quote;
pub mod traits;
pub mod types;

#[cfg(feature = "mock")]
pub mod mock;

#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "sev-snp")]
pub mod sev_snp;

#[cfg(feature = "gcp-confidential-space")]
pub mod gcp_confidential_space;

// Re-exports for convenience.
pub use traits::{Attester, Verifier};
pub use types::{AttestError, Evidence, TeeType};
