use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The type of TEE that produced the attestation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeType {
    /// Intel TDX (Trust Domain Extensions)
    Tdx,
    /// AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
    SevSnp,
    /// Google Cloud Confidential Space attestation token.
    GcpConfidentialSpace,
    /// Mock TEE for development and testing
    Mock,
}

/// Attestation evidence: a TEE-signed blob binding user-supplied data (e.g. a TLS
/// public key hash) to the platform's measurement of the running code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// The TEE type that generated this evidence.
    pub tee_type: TeeType,
    /// The raw evidence bytes.  For real TEEs this is the quote/report; for mock
    /// this is a custom signed structure.
    pub data: Vec<u8>,
}

/// Errors from attestation operations.
#[derive(Debug, Error)]
pub enum AttestError {
    #[error("attestation generation failed: {0}")]
    GenerationFailed(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("measurement mismatch: expected {expected}, got {actual}")]
    MeasurementMismatch { expected: String, actual: String },

    #[error("REPORTDATA mismatch")]
    ReportDataMismatch,

    #[error("unsupported TEE type: {0:?}")]
    UnsupportedTeeType(TeeType),

    #[error("X.509 error: {0}")]
    X509Error(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
