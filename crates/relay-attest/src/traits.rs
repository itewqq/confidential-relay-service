use crate::types::{AttestError, Evidence};

/// Generates attestation evidence from inside a TEE.
///
/// The `user_data` field (64 bytes) is embedded in the hardware-signed attestation
/// report (REPORTDATA for TDX, REPORT_DATA for SEV-SNP).  Typically this is
/// `SHA-384(tls_public_key)` zero-padded to 64 bytes — binding the attestation to a
/// specific TLS channel.
pub trait Attester: Send + Sync {
    fn attest(&self, user_data: &[u8; 64]) -> Result<Evidence, AttestError>;

    /// Human-readable backend name for logs and diagnostics.
    fn name(&self) -> &'static str {
        "unknown"
    }
}

/// Verifies attestation evidence on the client side.
///
/// Checks the cryptographic signature chain back to the hardware root of trust,
/// optionally verifies that the code measurement matches an expected value, and
/// returns the REPORTDATA so the caller can confirm it matches the TLS public key.
pub trait Verifier: Send + Sync {
    fn verify(
        &self,
        evidence: &Evidence,
        expected_measurement: Option<&[u8]>,
    ) -> Result<[u8; 64], AttestError>;
}
