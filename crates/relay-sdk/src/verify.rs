//! Verification policies for attestation.

/// How the SDK verifies the relay's attestation evidence.
#[derive(Debug, Clone)]
pub enum VerificationPolicy {
    /// Strict: the evidence's code measurement must match this exact value.
    /// This is the most secure mode — the user pins a specific binary.
    Strict {
        /// Expected measurement bytes (e.g. MRTD for TDX, MEASUREMENT for SEV-SNP).
        expected_measurement: Vec<u8>,
    },

    /// Trust On First Use: accept the measurement on the first connection,
    /// then reject if it changes.  Not yet implemented — will store the
    /// pinned measurement locally.
    TrustOnFirstUse,

    /// Audit: verify that the server is running inside a real TEE, but don't
    /// check the specific measurement.  Trusts the operator's code.
    Audit,

    /// GCP Confidential Space: pin a workload container digest/signature policy.
    GcpConfidentialSpace {
        audience: String,
        image_digest: String,
    },

    /// Mock: accept mock attestation evidence.  For development only.
    MockDev,
}

impl VerificationPolicy {
    /// Get the expected measurement bytes, or None if measurement is not checked.
    pub fn expected_measurement(&self) -> Option<&[u8]> {
        match self {
            VerificationPolicy::Strict {
                expected_measurement,
            } => Some(expected_measurement),
            _ => None,
        }
    }
}
