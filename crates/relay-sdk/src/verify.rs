//! Verification policies for attestation.

/// How the SDK verifies the relay's attestation evidence.
#[derive(Debug, Clone)]
pub enum VerificationPolicy {
    /// Strict: the evidence's code measurement must match this exact value.
    /// This is the most secure generic mode because the user pins a specific
    /// measured workload identity rather than merely checking that some TEE exists.
    Strict {
        /// Expected measurement bytes (e.g. MRTD for TDX, MEASUREMENT for SEV-SNP).
        expected_measurement: Vec<u8>,
    },

    /// Trust On First Use: accept the measurement on the first connection,
    /// then reject if it changes. Not yet implemented.
    TrustOnFirstUse,

    /// Audit: verify that the server is running inside a real TEE, but do not
    /// pin the workload identity. This explicitly trusts the operator's code and
    /// therefore is not sufficient for the relay's operator-resistant
    /// confidentiality claim.
    Audit,

    /// GCP Confidential Space production policy using an exact workload
    /// container image digest. Exact-digest pinning prevents the operator from
    /// choosing a different or older image signed by the same release key.
    GcpConfidentialSpace {
        audience: String,
        image_digest: String,
    },

    /// Mock: accept mock attestation evidence. For development only.
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
