//! TDX attestation backend (stub).
//!
//! This module provides the correct interface for Intel TDX attestation but
//! cannot generate real attestation evidence without TDX hardware.  It will
//! return an error if called outside a TDX Trust Domain.

use crate::traits::Attester;
use crate::types::{AttestError, Evidence};

/// Intel TDX attester.  Requires `/dev/tdx_guest` to be available.
pub struct TdxAttester;

impl Attester for TdxAttester {
    fn attest(&self, _user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
        // In a real implementation:
        // 1. Open /dev/tdx_guest
        // 2. Build a TDX report request with user_data in REPORTDATA
        // 3. ioctl(fd, TDX_CMD_GET_REPORT, &req)
        // 4. Convert TD Report to Quote via configfs-tsm or QGS
        // 5. Return Evidence { tee_type: Tdx, data: quote_bytes }
        Err(AttestError::GenerationFailed(
            "TDX attestation requires /dev/tdx_guest (not available on this platform)".to_string(),
        ))
    }
}

/// Intel TDX verifier stub.
pub struct TdxVerifier;

impl crate::traits::Verifier for TdxVerifier {
    fn verify(
        &self,
        _evidence: &Evidence,
        _expected_measurement: Option<&[u8]>,
    ) -> Result<[u8; 64], AttestError> {
        // In a real implementation:
        // 1. Parse the TDX Quote structure
        // 2. Verify signature chain: Quote → QE → Intel DCAP → Intel Root CA
        //    OR send to Intel Trust Authority API for verification
        // 3. Extract MRTD (measurement) and compare with expected_measurement
        // 4. Extract REPORTDATA (64 bytes) and return it
        Err(AttestError::VerificationFailed(
            "TDX verification not yet implemented".to_string(),
        ))
    }
}
