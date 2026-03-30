//! Mock attestation backend for local development and testing.
//!
//! Uses Ed25519 to simulate a hardware-signed attestation quote.  The quote
//! structure mirrors what real TEEs provide:  a measurement (hash of the running
//! code), user-supplied REPORTDATA (64 bytes), and a signature.
//!
//! The signing key is deterministic (derived from a fixed seed) so that tests
//! can verify signatures without any hardware.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::traits::{Attester, Verifier};
use crate::types::{AttestError, Evidence, TeeType};

/// A fixed seed used to derive the mock signing key.  In production this would be
/// the TEE hardware's signing key — here it's just a deterministic test value.
const MOCK_SEED: [u8; 32] = *b"trusted-relay-mock-key-seed!0000";

/// The "measurement" of the mock enclave.  In production this would be MRTD (TDX)
/// or MEASUREMENT (SEV-SNP) — the hash of the running binary.
fn mock_measurement() -> [u8; 32] {
    Sha256::digest(b"trusted-relay-mock-measurement").into()
}

/// The mock quote payload that gets signed.
/// We use `Vec<u8>` for serialization because serde doesn't derive for `[u8; 64]`.
#[derive(Serialize, Deserialize)]
struct MockQuote {
    measurement: Vec<u8>,
    user_data: Vec<u8>,
}

fn mock_signing_key() -> SigningKey {
    SigningKey::from_bytes(&MOCK_SEED)
}

fn mock_verifying_key() -> VerifyingKey {
    mock_signing_key().verifying_key()
}

// ---------------------------------------------------------------------------
// Attester
// ---------------------------------------------------------------------------

/// Mock attester that simulates TEE attestation with Ed25519 signatures.
pub struct MockAttester;

impl Attester for MockAttester {
    fn attest(&self, user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
        let quote = MockQuote {
            measurement: mock_measurement().to_vec(),
            user_data: user_data.to_vec(),
        };

        let payload =
            serde_json::to_vec(&quote).map_err(|e| AttestError::GenerationFailed(e.to_string()))?;

        let signing_key = mock_signing_key();
        let signature: Signature = signing_key.sign(&payload);

        // Evidence = payload length (4 bytes LE) || payload || signature (64 bytes)
        let mut data = Vec::with_capacity(4 + payload.len() + 64);
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(&payload);
        data.extend_from_slice(&signature.to_bytes());

        Ok(Evidence {
            tee_type: TeeType::Mock,
            data,
        })
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Mock verifier that checks Ed25519 signatures from [`MockAttester`].
pub struct MockVerifier;

impl MockVerifier {
    /// Parse the evidence into (payload_bytes, MockQuote, Signature).
    fn parse_evidence(evidence: &Evidence) -> Result<(Vec<u8>, MockQuote, Signature), AttestError> {
        if evidence.tee_type != TeeType::Mock {
            return Err(AttestError::UnsupportedTeeType(evidence.tee_type));
        }

        let data = &evidence.data;
        if data.len() < 4 + 64 {
            return Err(AttestError::VerificationFailed(
                "evidence too short".to_string(),
            ));
        }

        let payload_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if data.len() != 4 + payload_len + 64 {
            return Err(AttestError::VerificationFailed(format!(
                "evidence length mismatch: expected {}, got {}",
                4 + payload_len + 64,
                data.len()
            )));
        }

        let payload = &data[4..4 + payload_len];
        let sig_bytes: [u8; 64] = data[4 + payload_len..]
            .try_into()
            .map_err(|_| AttestError::VerificationFailed("bad signature length".to_string()))?;

        let signature = Signature::from_bytes(&sig_bytes);
        let quote: MockQuote = serde_json::from_slice(payload)
            .map_err(|e| AttestError::VerificationFailed(format!("bad quote JSON: {e}")))?;

        Ok((payload.to_vec(), quote, signature))
    }
}

impl Verifier for MockVerifier {
    fn verify(
        &self,
        evidence: &Evidence,
        expected_measurement: Option<&[u8]>,
    ) -> Result<[u8; 64], AttestError> {
        let (payload, quote, signature) = Self::parse_evidence(evidence)?;

        // 1. Verify Ed25519 signature (simulates hardware signature chain verification).
        let verifying_key = mock_verifying_key();
        verifying_key
            .verify(&payload, &signature)
            .map_err(|e| AttestError::VerificationFailed(format!("signature invalid: {e}")))?;

        // 2. Optionally check measurement.
        if let Some(expected) = expected_measurement {
            if quote.measurement.as_slice() != expected {
                return Err(AttestError::MeasurementMismatch {
                    expected: hex::encode(expected),
                    actual: hex::encode(&quote.measurement),
                });
            }
        }

        // 3. Return the REPORTDATA for the caller to compare with the TLS pubkey hash.
        let user_data: [u8; 64] = quote
            .user_data
            .try_into()
            .map_err(|_| AttestError::VerificationFailed("user_data not 64 bytes".to_string()))?;
        Ok(user_data)
    }
}

/// Returns the mock measurement value.  Tests and SDK in mock mode use this to
/// know what value to expect.
pub fn get_mock_measurement() -> [u8; 32] {
    mock_measurement()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_attest_verify() {
        let attester = MockAttester;
        let verifier = MockVerifier;

        let user_data = [42u8; 64];
        let evidence = attester.attest(&user_data).unwrap();

        assert_eq!(evidence.tee_type, TeeType::Mock);

        let recovered = verifier.verify(&evidence, None).unwrap();
        assert_eq!(recovered, user_data);
    }

    #[test]
    fn verify_with_correct_measurement() {
        let attester = MockAttester;
        let verifier = MockVerifier;

        let user_data = [7u8; 64];
        let evidence = attester.attest(&user_data).unwrap();

        let measurement = mock_measurement();
        let recovered = verifier.verify(&evidence, Some(&measurement)).unwrap();
        assert_eq!(recovered, user_data);
    }

    #[test]
    fn verify_rejects_wrong_measurement() {
        let attester = MockAttester;
        let verifier = MockVerifier;

        let evidence = attester.attest(&[0u8; 64]).unwrap();

        let wrong = [0xFFu8; 32];
        let result = verifier.verify(&evidence, Some(&wrong));
        assert!(matches!(result, Err(AttestError::MeasurementMismatch { .. })));
    }

    #[test]
    fn verify_rejects_tampered_evidence() {
        let attester = MockAttester;
        let verifier = MockVerifier;

        let mut evidence = attester.attest(&[1u8; 64]).unwrap();

        // Tamper with a byte in the payload region.
        if evidence.data.len() > 10 {
            evidence.data[10] ^= 0xFF;
        }

        let result = verifier.verify(&evidence, None);
        assert!(result.is_err());
    }
}
