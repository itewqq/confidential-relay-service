//! Client-side attested TLS: a custom `rustls::ServerCertVerifier` that extracts
//! and verifies the attestation evidence embedded in the server's X.509 certificate.

use std::sync::Arc;

use relay_attest::quote::{extract_evidence_from_cert, extract_spki_from_cert};
use relay_attest::Verifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::verify_tls12_signature as crypto_verify_tls12;
use rustls::crypto::verify_tls13_signature as crypto_verify_tls13;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha384};

/// A `rustls` server certificate verifier that checks attestation evidence.
///
/// During the TLS handshake this verifier:
/// 1. Extracts the attestation evidence from the server cert's X.509 extension
/// 2. Extracts the TLS public key from the cert
/// 3. Computes `expected_reportdata`:
///    - Bytes 0..48: `SHA-384(SPKI)`
///    - Bytes 48..64: `config_hash[0..16]` (if provided), else zeros
/// 4. Calls `Verifier::verify(evidence, expected_measurement)` to check the
///    hardware signature and measurement
/// 5. Confirms the REPORTDATA in the evidence matches the expected value
///    (proving the TLS key lives inside the attested TEE and the config is as expected)
pub struct AttestedCertVerifier {
    verifier: Arc<dyn Verifier>,
    expected_measurement: Option<Vec<u8>>,
    /// Optional expected config hash (32 bytes). If set, REPORTDATA bytes 48..64
    /// must match `config_hash[0..16]`.
    expected_config_hash: Option<[u8; 32]>,
}

// Manual Debug impl because `dyn Verifier` doesn't implement Debug.
impl std::fmt::Debug for AttestedCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedCertVerifier")
            .field("expected_measurement", &self.expected_measurement)
            .field("expected_config_hash", &self.expected_config_hash.map(hex::encode))
            .finish_non_exhaustive()
    }
}

impl AttestedCertVerifier {
    /// Create a new verifier.
    ///
    /// - `verifier`: the attestation verifier (e.g. `MockVerifier`, `SevSnpVerifier`)
    /// - `expected_measurement`: if `Some`, the evidence's measurement (MRTD /
    ///   MEASUREMENT) must match this value exactly.  If `None`, measurement is
    ///   not checked (useful for TOFU or audit-only mode).
    /// - `expected_config_hash`: if `Some`, REPORTDATA bytes 48..64 must match
    ///   `config_hash[0..16]`. This verifies the relay's upstream configuration
    ///   is as expected. If `None`, config binding is not checked.
    pub fn new(
        verifier: Arc<dyn Verifier>,
        expected_measurement: Option<Vec<u8>>,
        expected_config_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            verifier,
            expected_measurement,
            expected_config_hash,
        }
    }
}


impl ServerCertVerifier for AttestedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let cert_der = end_entity.as_ref();

        // 1. Extract attestation evidence from the X.509 extension.
        let evidence = extract_evidence_from_cert(cert_der).map_err(|e| {
            TlsError::General(format!("failed to extract attestation evidence: {e}"))
        })?;

        // 2. Extract the full SPKI (SubjectPublicKeyInfo) from the certificate.
        //    This must match what the server hashes (rcgen KeyPair::public_key_der()).
        let spki_bytes = extract_spki_from_cert(cert_der)
            .map_err(|e| TlsError::General(format!("failed to extract SPKI: {e}")))?;

        // 3. Compute expected REPORTDATA.
        //    Bytes  0..48: SHA-384(SPKI) — binds attestation to this TLS key
        //    Bytes 48..64: config_hash[0..16] — binds attestation to upstream config
        let hash = Sha384::digest(&spki_bytes);
        let mut expected_reportdata = [0u8; 64];
        expected_reportdata[..48].copy_from_slice(&hash);

        if let Some(ref ch) = self.expected_config_hash {
            expected_reportdata[48..64].copy_from_slice(&ch[..16]);
        }

        // 4. Verify the attestation evidence (signature chain + measurement).
        let actual_reportdata = self
            .verifier
            .verify(&evidence, self.expected_measurement.as_deref())
            .map_err(|e| TlsError::General(format!("attestation verification failed: {e}")))?;

        // 5. Confirm REPORTDATA bytes 0..48 match — proves the TLS key is inside the TEE.
        if actual_reportdata[..48] != expected_reportdata[..48] {
            return Err(TlsError::General(
                "REPORTDATA does not match TLS public key hash — \
                 the TLS channel may not terminate inside the TEE"
                    .to_string(),
            ));
        }

        // 6. Confirm REPORTDATA bytes 48..64 match config hash (if client expects one).
        if self.expected_config_hash.is_some()
            && actual_reportdata[48..64] != expected_reportdata[48..64]
        {
            return Err(TlsError::General(format!(
                "REPORTDATA config hash mismatch — relay upstream config is not as expected \
                 (expected: {}, actual: {})",
                hex::encode(&expected_reportdata[48..64]),
                hex::encode(&actual_reportdata[48..64]),
            )));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Delegate to rustls's crypto provider for real signature verification.
        // This ensures the TLS handshake can't be forged even with a stolen cert.
        let provider = rustls::crypto::ring::default_provider();
        crypto_verify_tls12(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let provider = rustls::crypto::ring::default_provider();
        crypto_verify_tls13(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Build a `rustls::ClientConfig` that uses [`AttestedCertVerifier`].
///
/// Ensures that the `ring` crypto provider is installed (idempotent) so this
/// function is safe to call from a fresh process without any prior setup.
///
/// - `expected_config_hash`: if `Some`, the verifier will check that the
///   relay's REPORTDATA bytes 48..64 match `config_hash[0..16]`.
pub fn attested_client_config(
    verifier: Arc<dyn Verifier>,
    expected_measurement: Option<Vec<u8>>,
    expected_config_hash: Option<[u8; 32]>,
) -> Arc<rustls::ClientConfig> {
    // Ensure a CryptoProvider is available process-wide. The call is
    // idempotent — if another thread or the server already installed it,
    // the Err is harmless and we discard it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_verifier =
        AttestedCertVerifier::new(verifier, expected_measurement, expected_config_hash);

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(cert_verifier))
        .with_no_client_auth();

    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_attest::mock::{MockAttester, MockVerifier};
    use relay_attest::Attester;

    #[test]
    fn verify_mock_cert_succeeds() {
        let attester = MockAttester;
        let verifier = Arc::new(MockVerifier) as Arc<dyn Verifier>;

        // Generate an attested cert the same way the server does.
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let pubkey_der = key_pair.public_key_der();
        let hash = Sha384::digest(&pubkey_der);
        let mut reportdata = [0u8; 64];
        reportdata[..48].copy_from_slice(&hash);

        let evidence = attester.attest(&reportdata).unwrap();
        let params = relay_attest::quote::cert_params_with_evidence(&evidence);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        let vc = AttestedCertVerifier::new(verifier, None, None);
        let result = vc.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("trusted-relay").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "verification should succeed: {result:?}");
    }

    #[test]
    fn verify_rejects_wrong_measurement() {
        let attester = MockAttester;
        let verifier = Arc::new(MockVerifier) as Arc<dyn Verifier>;

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let pubkey_der = key_pair.public_key_der();
        let hash = Sha384::digest(&pubkey_der);
        let mut reportdata = [0u8; 64];
        reportdata[..48].copy_from_slice(&hash);

        let evidence = attester.attest(&reportdata).unwrap();
        let params = relay_attest::quote::cert_params_with_evidence(&evidence);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        // Use a wrong expected measurement.
        let wrong_measurement = vec![0xFF; 32];
        let vc = AttestedCertVerifier::new(verifier, Some(wrong_measurement), None);
        let result = vc.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("trusted-relay").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err(), "should reject wrong measurement");
    }

    #[test]
    fn verify_config_hash_match_succeeds() {
        let attester = MockAttester;
        let verifier = Arc::new(MockVerifier) as Arc<dyn Verifier>;

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let pubkey_der = key_pair.public_key_der();
        let hash = Sha384::digest(&pubkey_der);

        let config_hash = [0xABu8; 32];
        let mut reportdata = [0u8; 64];
        reportdata[..48].copy_from_slice(&hash);
        reportdata[48..64].copy_from_slice(&config_hash[..16]);

        let evidence = attester.attest(&reportdata).unwrap();
        let params = relay_attest::quote::cert_params_with_evidence(&evidence);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        let vc = AttestedCertVerifier::new(verifier, None, Some(config_hash));
        let result = vc.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("trusted-relay").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "should accept matching config hash: {result:?}");
    }

    #[test]
    fn verify_config_hash_mismatch_fails() {
        let attester = MockAttester;
        let verifier = Arc::new(MockVerifier) as Arc<dyn Verifier>;

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let pubkey_der = key_pair.public_key_der();
        let hash = Sha384::digest(&pubkey_der);

        // Server uses config_hash_A in REPORTDATA
        let config_hash_a = [0xAAu8; 32];
        let mut reportdata = [0u8; 64];
        reportdata[..48].copy_from_slice(&hash);
        reportdata[48..64].copy_from_slice(&config_hash_a[..16]);

        let evidence = attester.attest(&reportdata).unwrap();
        let params = relay_attest::quote::cert_params_with_evidence(&evidence);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        // Client expects config_hash_B — should reject.
        let config_hash_b = [0xBBu8; 32];
        let vc = AttestedCertVerifier::new(verifier, None, Some(config_hash_b));
        let result = vc.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("trusted-relay").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err(), "should reject mismatched config hash");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("config hash mismatch"), "error: {err}");
    }

    #[test]
    fn verify_no_expected_config_hash_ignores_server_config() {
        // When client doesn't set expected_config_hash, it should accept
        // any config hash from the server.
        let attester = MockAttester;
        let verifier = Arc::new(MockVerifier) as Arc<dyn Verifier>;

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let pubkey_der = key_pair.public_key_der();
        let hash = Sha384::digest(&pubkey_der);

        let config_hash = [0xABu8; 32];
        let mut reportdata = [0u8; 64];
        reportdata[..48].copy_from_slice(&hash);
        reportdata[48..64].copy_from_slice(&config_hash[..16]);

        let evidence = attester.attest(&reportdata).unwrap();
        let params = relay_attest::quote::cert_params_with_evidence(&evidence);
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        // No expected config hash — should still accept.
        let vc = AttestedCertVerifier::new(verifier, None, None);
        let result = vc.verify_server_cert(
            &cert_der,
            &[],
            &ServerName::try_from("trusted-relay").unwrap(),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok(), "should accept when no config hash expected: {result:?}");
    }
}
