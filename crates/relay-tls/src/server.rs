//! Server-side attested TLS: generate a self-signed certificate with an embedded
//! attestation quote, bound to the TLS public key and relay configuration via
//! REPORTDATA.
//!
//! ## REPORTDATA layout (64 bytes)
//!
//! ```text
//! [ SHA-384(SPKI) (48 bytes) | config_hash[0..16] (16 bytes) ]
//! ```
//!
//! - Bytes 0..48: SHA-384 of the TLS public key's SPKI DER encoding.
//!   This binds the attestation to a specific TLS channel.
//! - Bytes 48..64: first 16 bytes of SHA-256(relay_config).
//!   This binds the attestation to a specific upstream configuration, so
//!   clients can verify which upstreams the relay is permitted to contact.
//!   If no config hash is provided (development), these bytes are zero.

use std::sync::Arc;

use rcgen::KeyPair;
use relay_attest::quote;
use relay_attest::types::AttestError;
use relay_attest::Attester;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha384};

/// Holds the TLS server configuration backed by an attested certificate.
pub struct AttestedTlsServer {
    server_config: Arc<rustls::ServerConfig>,
    /// The raw DER certificate (for inspection / logging the measurement).
    cert_der: Vec<u8>,
}

impl AttestedTlsServer {
    /// Create a new attested TLS server.
    ///
    /// 1. Generates an ephemeral key pair
    /// 2. Hashes the public key with SHA-384 → 48 bytes → first 48 bytes of REPORTDATA
    /// 3. Copies `config_hash[0..16]` into REPORTDATA bytes 48..64 (if provided)
    /// 4. Calls `attester.attest(reportdata)` to get hardware-signed evidence
    /// 5. Embeds the evidence in a self-signed X.509 certificate
    /// 6. Builds a `rustls::ServerConfig` with this certificate
    ///
    /// ## `config_hash`
    ///
    /// An optional 32-byte hash of the relay's security-critical configuration
    /// (computed by `RelayConfig::config_hash()`). The first 16 bytes are placed
    /// into REPORTDATA bytes 48..64, binding the attestation to a specific
    /// upstream routing configuration. Clients that know the expected config hash
    /// can verify it from the REPORTDATA in the attestation quote.
    ///
    /// Pass `None` during development (bytes 48..64 will be zero).
    pub fn new(attester: &dyn Attester, config_hash: Option<&[u8; 32]>) -> Result<Self, AttestError> {
        // Step 1: generate key pair.
        let key_pair = KeyPair::generate()
            .map_err(|e| AttestError::GenerationFailed(format!("keygen: {e}")))?;

        // Step 2: compute REPORTDATA.
        // Bytes 0..48  = SHA-384(public_key_der)  — TLS key binding
        // Bytes 48..64 = config_hash[0..16]        — config binding
        let pubkey_der = key_pair.public_key_der();
        let hash = Sha384::digest(&pubkey_der);
        let mut reportdata = [0u8; 64];
        reportdata[..48].copy_from_slice(&hash);

        if let Some(ch) = config_hash {
            reportdata[48..64].copy_from_slice(&ch[..16]);
        }

        // Step 3: generate attestation evidence binding the public key + config.
        let evidence = attester.attest(&reportdata)?;

        // Step 4: embed evidence in self-signed cert.
        let params = quote::cert_params_with_evidence(&evidence);
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AttestError::X509Error(format!("self-sign: {e}")))?;
        let cert_der = cert.der().to_vec();

        // Step 5: build rustls ServerConfig.
        let private_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let cert_chain = vec![CertificateDer::from(cert_der.clone())];

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key_der)
            .map_err(|e| AttestError::Other(anyhow::anyhow!("rustls config: {e}")))?;

        Ok(Self {
            server_config: Arc::new(server_config),
            cert_der,
        })
    }

    /// Get the `rustls::ServerConfig` to use with a TLS acceptor.
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.server_config)
    }

    /// Get the raw DER certificate bytes (useful for debugging / logging).
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_attest::mock::MockAttester;

    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn creates_server_config_with_mock() {
        install_crypto_provider();
        let attester = MockAttester;
        let server = AttestedTlsServer::new(&attester, None).unwrap();

        let _ = server.server_config();
        assert!(!server.cert_der().is_empty());
    }

    #[test]
    fn cert_contains_evidence() {
        install_crypto_provider();
        let attester = MockAttester;
        let server = AttestedTlsServer::new(&attester, None).unwrap();

        let evidence =
            relay_attest::quote::extract_evidence_from_cert(server.cert_der()).unwrap();
        assert_eq!(evidence.tee_type, relay_attest::TeeType::Mock);
    }

    #[test]
    fn config_hash_is_embedded_in_reportdata() {
        install_crypto_provider();
        let attester = MockAttester;
        let config_hash = [0xABu8; 32];
        let server = AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap();

        // Extract evidence and verify REPORTDATA bytes 48..64 match config_hash[0..16].
        let evidence =
            relay_attest::quote::extract_evidence_from_cert(server.cert_der()).unwrap();
        let verifier = relay_attest::mock::MockVerifier;
        use relay_attest::Verifier;
        let reportdata = verifier.verify(&evidence, None).unwrap();

        assert_eq!(&reportdata[48..64], &config_hash[..16]);
    }
}
