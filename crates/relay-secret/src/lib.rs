//! Attested provider-secret injection protocol.
//!
//! The CVM relay uses this crate to prove its attested TLS certificate to a
//! secret broker. The broker verifies the embedded TEE evidence, measurement,
//! config hash, and TLS-key binding before returning the provider credential.

use std::sync::Arc;

use anyhow::{Context, Result};
use relay_attest::quote::{extract_evidence_from_cert, extract_spki_from_cert};
use relay_attest::traits::Verifier;
use relay_attest::TeeType;
use relay_core::secrets::ProviderCredential;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

/// Request sent from the CVM relay to a secret broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRequest {
    /// DER-encoded attested TLS certificate, hex encoded.
    pub attested_cert_der_hex: String,
    /// Deployment/config hash expected to be bound into REPORTDATA bytes 48..64.
    pub config_hash_hex: String,
    /// Broker-provided or deployment-provided nonce. This is logged/audited and
    /// leaves room for replay protection in production brokers.
    pub nonce: String,
}

/// Response returned by the secret broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretResponse {
    pub provider_credential: ProviderCredential,
}

/// Verify an attested secret request and return the report data if valid.
pub fn verify_secret_request(
    request: &SecretRequest,
    verifier: Arc<dyn Verifier>,
    expected_measurement: Option<&[u8]>,
    expected_config_hash: Option<[u8; 32]>,
) -> Result<[u8; 64]> {
    if request.nonce.trim().is_empty() {
        anyhow::bail!("secret request nonce must not be empty");
    }

    let cert_der = hex::decode(&request.attested_cert_der_hex)
        .context("secret request cert is not valid hex")?;
    verify_attested_cert(
        &cert_der,
        &request.config_hash_hex,
        verifier,
        expected_measurement,
        expected_config_hash,
    )
}

/// Verify an attested TLS certificate and return its report data.
pub fn verify_attested_cert(
    cert_der: &[u8],
    config_hash_hex: &str,
    verifier: Arc<dyn Verifier>,
    expected_measurement: Option<&[u8]>,
    expected_config_hash: Option<[u8; 32]>,
) -> Result<[u8; 64]> {
    let evidence = extract_evidence_from_cert(cert_der).context("attested cert lacks evidence")?;
    let spki = extract_spki_from_cert(cert_der).context("failed to extract attested cert SPKI")?;
    let spki_hash = Sha384::digest(spki);
    let request_config_hash = parse_config_hash(config_hash_hex)?;

    let expected_reportdata = expected_reportdata_for_cert(&spki_hash, request_config_hash);
    let attestation_expected = match evidence.tee_type {
        // Confidential Space carries the TLS/config binding in token nonces, so
        // the backend verifier needs the expected 64-byte reportdata.
        TeeType::GcpConfidentialSpace => Some(&expected_reportdata[..]),
        // SEV-SNP/TDX/mock use this verifier argument for launch measurement.
        _ => expected_measurement,
    };

    let reportdata = verifier
        .verify(&evidence, attestation_expected)
        .context("attestation evidence verification failed")?;

    verify_reportdata_bindings(
        &reportdata,
        &spki_hash,
        config_hash_hex,
        expected_config_hash,
    )?;
    Ok(reportdata)
}

fn expected_reportdata_for_cert(spki_sha384: &[u8], config_hash: [u8; 32]) -> [u8; 64] {
    let mut reportdata = [0u8; 64];
    if spki_sha384.len() >= 48 {
        reportdata[..48].copy_from_slice(&spki_sha384[..48]);
    }
    reportdata[48..64].copy_from_slice(&config_hash[..16]);
    reportdata
}

/// Verify REPORTDATA TLS-key and config bindings.
pub fn verify_reportdata_bindings(
    reportdata: &[u8; 64],
    spki_sha384: &[u8],
    config_hash_hex: &str,
    expected_config_hash: Option<[u8; 32]>,
) -> Result<()> {
    if spki_sha384.len() < 48 {
        anyhow::bail!("SPKI SHA-384 digest must be at least 48 bytes");
    }

    if reportdata[..48] != spki_sha384[..48] {
        anyhow::bail!(
            "REPORTDATA TLS key binding mismatch: expected {}, actual {}",
            hex::encode(&spki_sha384[..48]),
            hex::encode(&reportdata[..48])
        );
    }

    let request_config_hash = parse_config_hash(config_hash_hex)?;
    if let Some(expected) = expected_config_hash {
        if request_config_hash != expected {
            anyhow::bail!(
                "secret request config hash mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(request_config_hash)
            );
        }
    }

    if reportdata[48..64] != request_config_hash[..16] {
        anyhow::bail!(
            "REPORTDATA config binding mismatch: expected {}, actual {}",
            hex::encode(&request_config_hash[..16]),
            hex::encode(&reportdata[48..64])
        );
    }

    Ok(())
}

/// Request the provider credential from a broker after the relay has generated
/// its attested TLS certificate.
pub async fn fetch_provider_credential(
    broker_url: &str,
    broker_ca_pem: Option<&str>,
    attested_cert_der: &[u8],
    config_hash: [u8; 32],
    nonce: impl Into<String>,
) -> Result<ProviderCredential> {
    validate_broker_url(broker_url)?;
    let request = SecretRequest {
        attested_cert_der_hex: hex::encode(attested_cert_der),
        config_hash_hex: hex::encode(config_hash),
        nonce: nonce.into(),
    };

    let response = secret_broker_client(broker_ca_pem)?
        .post(broker_url)
        .json(&request)
        .send()
        .await
        .with_context(|| format!("failed to call secret broker at {broker_url}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("secret broker returned {status}: {body}");
    }

    let response: SecretResponse = response
        .json()
        .await
        .context("secret broker response is not valid JSON")?;
    Ok(response.provider_credential)
}

pub fn secret_broker_client(broker_ca_pem: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(pem) = broker_ca_pem {
        for cert in reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .context("secret broker CA PEM is invalid")?
        {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .context("failed to build secret broker HTTP client")
}

fn validate_broker_url(broker_url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(broker_url).context("secret broker URL is invalid")?;
    if parsed.scheme() == "https" {
        return Ok(());
    }

    let is_loopback = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
    });
    let explicit_dev_override =
        std::env::var_os("TRUSTED_RELAY_ALLOW_INSECURE_SECRET_BROKER").is_some();
    if parsed.scheme() == "http" && (is_loopback || explicit_dev_override) {
        return Ok(());
    }

    anyhow::bail!(
        "secret broker URL must use https:// outside localhost; set TRUSTED_RELAY_ALLOW_INSECURE_SECRET_BROKER=1 only for private dev tests"
    )
}

fn parse_config_hash(raw: &str) -> Result<[u8; 32]> {
    let clean = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    let bytes = hex::decode(clean).context("config hash is not valid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("config hash must be 32 bytes, got {}", bytes.len());
    }
    Ok(bytes.try_into().expect("length checked"))
}

pub fn sha256_hex(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

pub fn sha256_hex_bytes(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_attest::mock::{MockAttester, MockVerifier};
    use relay_core::secrets::ProviderCredential;
    use relay_tls::server::AttestedTlsServer;

    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn verifies_mock_secret_request() {
        install_crypto_provider();
        let config_hash = [0x42u8; 32];
        let attester = MockAttester;
        let server = AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap();
        let request = SecretRequest {
            attested_cert_der_hex: hex::encode(server.cert_der()),
            config_hash_hex: hex::encode(config_hash),
            nonce: "nonce-1".to_string(),
        };

        let reportdata =
            verify_secret_request(&request, Arc::new(MockVerifier), None, Some(config_hash))
                .unwrap();

        assert_eq!(&reportdata[48..64], &config_hash[..16]);
    }

    #[test]
    fn rejects_wrong_config_hash() {
        install_crypto_provider();
        let config_hash = [0x42u8; 32];
        let wrong_hash = [0x24u8; 32];
        let attester = MockAttester;
        let server = AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap();
        let request = SecretRequest {
            attested_cert_der_hex: hex::encode(server.cert_der()),
            config_hash_hex: hex::encode(config_hash),
            nonce: "nonce-1".to_string(),
        };

        let result =
            verify_secret_request(&request, Arc::new(MockVerifier), None, Some(wrong_hash));

        assert!(result.is_err());
    }

    #[test]
    fn rejects_changed_release_artifact_digest_via_config_hash() {
        install_crypto_provider();
        let release_a_config_hash = [0xAAu8; 32];
        let release_b_config_hash = [0xBBu8; 32];
        let attester = MockAttester;
        let server = AttestedTlsServer::new(&attester, Some(&release_b_config_hash)).unwrap();
        let request = SecretRequest {
            attested_cert_der_hex: hex::encode(server.cert_der()),
            config_hash_hex: hex::encode(release_b_config_hash),
            nonce: "nonce-1".to_string(),
        };

        let result = verify_secret_request(
            &request,
            Arc::new(MockVerifier),
            None,
            Some(release_a_config_hash),
        );

        assert!(result.is_err());
    }

    #[test]
    fn secret_response_round_trips() {
        let response = SecretResponse {
            provider_credential: ProviderCredential {
                auth_scheme: "Bearer".to_string(),
                token: "provider-secret".to_string(),
            },
        };
        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: SecretResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.provider_credential.token, "provider-secret");
    }

    #[test]
    fn rejects_insecure_remote_broker_url() {
        let err = validate_broker_url("http://10.0.0.5:8787/v1/secret/provider")
            .unwrap_err()
            .to_string();
        assert!(err.contains("https"), "{err}");
        assert!(validate_broker_url("http://127.0.0.1:8787/v1/secret/provider").is_ok());
    }

    #[test]
    fn hashes_broker_ca_material() {
        assert_eq!(sha256_hex("broker-ca").len(), 64);
        assert_ne!(sha256_hex("broker-ca"), sha256_hex("other-ca"));
        assert_eq!(sha256_hex("broker-ca"), sha256_hex_bytes(b"broker-ca"));
    }
}
