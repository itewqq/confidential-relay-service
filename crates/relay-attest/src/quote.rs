//! X.509 certificate extension embedding and extraction for attestation evidence.
//!
//! The attestation quote (Evidence) is embedded as a custom X.509 certificate
//! extension so that the TLS certificate itself carries the proof of TEE execution.
//! The client extracts and verifies this extension during the TLS handshake.
//!
//! We use a custom OID under the Gramine RA-TLS convention:
//!   `1.2.840.113741.1337.6` — attestation evidence blob
//!   `1.2.840.113741.1337.7` — evidence type indicator (TDX / SEV-SNP / Mock)

use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};
use x509_parser::prelude::*;

use crate::types::{AttestError, Evidence, TeeType};

/// OID for the attestation evidence blob (as rcgen `&[u64]` arcs).
const OID_EVIDENCE_BLOB: &[u64] = &[1, 2, 840, 113741, 1337, 6];
/// OID for the TEE type indicator.
const OID_TEE_TYPE: &[u64] = &[1, 2, 840, 113741, 1337, 7];

/// The same OIDs as dot-notation strings for x509-parser comparison.
const OID_EVIDENCE_BLOB_STR: &str = "1.2.840.113741.1337.6";
const OID_TEE_TYPE_STR: &str = "1.2.840.113741.1337.7";

fn tee_type_to_byte(t: TeeType) -> u8 {
    match t {
        TeeType::Mock => 0,
        TeeType::Tdx => 1,
        TeeType::SevSnp => 2,
    }
}

fn byte_to_tee_type(b: u8) -> Result<TeeType, AttestError> {
    match b {
        0 => Ok(TeeType::Mock),
        1 => Ok(TeeType::Tdx),
        2 => Ok(TeeType::SevSnp),
        _ => Err(AttestError::X509Error(format!("unknown TEE type byte: {b}"))),
    }
}

/// Generate an rcgen [`CertificateParams`] that includes the attestation evidence
/// as a custom X.509 extension.
///
/// The returned params can be used with [`CertificateParams::self_signed`] and a
/// [`KeyPair`] to produce a DER-encoded certificate.
pub fn cert_params_with_evidence(evidence: &Evidence) -> CertificateParams {
    let mut params = CertificateParams::new(vec!["trusted-relay".to_string()])
        .expect("valid cert params");

    params
        .distinguished_name
        .push(DnType::CommonName, "trusted-relay");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "trusted-relay");

    // Extension 1: the raw evidence blob.
    let ext_blob = CustomExtension::from_oid_content(OID_EVIDENCE_BLOB, evidence.data.clone());
    params.custom_extensions.push(ext_blob);

    // Extension 2: TEE type indicator (single byte).
    let ext_type =
        CustomExtension::from_oid_content(OID_TEE_TYPE, vec![tee_type_to_byte(evidence.tee_type)]);
    params.custom_extensions.push(ext_type);

    params
}

/// Generate a self-signed DER certificate embedding the attestation evidence.
///
/// Returns `(cert_der, key_pair)` — the key pair's private key should be used to
/// configure the TLS server.
pub fn generate_attested_cert(
    evidence: &Evidence,
) -> Result<(Vec<u8>, KeyPair), AttestError> {
    let key_pair =
        KeyPair::generate().map_err(|e| AttestError::X509Error(format!("keygen failed: {e}")))?;

    let params = cert_params_with_evidence(evidence);
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AttestError::X509Error(format!("self-sign failed: {e}")))?;

    Ok((cert.der().to_vec(), key_pair))
}

/// Extract attestation evidence from a DER-encoded X.509 certificate.
pub fn extract_evidence_from_cert(cert_der: &[u8]) -> Result<Evidence, AttestError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AttestError::X509Error(format!("failed to parse cert: {e}")))?;

    let mut evidence_data: Option<Vec<u8>> = None;
    let mut tee_type: Option<TeeType> = None;

    for ext in cert.extensions() {
        let oid_str = ext.oid.to_string();
        if oid_str == OID_EVIDENCE_BLOB_STR {
            evidence_data = Some(ext.value.to_vec());
        } else if oid_str == OID_TEE_TYPE_STR {
            if ext.value.is_empty() {
                return Err(AttestError::X509Error(
                    "TEE type extension is empty".to_string(),
                ));
            }
            tee_type = Some(byte_to_tee_type(ext.value[0])?);
        }
    }

    let data = evidence_data.ok_or_else(|| {
        AttestError::X509Error("missing attestation evidence extension".to_string())
    })?;
    let tt = tee_type
        .ok_or_else(|| AttestError::X509Error("missing TEE type extension".to_string()))?;

    Ok(Evidence {
        tee_type: tt,
        data,
    })
}

/// Extract the SubjectPublicKeyInfo (SPKI) DER-encoded bytes from a certificate.
///
/// This returns the full SPKI structure (algorithm OID + raw key bits), matching
/// what `rcgen::KeyPair::public_key_der()` returns.  Both server and client must
/// hash the same representation to get a matching REPORTDATA.
pub fn extract_spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, AttestError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AttestError::X509Error(format!("failed to parse cert: {e}")))?;

    // `subject_pki.raw` gives us the raw DER bytes of the full SPKI structure.
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAttester;
    use crate::traits::Attester;

    #[test]
    fn embed_and_extract_round_trip() {
        let attester = MockAttester;
        let user_data = [99u8; 64];
        let evidence = attester.attest(&user_data).unwrap();

        let (cert_der, _key_pair) = generate_attested_cert(&evidence).unwrap();

        let extracted = extract_evidence_from_cert(&cert_der).unwrap();
        assert_eq!(extracted.tee_type, evidence.tee_type);
        assert_eq!(extracted.data, evidence.data);
    }

    #[test]
    fn extract_spki_works() {
        let attester = MockAttester;
        let evidence = attester.attest(&[0u8; 64]).unwrap();
        let (cert_der, _kp) = generate_attested_cert(&evidence).unwrap();

        let spki = extract_spki_from_cert(&cert_der).unwrap();
        assert!(!spki.is_empty());
    }
}
