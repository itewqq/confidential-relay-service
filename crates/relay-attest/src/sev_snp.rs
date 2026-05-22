//! AMD SEV-SNP attestation backend.
//!
//! ## Attester
//! Generates an attestation report by issuing an ioctl to `/dev/sev-guest`.
//! The REPORT_DATA field (64 bytes) carries the SHA-384 hash of the TLS public key.
//! The report is signed by the AMD Secure Processor using a per-chip VCEK key.
//!
//! Only works on Linux inside a SEV-SNP Confidential VM.
//! On other platforms, the `sev-snp` feature still compiles but attester returns an error.
//!
//! ## Verifier
//! Verifies the attestation report:
//! 1. Fetches or reads the VCEK/VLEK certificate and AMD KDS product chain
//! 2. Verifies the VCEK/VLEK chains to AMD's ARK (root) certificate
//! 3. Verifies the report signature against the endorsement key (ECDSA P-384)
//! 4. Checks the code measurement against the expected value
//! 5. Returns the REPORT_DATA for the caller to match against the TLS public key hash
//!
//! The verifier works on any platform (Mac, Linux, etc.) — only the attester needs
//! real SEV-SNP hardware.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::traits::{Attester, Verifier};
use crate::types::{AttestError, Evidence, TeeType};
#[cfg(feature = "sev-snp")]
use asn1_rs::FromDer as Asn1FromDer;

// ═══════════════════════════════════════════════════════════════════════════════
// Constants — SNP attestation report layout
// ═══════════════════════════════════════════════════════════════════════════════

/// Total size of an SNP attestation report (as returned by the firmware).
const SNP_REPORT_SIZE: usize = 0x4A0; // 1184 bytes

/// Offsets within the attestation report for fields we need.
/// Reference: AMD SEV-SNP ABI Specification, Table 21 "ATTESTATION_REPORT Structure"
const REPORT_DATA_OFFSET: usize = 0x50; // 64 bytes of user-supplied data
const REPORT_DATA_LEN: usize = 64;
const MEASUREMENT_OFFSET: usize = 0x90; // 48 bytes: SHA-384 of launch digest
const MEASUREMENT_LEN: usize = 48;
const GUEST_SVN_OFFSET: usize = 0x04; // 4-byte guest SVN
const POLICY_OFFSET: usize = 0x08; // 8-byte guest policy
const SIGNING_KEY_OFFSET: usize = 0x48; // signature key selector + mask bits
const SIGNATURE_OFFSET: usize = 0x2A0; // ECDSA P-384 signature (r || s, each 72 bytes)
const SIGNATURE_LEN: usize = 512; // Signature area (padded)
const ECDSA_P384_SCALAR_LEN: usize = 48;
const ECDSA_P384_AMD_SCALAR_LEN: usize = 72;

// The signed portion of the report is everything before the signature.
const SIGNED_DATA_LEN: usize = SIGNATURE_OFFSET;

// Fields needed to build the VCEK URL
const CHIP_ID_OFFSET: usize = 0x1A0; // 64 bytes
const CHIP_ID_LEN: usize = 64;
// Reported TCB at offset 0x180, 8 bytes.
const REPORTED_TCB_OFFSET: usize = 0x180;

const POLICY_DEBUG_ALLOWED_BIT: u64 = 1 << 19;
const KDS_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);
#[cfg(target_os = "linux")]
const SNP_CERT_BLOB_SIZE: usize = 16 * 1024;
const SNP_CERT_TABLE_ENTRY_SIZE: usize = 24;

const SNP_SIGNING_KEY_VCEK: u8 = 0;
const SNP_SIGNING_KEY_VLEK: u8 = 1;

const GUID_VCEK: [u8; 16] = guid_bytes("63da758d-e664-4564-adc5-f4b93be8accd");
const GUID_VLEK: [u8; 16] = guid_bytes("a8074bc2-a25a-483e-aae6-39c045a0b8a1");

// ═══════════════════════════════════════════════════════════════════════════════
// Attester (Linux-only ioctl)
// ═══════════════════════════════════════════════════════════════════════════════

pub struct SevSnpAttester;

impl Attester for SevSnpAttester {
    fn name(&self) -> &'static str {
        "AMD SEV-SNP"
    }

    fn attest(&self, user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
        #[cfg(target_os = "linux")]
        {
            attest_linux(user_data)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = user_data;
            Err(AttestError::GenerationFailed(
                "SEV-SNP attestation requires Linux with /dev/sev-guest".to_string(),
            ))
        }
    }
}

/// Linux-specific implementation using /dev/sev-guest ioctl.
#[cfg(target_os = "linux")]
fn attest_linux(user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
    match attest_linux_ext(user_data) {
        Ok(evidence) => return Ok(evidence),
        Err(e) => {
            tracing::debug!(error = %e, "SNP_GET_EXT_REPORT failed; falling back to SNP_GET_REPORT")
        }
    }

    attest_linux_report_only(user_data)
}

#[cfg(target_os = "linux")]
fn attest_linux_report_only(user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // SNP_GET_REPORT ioctl structures.
    // Reference: linux/include/uapi/linux/sev-guest.h

    /// ioctl request number for SNP_GET_REPORT.
    /// _IOWR('S', 0x0, struct snp_guest_request_ioctl); the struct is 32 bytes on x86_64.
    const SNP_GET_REPORT: libc::c_ulong = 0xC0205300;

    #[repr(C)]
    struct SnpReportReq {
        /// User data to include in REPORT_DATA (64 bytes).
        user_data: [u8; 64],
        /// VMPL level (0 for most cases).
        vmpl: u32,
        /// Reserved, must be zero.
        rsvd: [u8; 28],
    }

    #[repr(C)]
    struct SnpReportResp {
        /// The attestation report data.
        data: [u8; 4000], // Large enough buffer
    }

    #[repr(C)]
    struct SnpGuestRequestIoctl {
        /// Request message version (must be 1).
        msg_version: u8,
        /// Request payload.
        req_data: u64,
        /// Response payload.
        resp_data: u64,
        /// Firmware error code (output).
        fw_err: u64,
    }

    // Open the SEV guest device.
    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| AttestError::GenerationFailed(format!("open /dev/sev-guest: {e}")))?;

    let mut req = SnpReportReq {
        user_data: *user_data,
        vmpl: 0,
        rsvd: [0u8; 28],
    };

    let mut resp = SnpReportResp { data: [0u8; 4000] };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: &mut req as *mut SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        fw_err: 0,
    };

    let ret = unsafe { libc::ioctl(dev.as_raw_fd(), SNP_GET_REPORT, &mut ioctl_req) };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(AttestError::GenerationFailed(format!(
            "SNP_GET_REPORT ioctl failed: {errno} (fw_err: 0x{:x})",
            ioctl_req.fw_err
        )));
    }

    // The response data starts with a 32-byte status/reserved header, followed
    // by the SNP attestation report.
    let report_offset = 32;
    let report_data = resp.data[report_offset..report_offset + SNP_REPORT_SIZE].to_vec();

    Ok(Evidence {
        tee_type: TeeType::SevSnp,
        data: report_data,
    })
}

/// Linux-specific implementation using /dev/sev-guest SNP_GET_EXT_REPORT.
#[cfg(target_os = "linux")]
fn attest_linux_ext(user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    const SNP_GET_EXT_REPORT: libc::c_ulong = 0xC0205302;

    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        rsvd: [u8; 28],
    }

    #[repr(C)]
    struct SnpExtReportReq {
        data: SnpReportReq,
        certs_address: u64,
        certs_len: u32,
    }

    #[repr(C)]
    struct SnpReportResp {
        data: [u8; 4000],
    }

    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8,
        req_data: u64,
        resp_data: u64,
        fw_err: u64,
    }

    let dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| AttestError::GenerationFailed(format!("open /dev/sev-guest: {e}")))?;

    let mut certs = vec![0u8; SNP_CERT_BLOB_SIZE];
    let mut req = SnpExtReportReq {
        data: SnpReportReq {
            user_data: *user_data,
            vmpl: 0,
            rsvd: [0u8; 28],
        },
        certs_address: certs.as_mut_ptr() as u64,
        certs_len: SNP_CERT_BLOB_SIZE as u32,
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: &mut req as *mut SnpExtReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        fw_err: 0,
    };

    let ret = unsafe { libc::ioctl(dev.as_raw_fd(), SNP_GET_EXT_REPORT, &mut ioctl_req) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(AttestError::GenerationFailed(format!(
            "SNP_GET_EXT_REPORT ioctl failed: {errno} (fw_err: 0x{:x}, certs_len: {})",
            ioctl_req.fw_err, req.certs_len
        )));
    }

    let status = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
    let report_size = u32::from_le_bytes(resp.data[4..8].try_into().unwrap()) as usize;
    if status != 0 {
        return Err(AttestError::GenerationFailed(format!(
            "SNP_GET_EXT_REPORT firmware status: 0x{status:x}"
        )));
    }
    if report_size < SNP_REPORT_SIZE || 32 + SNP_REPORT_SIZE > resp.data.len() {
        return Err(AttestError::GenerationFailed(format!(
            "SNP_GET_EXT_REPORT returned invalid report size: {report_size}"
        )));
    }

    let mut data = Vec::new();
    data.extend_from_slice(&resp.data[32..32 + SNP_REPORT_SIZE]);
    let certs_len = cert_blob_used_len(&certs);
    data.extend_from_slice(&certs[..certs_len]);

    Ok(Evidence {
        tee_type: TeeType::SevSnp,
        data,
    })
}

#[cfg(target_os = "linux")]
fn cert_blob_used_len(certs: &[u8]) -> usize {
    let mut used = 0usize;
    let mut header_end = 0usize;
    for entry in certs.chunks_exact(SNP_CERT_TABLE_ENTRY_SIZE) {
        header_end += SNP_CERT_TABLE_ENTRY_SIZE;
        if entry.iter().all(|&b| b == 0) {
            break;
        }
        let offset = u32::from_le_bytes(entry[16..20].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().unwrap()) as usize;
        if let Some(end) = offset.checked_add(length) {
            used = used.max(end.min(certs.len()));
        }
    }
    if used == 0 {
        0
    } else {
        used.max(header_end)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Verifier (works on any platform)
// ═══════════════════════════════════════════════════════════════════════════════

/// AMD SEV-SNP report verifier with full VCEK/VLEK signature chain verification.
///
/// Verification steps:
/// 1. Parse the report structure and validate its length
/// 2. Extract chip_id + reported_tcb or embedded VLEK cert
/// 3. Verify the endorsement cert is signed by AMD's pinned ARK/product root
/// 4. Verify the report signature (ECDSA P-384) against the endorsement key
/// 5. Check the code measurement against the expected value
/// 6. Return REPORTDATA for TLS key binding verification
pub struct SevSnpVerifier;

impl Verifier for SevSnpVerifier {
    fn verify(
        &self,
        evidence: &Evidence,
        expected_measurement: Option<&[u8]>,
    ) -> Result<[u8; 64], AttestError> {
        if evidence.tee_type != TeeType::SevSnp {
            return Err(AttestError::UnsupportedTeeType(evidence.tee_type));
        }

        if evidence.data.len() < SNP_REPORT_SIZE {
            return Err(AttestError::VerificationFailed(format!(
                "report too short: {} < {}",
                evidence.data.len(),
                SNP_REPORT_SIZE
            )));
        }

        let report = report_bytes(&evidence.data)?;
        let certs = cert_blob_bytes(&evidence.data);

        // 1. Enforce basic guest policy before trusting report contents.
        // AMD's SEV-SNP guest policy bit 19 indicates whether debug is allowed.
        let policy = read_le_u64(report, POLICY_OFFSET)?;
        if policy & POLICY_DEBUG_ALLOWED_BIT != 0 {
            return Err(AttestError::VerificationFailed(format!(
                "SEV-SNP guest policy enables debug access (policy=0x{policy:016x})"
            )));
        }

        let guest_svn = read_le_u32(report, GUEST_SVN_OFFSET)?;

        // 2. Extract REPORT_DATA.
        let mut report_data = [0u8; 64];
        report_data
            .copy_from_slice(&report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_LEN]);

        // 3. Extract MEASUREMENT.
        let measurement = &report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN];

        // 4. Check measurement if expected.
        if let Some(expected) = expected_measurement {
            if measurement != expected {
                return Err(AttestError::MeasurementMismatch {
                    expected: hex::encode(expected),
                    actual: hex::encode(measurement),
                });
            }
        }

        // 5. Verify the ECDSA P-384 signature over the report.
        //    The signature covers bytes [0..SIGNED_DATA_LEN) of the report.
        let signed_data = &report[..SIGNED_DATA_LEN];
        let sig_area = &report[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN];
        // AMD's ABI stores ECDSA P-384 R/S as 72-byte little-endian integers.
        let sig_r = &sig_area[..ECDSA_P384_AMD_SCALAR_LEN];
        let sig_s = &sig_area[ECDSA_P384_AMD_SCALAR_LEN..ECDSA_P384_AMD_SCALAR_LEN * 2];

        let signing_key = signing_key(report)?;

        // Extract chip ID and TCB for VCEK URL construction.
        let chip_id_slice = &report[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_LEN];
        let reported_tcb_bytes = &report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8];
        let reported_tcb = u64::from_le_bytes(reported_tcb_bytes.try_into().unwrap());

        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(chip_id_slice);

        tracing::debug!(
            reported_tcb = %hex::encode(reported_tcb_bytes),
            measurement = %hex::encode(measurement),
            guest_svn,
            policy = format_args!("0x{policy:016x}"),
            signing_key = signing_key_name(signing_key),
            "SEV-SNP: verifying report signature against AMD endorsement key"
        );

        // 5. Verify signature using ECDSA P-384.
        //    In a live deployment, we fetch the VCEK cert from AMD KDS and extract
        //    the public key. For now, we verify the signature format is valid and
        //    perform the cryptographic check.
        verify_report_signature(
            signed_data,
            sig_r,
            sig_s,
            &chip_id,
            reported_tcb,
            signing_key,
            certs,
        )?;

        Ok(report_data)
    }
}

fn report_bytes(data: &[u8]) -> Result<&[u8], AttestError> {
    data.get(..SNP_REPORT_SIZE)
        .ok_or_else(|| AttestError::VerificationFailed("report too short".to_string()))
}

fn cert_blob_bytes(data: &[u8]) -> Option<&[u8]> {
    data.get(SNP_REPORT_SIZE..)
        .filter(|certs| !certs.is_empty())
}

fn signing_key(report: &[u8]) -> Result<u8, AttestError> {
    let bytes = report
        .get(SIGNING_KEY_OFFSET..SIGNING_KEY_OFFSET + 4)
        .ok_or_else(|| {
            AttestError::VerificationFailed("report too short for signing key flags".to_string())
        })?;
    let flags = u32::from_le_bytes(bytes.try_into().unwrap());
    if flags >> 5 != 0 {
        return Err(AttestError::VerificationFailed(format!(
            "SEV-SNP signer info has non-zero reserved bits: 0x{flags:08x}"
        )));
    }

    let key = ((flags >> 2) & 0x7) as u8;
    if key > SNP_SIGNING_KEY_VLEK && key != 7 {
        return Err(AttestError::VerificationFailed(format!(
            "reserved SEV-SNP signing key selector: {key}"
        )));
    }
    if key == 7 {
        return Err(AttestError::VerificationFailed(
            "SEV-SNP report is marked unsigned".to_string(),
        ));
    }
    Ok(key)
}

fn signing_key_name(signing_key: u8) -> &'static str {
    match signing_key {
        SNP_SIGNING_KEY_VCEK => "VCEK",
        SNP_SIGNING_KEY_VLEK => "VLEK",
        7 => "None",
        _ => "unknown",
    }
}

/// Verify the ECDSA P-384 signature on the report.
///
/// This function:
/// 1. Detects the AMD product name (Milan/Genoa/Turin) from the report version fields
/// 2. Constructs the VCEK URL from chip_id and reported_tcb
/// 3. Fetches the VCEK certificate from AMD KDS
/// 4. Fetches the AMD certificate chain (ASK → ARK) and verifies VCEK chains to AMD root
/// 5. Extracts the ECDSA P-384 public key from the VCEK
/// 6. Verifies the report signature against that public key
///
/// If VCEK fetching or chain validation fails, returns an error.
/// This function does NOT silently accept unverified reports.
fn verify_report_signature(
    signed_data: &[u8],
    sig_r: &[u8],
    sig_s: &[u8],
    chip_id: &[u8; 64],
    reported_tcb: u64,
    signing_key: u8,
    certs: Option<&[u8]>,
) -> Result<(), AttestError> {
    use p384::ecdsa::signature::Verifier;

    // Construct the expected signature from r || s.
    // Check that r and s are not all zeros (which would indicate a dummy/unsigned report).
    if sig_r.iter().all(|&b| b == 0) && sig_s.iter().all(|&b| b == 0) {
        return Err(AttestError::VerificationFailed(
            "SEV-SNP report has all-zero signature — report is unsigned or corrupted".to_string(),
        ));
    }

    let signature = amd_signature_to_p384(sig_r, sig_s)?;

    let mut errors = Vec::new();
    for product_name in candidate_product_names() {
        let result = (|| {
            let (leaf_der, chain_url, endorser_name) = match signing_key {
                SNP_SIGNING_KEY_VCEK => {
                    let leaf = if let Some(certs) = certs {
                        find_cert(certs, &GUID_VCEK)
                    } else {
                        None
                    };
                    let leaf_der = match leaf {
                        Some(cert) => cert,
                        None => {
                            let vcek_url = vcek_url(product_name, chip_id, reported_tcb);
                            tracing::debug!(url = %vcek_url, "fetching VCEK certificate from AMD KDS");
                            fetch_cert_bytes_cached(&vcek_url)?
                        }
                    };
                    (leaf_der, cert_chain_url("vcek", product_name), "VCEK")
                }
                SNP_SIGNING_KEY_VLEK => {
                    let certs = certs.ok_or_else(|| {
                        AttestError::VerificationFailed(
                            "SEV-SNP report is signed by VLEK but no certificate blob is embedded"
                                .to_string(),
                        )
                    })?;
                    let leaf_der = find_cert(certs, &GUID_VLEK).ok_or_else(|| {
                        AttestError::VerificationFailed(
                            "SEV-SNP certificate blob does not contain a VLEK certificate"
                                .to_string(),
                        )
                    })?;
                    (leaf_der, cert_chain_url("vlek", product_name), "VLEK")
                }
                other => {
                    return Err(AttestError::VerificationFailed(format!(
                        "unsupported SEV-SNP signing key selector: {other}"
                    )));
                }
            };

            tracing::debug!(url = %chain_url, endorser = endorser_name, "fetching AMD cert chain");
            let chain_pem_bytes = fetch_cert_bytes_cached(&chain_url)?;

            verify_vcek_chain(&leaf_der, &chain_pem_bytes)?;
            verify_vcek_certificate(&leaf_der)?;
            tracing::debug!(
                product_name,
                endorser = endorser_name,
                "certificate chain verified"
            );

            let vcek_pubkey = extract_p384_pubkey_from_der(&leaf_der)?;

            vcek_pubkey.verify(signed_data, &signature).map_err(|e| {
                AttestError::VerificationFailed(format!(
                    "SEV-SNP report signature verification failed against {product_name} {endorser_name}: {e}"
                ))
            })
        })();

        match result {
            Ok(()) => {
                tracing::debug!(
                    product_name,
                    signing_key = signing_key_name(signing_key),
                    "SEV-SNP report signature verified against AMD endorsement key"
                );
                return Ok(());
            }
            Err(e) => errors.push(format!("{product_name}: {e}")),
        }
    }

    Err(AttestError::VerificationFailed(format!(
        "SEV-SNP report could not be verified against AMD KDS product roots: {}",
        errors.join("; ")
    )))
}

fn amd_signature_to_p384(
    sig_r: &[u8],
    sig_s: &[u8],
) -> Result<p384::ecdsa::Signature, AttestError> {
    use p384::ecdsa::Signature;

    if sig_r.len() != ECDSA_P384_AMD_SCALAR_LEN || sig_s.len() != ECDSA_P384_AMD_SCALAR_LEN {
        return Err(AttestError::VerificationFailed(format!(
            "invalid SEV-SNP ECDSA signature field length: r={}, s={}, expected {} each",
            sig_r.len(),
            sig_s.len(),
            ECDSA_P384_AMD_SCALAR_LEN
        )));
    }

    let mut signature_bytes = [0u8; ECDSA_P384_SCALAR_LEN * 2];
    for (dst, src) in signature_bytes[..ECDSA_P384_SCALAR_LEN]
        .iter_mut()
        .zip(sig_r[..ECDSA_P384_SCALAR_LEN].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in signature_bytes[ECDSA_P384_SCALAR_LEN..]
        .iter_mut()
        .zip(sig_s[..ECDSA_P384_SCALAR_LEN].iter().rev())
    {
        *dst = *src;
    }

    Signature::from_slice(&signature_bytes).map_err(|e| {
        AttestError::VerificationFailed(format!("invalid ECDSA P-384 signature encoding: {e}"))
    })
}

fn read_le_u32(report: &[u8], offset: usize) -> Result<u32, AttestError> {
    let bytes = report
        .get(offset..offset + 4)
        .ok_or_else(|| AttestError::VerificationFailed("report too short for u32".to_string()))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_le_u64(report: &[u8], offset: usize) -> Result<u64, AttestError> {
    let bytes = report
        .get(offset..offset + 8)
        .ok_or_else(|| AttestError::VerificationFailed("report too short for u64".to_string()))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

struct CachedCert {
    fetched_at: Instant,
    bytes: Vec<u8>,
}

fn cert_cache() -> &'static Mutex<HashMap<String, CachedCert>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedCert>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fetch_cert_bytes_cached(url: &str) -> Result<Vec<u8>, AttestError> {
    let now = Instant::now();
    if let Some(bytes) = {
        let cache = cert_cache().lock().map_err(|_| {
            AttestError::VerificationFailed("certificate cache lock poisoned".to_string())
        })?;
        cache
            .get(url)
            .filter(|entry| now.duration_since(entry.fetched_at) < KDS_CACHE_TTL)
            .map(|entry| entry.bytes.clone())
    } {
        return Ok(bytes);
    }

    let bytes = fetch_cert_bytes(url)?;
    let mut cache = cert_cache().lock().map_err(|_| {
        AttestError::VerificationFailed("certificate cache lock poisoned".to_string())
    })?;
    cache.insert(
        url.to_string(),
        CachedCert {
            fetched_at: now,
            bytes: bytes.clone(),
        },
    );
    Ok(bytes)
}

/// Fetch raw certificate bytes from a URL (DER or PEM).
///
/// Works safely from any context:
/// - Multi-threaded Tokio runtime → `block_in_place` + `block_on`
/// - Current-thread Tokio runtime → spawn a dedicated OS thread to avoid panic
/// - No Tokio runtime at all → create a temporary one
fn fetch_cert_bytes(url: &str) -> Result<Vec<u8>, AttestError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We're inside a Tokio runtime. Check if block_in_place is safe
            // (it panics on current_thread runtimes).
            let runtime_flavor = handle.runtime_flavor();
            if runtime_flavor == tokio::runtime::RuntimeFlavor::MultiThread {
                // Multi-threaded runtime: block_in_place is safe.
                tokio::task::block_in_place(|| handle.block_on(fetch_url_bytes(url)))
            } else {
                // Current-thread runtime: block_in_place would panic.
                // Spawn a dedicated OS thread with its own runtime instead.
                let url = url.to_string();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            AttestError::VerificationFailed(format!(
                                "failed to create runtime for cert fetch: {e}"
                            ))
                        })?;
                    rt.block_on(fetch_url_bytes(&url))
                })
                .join()
                .map_err(|_| {
                    AttestError::VerificationFailed("cert fetch thread panicked".to_string())
                })?
            }
        }
        Err(_) => {
            // No async runtime — create a temporary one.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    AttestError::VerificationFailed(format!("failed to create runtime: {e}"))
                })?;
            rt.block_on(fetch_url_bytes(url))
        }
    }
}

/// Async helper: fetch raw bytes from a URL.
async fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, AttestError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| AttestError::VerificationFailed(format!("HTTP client error: {e}")))?;

    let resp = client.get(url).send().await.map_err(|e| {
        AttestError::VerificationFailed(format!("failed to fetch from AMD KDS ({url}): {e}"))
    })?;

    if !resp.status().is_success() {
        return Err(AttestError::VerificationFailed(format!(
            "AMD KDS returned HTTP {}: {url}",
            resp.status()
        )));
    }

    let bytes = resp.bytes().await.map_err(|e| {
        AttestError::VerificationFailed(format!("failed to read response body: {e}"))
    })?;

    Ok(bytes.to_vec())
}

/// Known AMD ARK (AMD Root Key) certificate fingerprints.
///
/// These are SHA-256 digests of the DER-encoded ARK certificates fetched from
/// AMD KDS. By pinning them here, we ensure the root of trust is a hardcoded
/// AMD key — not whatever the network serves us.
///
/// If AMD rotates or adds new ARK keys (e.g. for Turin), this list must be updated.
const PINNED_ARK_FINGERPRINTS: &[(&str, &str)] = &[
    // Milan ARK — RSA-4096, valid 2020-10-22 to 2045-10-22
    (
        "Milan",
        "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
    ),
    // Genoa ARK — RSA-4096, valid 2022-01-26 to 2047-01-26
    (
        "Genoa",
        "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
    ),
    // Turin ARK — RSA-4096, valid 2023-12-20 to 2048-12-20
    (
        "Turin",
        "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
    ),
];

/// Verify the endorsement certificate chains to AMD's root of trust.
///
/// The cert chain PEM from AMD KDS contains two certificates:
/// 1. ASK or ASVK — intermediate CA, signed by ARK
/// 2. ARK (AMD Root Key) — self-signed root CA
///
/// We verify:
/// - ARK fingerprint matches a **pinned** known AMD root key
/// - ASK/ASVK chains to the pinned ARK
/// - VCEK/VLEK chains to ASK/ASVK
fn verify_vcek_chain(leaf_der: &[u8], chain_pem_bytes: &[u8]) -> Result<(), AttestError> {
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    // Parse PEM chain — AMD KDS returns ASK first, then ARK.
    let chain_str = std::str::from_utf8(chain_pem_bytes).map_err(|e| {
        AttestError::VerificationFailed(format!("cert chain PEM is not valid UTF-8: {e}"))
    })?;

    let pems: Vec<::pem::Pem> = ::pem::parse_many(chain_str).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse cert chain PEM: {e}"))
    })?;

    if pems.len() < 2 {
        return Err(AttestError::VerificationFailed(format!(
            "expected at least 2 certificates in chain (ASK + ARK), got {}",
            pems.len()
        )));
    }

    let ark_der = pems[1].contents();

    // Parse each cert: first is ASK/ASVK, second is ARK.
    let _ = X509Certificate::from_der(pems[0].contents()).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse ASK/ASVK certificate: {e}"))
    })?;

    let _ = X509Certificate::from_der(ark_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse ARK certificate: {e}"))
    })?;

    // 1. Verify ARK fingerprint matches a pinned AMD root key.
    //    This is the critical check — without it, an attacker who controls the
    //    network path to KDS could supply their own fake ARK/ASK/VCEK chain.
    let ark_fingerprint = hex::encode(Sha256::digest(ark_der));
    let is_known_ark = PINNED_ARK_FINGERPRINTS
        .iter()
        .any(|(_, fp)| *fp == ark_fingerprint);

    if !is_known_ark {
        return Err(AttestError::VerificationFailed(format!(
            "ARK certificate fingerprint {} does not match any known AMD root key. \
             This may indicate a MITM attack or an unrecognised AMD generation. \
             Known fingerprints: {:?}",
            ark_fingerprint,
            PINNED_ARK_FINGERPRINTS
                .iter()
                .map(|(name, fp)| format!("{name}: {fp}"))
                .collect::<Vec<_>>()
        )));
    }
    tracing::debug!(fingerprint = %ark_fingerprint, "ARK matches pinned AMD root key");

    // 2. Verify ASK/ASVK -> ARK and VCEK/VLEK -> ASK/ASVK. AMD KDS certs use
    // RSASSA-PSS signatures, which x509-parser 0.16 cannot verify itself.
    let ark_der_owned = ark_der.to_vec();
    let ask_der_owned = pems[0].contents().to_vec();
    verify_cert_signature_with_alg(&ask_der_owned, &ark_der_owned, "ASK/ASVK")?;
    verify_cert_signed_by_trust_anchor(leaf_der, &ask_der_owned, &[], "VCEK/VLEK")?;

    // Parse the endorsement cert once here to ensure it is valid DER before the caller extracts
    // its P-384 public key for report signature verification.
    let _ = X509Certificate::from_der(leaf_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse VCEK/VLEK certificate: {e}"))
    })?;

    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct NoEkuValidator;

impl webpki::ExtendedKeyUsageValidator for NoEkuValidator {
    fn validate(&self, _iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

fn verify_cert_signature_with_alg(
    cert_der: &[u8],
    issuer_der: &[u8],
    label: &str,
) -> Result<(), AttestError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse {label} certificate: {e}"))
    })?;
    let (_, issuer) = X509Certificate::from_der(issuer_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse {label} issuer certificate: {e}"))
    })?;

    let tbs_der = tbs_certificate_der(cert_der)?;
    let verification_alg = rsa_pss_verification_alg(&cert.signature_algorithm)?;
    let key = ring::signature::UnparsedPublicKey::new(
        verification_alg,
        issuer.public_key().subject_public_key.data.as_ref(),
    );

    key.verify(tbs_der, cert.signature_value.data.as_ref())
        .map_err(|_| {
            AttestError::VerificationFailed(format!(
                "{label} certificate signature validation failed"
            ))
        })
}

fn rsa_pss_verification_alg(
    alg: &x509_parser::prelude::AlgorithmIdentifier<'_>,
) -> Result<&'static dyn ring::signature::VerificationAlgorithm, AttestError> {
    use std::convert::TryFrom;
    use x509_parser::signature_algorithm::RsaSsaPssParams;

    if alg.algorithm != oid_registry::OID_PKCS1_RSASSAPSS {
        return Err(AttestError::VerificationFailed(format!(
            "certificate uses unsupported signature algorithm: {}",
            alg.algorithm
        )));
    }

    let params = alg.parameters.as_ref().ok_or_else(|| {
        AttestError::VerificationFailed("RSA-PSS signature is missing parameters".to_string())
    })?;
    let params = RsaSsaPssParams::try_from(params).map_err(|_| {
        AttestError::VerificationFailed("invalid RSA-PSS signature parameters".to_string())
    })?;
    let hash_algo = params.hash_algorithm_oid();

    if *hash_algo == oid_registry::OID_NIST_HASH_SHA256 {
        Ok(&ring::signature::RSA_PSS_2048_8192_SHA256)
    } else if *hash_algo == oid_registry::OID_NIST_HASH_SHA384 {
        Ok(&ring::signature::RSA_PSS_2048_8192_SHA384)
    } else if *hash_algo == oid_registry::OID_NIST_HASH_SHA512 {
        Ok(&ring::signature::RSA_PSS_2048_8192_SHA512)
    } else {
        Err(AttestError::VerificationFailed(format!(
            "unsupported RSA-PSS hash algorithm: {hash_algo}"
        )))
    }
}

fn tbs_certificate_der(cert_der: &[u8]) -> Result<&[u8], AttestError> {
    let (_, outer) = asn1_rs::Header::from_der(cert_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse certificate DER header: {e}"))
    })?;
    let outer_len = outer.length().definite().map_err(|e| {
        AttestError::VerificationFailed(format!("invalid certificate DER length: {e}"))
    })?;
    let cert_inner = cert_der.get(cert_der.len() - outer_len..).ok_or_else(|| {
        AttestError::VerificationFailed("certificate DER length is inconsistent".to_string())
    })?;

    let (after_tbs_header, tbs_header) = asn1_rs::Header::from_der(cert_inner).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse TBS DER header: {e}"))
    })?;
    let tbs_content_len = tbs_header
        .length()
        .definite()
        .map_err(|e| AttestError::VerificationFailed(format!("invalid TBS DER length: {e}")))?;
    let tbs_header_len = cert_inner.len() - after_tbs_header.len();
    let total_tbs_len = tbs_header_len + tbs_content_len;

    cert_inner.get(..total_tbs_len).ok_or_else(|| {
        AttestError::VerificationFailed("TBS DER extends past certificate".to_string())
    })
}

fn verify_cert_signed_by_trust_anchor(
    cert_der: &[u8],
    trust_anchor_der: &[u8],
    intermediates: &[rustls_pki_types::CertificateDer<'_>],
    label: &str,
) -> Result<(), AttestError> {
    let cert = rustls_pki_types::CertificateDer::from(cert_der);
    let anchor_cert = rustls_pki_types::CertificateDer::from(trust_anchor_der);
    let anchor = webpki::anchor_from_trusted_cert(&anchor_cert).map_err(|e| {
        AttestError::VerificationFailed(format!(
            "failed to parse {label} issuer as trust anchor: {e}"
        ))
    })?;

    let end_entity = webpki::EndEntityCert::try_from(&cert).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse {label} certificate: {e}"))
    })?;

    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            intermediates,
            rustls_pki_types::UnixTime::now(),
            NoEkuValidator,
            None,
            None,
        )
        .map_err(|e| {
            AttestError::VerificationFailed(format!(
                "{label} certificate signature/path validation failed: {e}"
            ))
        })?;

    Ok(())
}

/// Extract the ECDSA P-384 public key from endorsement certificate bytes (DER or PEM).
fn extract_p384_pubkey_from_der(
    cert_bytes: &[u8],
) -> Result<p384::ecdsa::VerifyingKey, AttestError> {
    use x509_parser::prelude::*;

    // Handle PEM-encoded certs.
    let der_bytes = if cert_bytes.starts_with(b"-----BEGIN") {
        let pem_str = std::str::from_utf8(cert_bytes).map_err(|e| {
            AttestError::VerificationFailed(format!("VCEK/VLEK PEM is not valid UTF-8: {e}"))
        })?;
        let p = ::pem::parse(pem_str).map_err(|e| {
            AttestError::VerificationFailed(format!("failed to parse VCEK/VLEK PEM: {e}"))
        })?;
        std::borrow::Cow::Owned(p.contents().to_vec())
    } else {
        std::borrow::Cow::Borrowed(cert_bytes)
    };

    let (_, cert) = X509Certificate::from_der(&der_bytes).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse VCEK/VLEK X.509 certificate: {e}"))
    })?;

    // The endorsement certificate should use ECDSA with P-384.
    let spki = cert.public_key();
    let key_bytes = &spki.subject_public_key.data;

    // P-384 uncompressed public key is 97 bytes: 0x04 || x (48) || y (48)
    p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
        AttestError::VerificationFailed(format!(
            "VCEK/VLEK public key is not a valid P-384 key ({} bytes): {e}",
            key_bytes.len()
        ))
    })
}

fn verify_vcek_certificate(endorsement_der: &[u8]) -> Result<(), AttestError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(endorsement_der).map_err(|e| {
        AttestError::VerificationFailed(format!("failed to parse VCEK/VLEK X.509 certificate: {e}"))
    })?;

    if !cert.validity().is_valid() {
        return Err(AttestError::VerificationFailed(
            "VCEK/VLEK certificate is not currently valid".to_string(),
        ));
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: AMD KDS URL construction (for future use)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build the URL to fetch the VCEK certificate from AMD's Key Distribution Service.
///
/// Product name is typically "Milan" or "Genoa" for SEV-SNP capable processors.
pub fn vcek_url(product_name: &str, chip_id: &[u8; 64], reported_tcb: u64) -> String {
    let boot_loader = (reported_tcb & 0xFF) as u8;
    let tee = ((reported_tcb >> 8) & 0xFF) as u8;
    let snp = ((reported_tcb >> 48) & 0xFF) as u8;
    let microcode = ((reported_tcb >> 56) & 0xFF) as u8;

    format!(
        "https://kdsintf.amd.com/vcek/v1/{product_name}/\
         {}?blSPL={boot_loader}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={microcode}",
        hex::encode(chip_id)
    )
}

/// Build the URL to fetch the AMD certificate chain (ASK + ARK) for a product.
pub fn cert_chain_url(endorser: &str, product_name: &str) -> String {
    format!("https://kdsintf.amd.com/{endorser}/v1/{product_name}/cert_chain")
}

/// AMD KDS partitions VCEK certificates by CPU product name. The raw report
/// contains chip ID and TCB values, but not a reliable human product string, so
/// the verifier tries known products and accepts only a chain that reaches a
/// pinned AMD ARK and verifies the report signature.
fn candidate_product_names() -> &'static [&'static str] {
    &["Milan", "Genoa", "Turin"]
}

const fn guid_bytes(text: &str) -> [u8; 16] {
    let bytes = text.as_bytes();
    [
        hex_pair(bytes[6], bytes[7]),
        hex_pair(bytes[4], bytes[5]),
        hex_pair(bytes[2], bytes[3]),
        hex_pair(bytes[0], bytes[1]),
        hex_pair(bytes[11], bytes[12]),
        hex_pair(bytes[9], bytes[10]),
        hex_pair(bytes[16], bytes[17]),
        hex_pair(bytes[14], bytes[15]),
        hex_pair(bytes[19], bytes[20]),
        hex_pair(bytes[21], bytes[22]),
        hex_pair(bytes[24], bytes[25]),
        hex_pair(bytes[26], bytes[27]),
        hex_pair(bytes[28], bytes[29]),
        hex_pair(bytes[30], bytes[31]),
        hex_pair(bytes[32], bytes[33]),
        hex_pair(bytes[34], bytes[35]),
    ]
}

const fn hex_pair(hi: u8, lo: u8) -> u8 {
    (hex_nibble(hi) << 4) | hex_nibble(lo)
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
fn cert_table_used_len(certs: &[u8]) -> usize {
    let mut used = 0usize;
    let mut header_end = 0usize;
    for entry in certs.chunks_exact(SNP_CERT_TABLE_ENTRY_SIZE) {
        header_end += SNP_CERT_TABLE_ENTRY_SIZE;
        if entry.iter().all(|&b| b == 0) {
            break;
        }
        let offset = u32::from_le_bytes(entry[16..20].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().unwrap()) as usize;
        if let Some(end) = offset.checked_add(length) {
            used = used.max(end.min(certs.len()));
        }
    }
    if used == 0 {
        0
    } else {
        used.max(header_end)
    }
}

fn find_cert(certs: &[u8], guid: &[u8; 16]) -> Option<Vec<u8>> {
    let mut header_end = 0usize;
    let mut matches = Vec::new();
    for entry in certs.chunks_exact(SNP_CERT_TABLE_ENTRY_SIZE) {
        header_end += SNP_CERT_TABLE_ENTRY_SIZE;
        if entry.iter().all(|&b| b == 0) {
            break;
        }
        if &entry[..16] != guid {
            continue;
        }
        let offset = u32::from_le_bytes(entry[16..20].try_into().ok()?) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().ok()?) as usize;
        let end = offset.checked_add(length)?;
        matches.push((offset, end));
    }

    for (offset, end) in matches {
        if offset < header_end || end > certs.len() {
            continue;
        }
        if let Some(cert) = certs.get(offset..end) {
            return Some(cert.to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_cert_entry(
        table: &mut [u8],
        index: usize,
        guid: &[u8; 16],
        offset: usize,
        len: usize,
    ) {
        let start = index * SNP_CERT_TABLE_ENTRY_SIZE;
        table[start..start + 16].copy_from_slice(guid);
        table[start + 16..start + 20].copy_from_slice(&(offset as u32).to_le_bytes());
        table[start + 20..start + 24].copy_from_slice(&(len as u32).to_le_bytes());
    }

    #[test]
    fn vcek_url_construction() {
        let chip_id = [0xABu8; 64];
        let tcb: u64 = 0x03_00_00_00_00_00_02_01; // microcode=3, snp=0, tee=2, bl=1
        let url = vcek_url("Milan", &chip_id, tcb);
        assert!(url.starts_with("https://kdsintf.amd.com/vcek/v1/Milan/"));
        assert!(url.contains("blSPL=1"));
        assert!(url.contains("teeSPL=2"));
    }

    #[test]
    fn cert_chain_url_supports_vcek_and_vlek() {
        assert_eq!(
            cert_chain_url("vcek", "Milan"),
            "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
        );
        assert_eq!(
            cert_chain_url("vlek", "Milan"),
            "https://kdsintf.amd.com/vlek/v1/Milan/cert_chain"
        );
    }

    #[test]
    fn guid_bytes_match_snp_cert_table_encoding() {
        assert_eq!(
            GUID_VCEK,
            [
                0x8d, 0x75, 0xda, 0x63, 0x64, 0xe6, 0x64, 0x45, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8,
                0xac, 0xcd,
            ]
        );
        assert_eq!(
            GUID_VLEK,
            [
                0xc2, 0x4b, 0x07, 0xa8, 0x5a, 0xa2, 0x3e, 0x48, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0,
                0xb8, 0xa1,
            ]
        );
    }

    #[test]
    fn signing_key_parses_four_byte_signer_info() {
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SIGNING_KEY_OFFSET..SIGNING_KEY_OFFSET + 4].copy_from_slice(&(0u32).to_le_bytes());
        assert_eq!(signing_key(&report).unwrap(), SNP_SIGNING_KEY_VCEK);

        let vlek_info = (SNP_SIGNING_KEY_VLEK as u32) << 2;
        report[SIGNING_KEY_OFFSET..SIGNING_KEY_OFFSET + 4]
            .copy_from_slice(&vlek_info.to_le_bytes());
        assert_eq!(signing_key(&report).unwrap(), SNP_SIGNING_KEY_VLEK);

        let reserved_info = 2u32 << 2;
        report[SIGNING_KEY_OFFSET..SIGNING_KEY_OFFSET + 4]
            .copy_from_slice(&reserved_info.to_le_bytes());
        assert!(signing_key(&report).is_err());

        let unsigned_info = 7u32 << 2;
        report[SIGNING_KEY_OFFSET..SIGNING_KEY_OFFSET + 4]
            .copy_from_slice(&unsigned_info.to_le_bytes());
        assert!(signing_key(&report).is_err());
    }

    #[test]
    fn cert_blob_helpers_find_expected_leaf_and_used_length() {
        let vcek = b"vcek-cert";
        let vlek = b"vlek-cert-longer";
        let header_len = 3 * SNP_CERT_TABLE_ENTRY_SIZE;
        let vcek_offset = header_len;
        let vlek_offset = vcek_offset + vcek.len();
        let mut certs = vec![0u8; vlek_offset + vlek.len() + 8];
        write_cert_entry(&mut certs, 0, &GUID_VCEK, vcek_offset, vcek.len());
        write_cert_entry(&mut certs, 1, &GUID_VLEK, vlek_offset, vlek.len());
        certs[vcek_offset..vcek_offset + vcek.len()].copy_from_slice(vcek);
        certs[vlek_offset..vlek_offset + vlek.len()].copy_from_slice(vlek);

        assert_eq!(find_cert(&certs, &GUID_VCEK).unwrap(), vcek);
        assert_eq!(find_cert(&certs, &GUID_VLEK).unwrap(), vlek);
        assert_eq!(cert_table_used_len(&certs), vlek_offset + vlek.len());
    }

    #[test]
    fn evidence_data_splits_report_and_certificate_blob() {
        let mut data = vec![0u8; SNP_REPORT_SIZE];
        data.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(report_bytes(&data).unwrap().len(), SNP_REPORT_SIZE);
        assert_eq!(cert_blob_bytes(&data), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn verifier_rejects_wrong_tee_type() {
        let verifier = SevSnpVerifier;
        let evidence = Evidence {
            tee_type: TeeType::Mock,
            data: vec![0; SNP_REPORT_SIZE],
        };
        let result = verifier.verify(&evidence, None);
        assert!(matches!(result, Err(AttestError::UnsupportedTeeType(_))));
    }

    #[test]
    fn verifier_rejects_short_report() {
        let verifier = SevSnpVerifier;
        let evidence = Evidence {
            tee_type: TeeType::SevSnp,
            data: vec![0; 100], // too short
        };
        let result = verifier.verify(&evidence, None);
        assert!(result.is_err());
    }

    #[test]
    fn verifier_rejects_all_zero_signature() {
        // A report with all-zero signature must be rejected — this is the key
        // security check that prevents accepting unsigned/dummy reports.
        let verifier = SevSnpVerifier;

        let mut report = vec![0u8; SNP_REPORT_SIZE];
        let expected_data = [0x42u8; 64];
        report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64].copy_from_slice(&expected_data);

        let evidence = Evidence {
            tee_type: TeeType::SevSnp,
            data: report,
        };

        let result = verifier.verify(&evidence, None);
        assert!(result.is_err(), "should reject all-zero signature");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("all-zero signature"),
            "error should mention all-zero signature, got: {err_msg}"
        );
    }

    #[test]
    fn verifier_rejects_debug_guest_policy() {
        let verifier = SevSnpVerifier;

        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[POLICY_OFFSET..POLICY_OFFSET + 8]
            .copy_from_slice(&POLICY_DEBUG_ALLOWED_BIT.to_le_bytes());

        let evidence = Evidence {
            tee_type: TeeType::SevSnp,
            data: report,
        };

        let result = verifier.verify(&evidence, None);
        assert!(result.is_err(), "should reject debug-enabled guest policy");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("debug"),
            "error should mention debug policy, got: {err_msg}"
        );
    }

    #[test]
    fn verifier_checks_measurement_before_signature() {
        // Measurement check happens before signature verification,
        // so a wrong measurement should fail even with a dummy signature.
        let verifier = SevSnpVerifier;

        let mut report = vec![0u8; SNP_REPORT_SIZE];
        let measurement = [0xAA; MEASUREMENT_LEN];
        report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN]
            .copy_from_slice(&measurement);

        let evidence = Evidence {
            tee_type: TeeType::SevSnp,
            data: report,
        };

        // Wrong measurement: should fail before reaching signature check.
        let wrong = [0xBB; MEASUREMENT_LEN];
        let result = verifier.verify(&evidence, Some(&wrong));
        assert!(matches!(
            result,
            Err(AttestError::MeasurementMismatch { .. })
        ));
    }

    #[test]
    fn candidate_products_are_known() {
        assert_eq!(candidate_product_names(), &["Milan", "Genoa", "Turin"]);
    }
}
