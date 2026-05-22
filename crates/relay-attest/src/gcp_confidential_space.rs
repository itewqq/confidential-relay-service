//! Google Cloud Confidential Space attestation backend.
//!
//! Confidential Space exposes workload attestation as OIDC/PKI JWTs from the
//! launcher over `/run/container_launcher/teeserver.sock`.  We request an OIDC
//! token with a custom audience and two nonces that encode the 64-byte attested
//! TLS binding.  The verifier validates Google's OIDC signature chain, expiry,
//! audience, nonce, debug status, service account, and workload container image
//! digest/signature policy.

use std::collections::{HashMap, HashSet};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::traits::{Attester, Verifier};
use crate::types::{AttestError, Evidence, TeeType};

const DEFAULT_SOCKET_PATH: &str = "/run/container_launcher/teeserver.sock";
const TOKEN_URL_PATH: &str = "/v1/token";
const DEFAULT_ISSUER: &str = "https://confidentialcomputing.googleapis.com";
const DEFAULT_WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";
const DEFAULT_AUDIENCE: &str = "trusted-relay-attested-tls";
const DEFAULT_TOKEN_TYPE: &str = "OIDC";
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(30 * 60);
const NONCE_SPKI_PREFIX: &str = "trr1s.";
const NONCE_CONFIG_PREFIX: &str = "trr1c.";
const MAX_CLOCK_SKEW_SECS: u64 = 300;
const SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const SOCKET_WAIT_INTERVAL: Duration = Duration::from_millis(250);

/// Confidential Space attester configuration.
#[derive(Debug, Clone)]
pub struct GcpConfidentialSpaceAttester {
    audience: String,
    socket_path: String,
    token_type: String,
}

impl GcpConfidentialSpaceAttester {
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            token_type: DEFAULT_TOKEN_TYPE.to_string(),
        }
    }

    pub fn from_env() -> Self {
        let audience = std::env::var("TRUSTED_RELAY_GCP_CS_AUDIENCE")
            .unwrap_or_else(|_| DEFAULT_AUDIENCE.to_string());
        let socket_path = std::env::var("TRUSTED_RELAY_GCP_CS_SOCKET")
            .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
        Self {
            audience,
            socket_path,
            token_type: DEFAULT_TOKEN_TYPE.to_string(),
        }
    }

    pub fn with_socket_path(mut self, socket_path: impl Into<String>) -> Self {
        self.socket_path = socket_path.into();
        self
    }

    pub fn with_token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = token_type.into();
        self
    }
}

impl Default for GcpConfidentialSpaceAttester {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Attester for GcpConfidentialSpaceAttester {
    fn name(&self) -> &'static str {
        "GCP Confidential Space"
    }

    fn attest(&self, user_data: &[u8; 64]) -> Result<Evidence, AttestError> {
        let nonce = reportdata_nonces(user_data);
        let request = TokenRequest {
            audience: &self.audience,
            token_type: &self.token_type,
            nonces: nonce.iter().map(String::as_str).collect(),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|e| AttestError::GenerationFailed(format!("token request JSON: {e}")))?;
        let token = request_token_over_unix_socket(&self.socket_path, &body)?;
        Ok(Evidence {
            tee_type: TeeType::GcpConfidentialSpace,
            data: token,
        })
    }
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    audience: &'a str,
    token_type: &'a str,
    nonces: Vec<&'a str>,
}

fn request_token_over_unix_socket(socket_path: &str, body: &[u8]) -> Result<Vec<u8>, AttestError> {
    let stream = connect_launcher_socket(socket_path, SOCKET_WAIT_TIMEOUT)?;
    request_token_over_stream(stream, body)
}

pub fn can_connect_launcher_socket(socket_path: &str) -> bool {
    UnixStream::connect(socket_path).is_ok()
}

fn connect_launcher_socket(
    socket_path: &str,
    timeout: Duration,
) -> Result<UnixStream, AttestError> {
    let start = Instant::now();
    let mut last_error = None;
    while start.elapsed() <= timeout {
        match UnixStream::connect(socket_path) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = Some(e);
                std::thread::sleep(SOCKET_WAIT_INTERVAL);
            }
        }
    }
    let error = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "socket did not appear".to_string());
    Err(AttestError::GenerationFailed(format!(
        "connect Confidential Space launcher socket {socket_path} within {timeout:?}: {error}"
    )))
}

fn request_token_over_stream(mut stream: UnixStream, body: &[u8]) -> Result<Vec<u8>, AttestError> {
    use std::io::{Read, Write};

    let request = format!(
        "POST {TOKEN_URL_PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| AttestError::GenerationFailed(format!("write token request headers: {e}")))?;
    stream
        .write_all(body)
        .map_err(|e| AttestError::GenerationFailed(format!("write token request body: {e}")))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| AttestError::GenerationFailed(format!("read token response: {e}")))?;
    parse_http_token_response(&response)
}

fn parse_http_token_response(response: &[u8]) -> Result<Vec<u8>, AttestError> {
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .ok_or_else(|| {
            AttestError::GenerationFailed("launcher token response lacks HTTP headers".to_string())
        })?;
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        AttestError::GenerationFailed(format!("launcher token response headers not UTF-8: {e}"))
    })?;
    let status = headers.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        let body = String::from_utf8_lossy(&response[header_end..]);
        return Err(AttestError::GenerationFailed(format!(
            "launcher token request failed: {status}: {body}"
        )));
    }
    let is_chunked = headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = if is_chunked {
        decode_chunked_body(&response[header_end..])?
    } else {
        response[header_end..].to_vec()
    };
    let body = trim_ascii(&body);
    if body.is_empty() {
        return Err(AttestError::GenerationFailed(
            "launcher returned an empty token".to_string(),
        ));
    }
    Ok(body.to_vec())
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, AttestError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let line_end = body[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|idx| pos + idx)
            .ok_or_else(|| {
                AttestError::GenerationFailed(
                    "chunked launcher token response has unterminated chunk header".to_string(),
                )
            })?;
        let size_line = std::str::from_utf8(&body[pos..line_end]).map_err(|e| {
            AttestError::GenerationFailed(format!(
                "chunked launcher token response chunk header is not UTF-8: {e}"
            ))
        })?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|e| {
            AttestError::GenerationFailed(format!(
                "chunked launcher token response has invalid chunk size '{size_hex}': {e}"
            ))
        })?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let chunk_end = pos.checked_add(size).ok_or_else(|| {
            AttestError::GenerationFailed(
                "chunked launcher token response chunk size overflow".to_string(),
            )
        })?;
        if body.len() < chunk_end + 2 || &body[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err(AttestError::GenerationFailed(
                "chunked launcher token response chunk is truncated".to_string(),
            ));
        }
        out.extend_from_slice(&body[pos..chunk_end]);
        pos = chunk_end + 2;
    }
    Ok(out)
}

/// Verifier policy for Confidential Space.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GcpConfidentialSpacePolicy {
    /// Expected custom audience. Defaults to `trusted-relay-attested-tls`.
    pub audience: String,
    /// Expected workload container digest, for example `sha256:...`.
    pub image_digest: Option<String>,
    /// Optional expected container image reference.
    pub image_reference: Option<String>,
    /// Optional expected container signature key IDs. At least one token
    /// signature key ID must match one configured key ID.
    #[serde(default)]
    pub signature_key_ids: Vec<String>,
    /// Optional expected Google service account email.
    pub service_account: Option<String>,
    /// Optional expected GCP project ID.
    pub project_id: Option<String>,
    /// Optional expected zone.
    pub zone: Option<String>,
    /// Optional expected VM instance name.
    pub instance_name: Option<String>,
    /// Require production Confidential Space debug status.
    #[serde(default = "default_require_debug_disabled")]
    pub require_debug_disabled: bool,
    /// Require `swname == CONFIDENTIAL_SPACE`.
    #[serde(default = "default_require_confidential_space")]
    pub require_confidential_space: bool,
    /// Require secure boot claim to be true when present.
    #[serde(default = "default_require_secure_boot")]
    pub require_secure_boot: bool,
    /// OIDC issuer. Defaults to Google's Confidential Computing issuer.
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// Optional JWKS URI override, mostly for offline tests.
    pub jwks_uri: Option<String>,
}

fn default_require_debug_disabled() -> bool {
    true
}

fn default_require_confidential_space() -> bool {
    true
}

fn default_require_secure_boot() -> bool {
    true
}

fn default_issuer() -> String {
    DEFAULT_ISSUER.to_string()
}

impl GcpConfidentialSpacePolicy {
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            require_debug_disabled: true,
            require_confidential_space: true,
            require_secure_boot: true,
            issuer: DEFAULT_ISSUER.to_string(),
            ..Default::default()
        }
    }

    pub fn from_env() -> Self {
        let mut policy = Self::new(
            std::env::var("TRUSTED_RELAY_GCP_CS_AUDIENCE")
                .unwrap_or_else(|_| DEFAULT_AUDIENCE.to_string()),
        );
        policy.image_digest = std::env::var("TRUSTED_RELAY_GCP_CS_IMAGE_DIGEST").ok();
        policy.image_reference = std::env::var("TRUSTED_RELAY_GCP_CS_IMAGE_REFERENCE").ok();
        policy.signature_key_ids = split_env("TRUSTED_RELAY_GCP_CS_SIGNATURE_KEY_ID");
        policy.service_account = std::env::var("TRUSTED_RELAY_GCP_CS_SERVICE_ACCOUNT").ok();
        policy.project_id = std::env::var("TRUSTED_RELAY_GCP_CS_PROJECT_ID").ok();
        policy.zone = std::env::var("TRUSTED_RELAY_GCP_CS_ZONE").ok();
        policy.instance_name = std::env::var("TRUSTED_RELAY_GCP_CS_INSTANCE_NAME").ok();
        policy.jwks_uri = std::env::var("TRUSTED_RELAY_GCP_CS_JWKS_URI").ok();
        policy
    }

    pub fn strict_for_image(audience: impl Into<String>, image_digest: impl Into<String>) -> Self {
        let mut policy = Self::new(audience);
        policy.image_digest = Some(normalize_digest(image_digest.into().as_str()));
        policy
    }

    pub fn validate(&self) -> Result<(), AttestError> {
        if self.audience.trim().is_empty() {
            return Err(AttestError::VerificationFailed(
                "Confidential Space audience must not be empty".to_string(),
            ));
        }
        if self.image_digest.is_none() && self.signature_key_ids.is_empty() {
            return Err(AttestError::VerificationFailed(
                "Confidential Space policy must pin --gcp-cs-image-digest or --gcp-cs-signature-key-id".to_string(),
            ));
        }
        if let Some(digest) = &self.image_digest {
            validate_image_digest(digest)?;
        }
        Ok(())
    }
}

fn split_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .into_iter()
        .flat_map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Confidential Space verifier.  For production, use [`Self::new`] so a
/// workload-image digest or signature key is enforced.  [`Self::new_audit`] is
/// for diagnostics and intentionally does not pin workload identity.
#[derive(Debug, Clone)]
pub struct GcpConfidentialSpaceVerifier {
    policy: GcpConfidentialSpacePolicy,
    jwks: Arc<dyn JwksProvider>,
    enforce_workload_identity: bool,
}

impl GcpConfidentialSpaceVerifier {
    pub fn new(policy: GcpConfidentialSpacePolicy) -> Result<Self, AttestError> {
        policy.validate()?;
        Ok(Self {
            policy,
            jwks: Arc::new(HttpJwksProvider),
            enforce_workload_identity: true,
        })
    }

    pub fn new_audit(policy: GcpConfidentialSpacePolicy) -> Self {
        Self {
            policy,
            jwks: Arc::new(HttpJwksProvider),
            enforce_workload_identity: false,
        }
    }

    pub fn with_static_jwks(
        policy: GcpConfidentialSpacePolicy,
        jwks: JwksSet,
    ) -> Result<Self, AttestError> {
        policy.validate()?;
        Ok(Self {
            policy,
            jwks: Arc::new(StaticJwksProvider { jwks }),
            enforce_workload_identity: true,
        })
    }

    pub fn policy(&self) -> &GcpConfidentialSpacePolicy {
        &self.policy
    }
}

impl Verifier for GcpConfidentialSpaceVerifier {
    fn verify(
        &self,
        evidence: &Evidence,
        expected_measurement: Option<&[u8]>,
    ) -> Result<[u8; 64], AttestError> {
        if evidence.tee_type != TeeType::GcpConfidentialSpace {
            return Err(AttestError::UnsupportedTeeType(evidence.tee_type));
        }

        if self.enforce_workload_identity {
            self.policy.validate()?;
        }

        let expected_reportdata = expected_measurement
            .map(|bytes| bytes.try_into())
            .transpose()
            .map_err(|_| {
                AttestError::VerificationFailed(format!(
                    "Confidential Space verifier expected a 64-byte nonce/reportdata, got {} bytes",
                    expected_measurement.map_or(0, <[u8]>::len)
                ))
            })?;

        let token = std::str::from_utf8(&evidence.data).map_err(|e| {
            AttestError::VerificationFailed(format!("Confidential Space token is not UTF-8: {e}"))
        })?;
        let claims = self.decode_and_validate(token)?;
        self.verify_claims(&claims, expected_reportdata)
    }
}

impl GcpConfidentialSpaceVerifier {
    fn decode_and_validate(&self, token: &str) -> Result<ConfidentialSpaceClaims, AttestError> {
        let header = decode_header(token).map_err(|e| {
            AttestError::VerificationFailed(format!("invalid Confidential Space JWT header: {e}"))
        })?;
        if header.alg != Algorithm::RS256 {
            return Err(AttestError::VerificationFailed(format!(
                "Confidential Space token alg must be RS256, got {:?}",
                header.alg
            )));
        }
        let kid = header.kid.ok_or_else(|| {
            AttestError::VerificationFailed("Confidential Space token lacks kid".to_string())
        })?;

        let jwks_uri = match &self.policy.jwks_uri {
            Some(uri) => uri.clone(),
            None => fetch_well_known(&self.policy.issuer)?.jwks_uri,
        };
        let jwks = self.jwks.jwks(&jwks_uri)?;
        let jwk = jwks.keys.iter().find(|jwk| jwk.kid == kid).ok_or_else(|| {
            AttestError::VerificationFailed(format!(
                "Confidential Space JWKS does not contain kid {kid}"
            ))
        })?;
        if jwk.alg.as_deref().is_some_and(|alg| alg != "RS256") {
            return Err(AttestError::VerificationFailed(format!(
                "Confidential Space JWK alg must be RS256, got {}",
                jwk.alg.as_deref().unwrap_or_default()
            )));
        }
        if jwk.kty != "RSA" {
            return Err(AttestError::VerificationFailed(format!(
                "Confidential Space JWK kty must be RSA, got {}",
                jwk.kty
            )));
        }

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            AttestError::VerificationFailed(format!("invalid Confidential Space RSA JWK: {e}"))
        })?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.policy.issuer.as_str()]);
        validation.set_audience(&[self.policy.audience.as_str()]);
        validation.leeway = MAX_CLOCK_SKEW_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss"]);
        decode::<ConfidentialSpaceClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                AttestError::VerificationFailed(format!(
                    "Confidential Space JWT validation failed: {e}"
                ))
            })
    }

    fn verify_claims(
        &self,
        claims: &ConfidentialSpaceClaims,
        expected_reportdata: Option<[u8; 64]>,
    ) -> Result<[u8; 64], AttestError> {
        let now = now_secs()?;
        if claims.iat > now + MAX_CLOCK_SKEW_SECS {
            return Err(AttestError::VerificationFailed(format!(
                "Confidential Space token iat is in the future: {} > {now}",
                claims.iat
            )));
        }
        if self.policy.require_confidential_space && claims.swname != "CONFIDENTIAL_SPACE" {
            return Err(AttestError::VerificationFailed(format!(
                "Confidential Space swname mismatch: expected CONFIDENTIAL_SPACE, got {}",
                claims.swname
            )));
        }
        if self.policy.require_debug_disabled && claims.dbgstat != "disabled-since-boot" {
            return Err(AttestError::VerificationFailed(format!(
                "Confidential Space debug status is not production-safe: {}",
                claims.dbgstat
            )));
        }
        if self.policy.require_secure_boot && !claims.secboot {
            return Err(AttestError::VerificationFailed(
                "Confidential Space token reports secboot=false".to_string(),
            ));
        }

        if let Some(expected_sa) = &self.policy.service_account {
            if !claims
                .google_service_accounts
                .iter()
                .any(|sa| sa == expected_sa)
            {
                return Err(AttestError::VerificationFailed(format!(
                    "Confidential Space service account mismatch: expected {expected_sa}, got {:?}",
                    claims.google_service_accounts
                )));
            }
        }

        if let Some(expected) = &self.policy.project_id {
            let actual = claims
                .submods
                .gce
                .as_ref()
                .and_then(|gce| gce.project_id.as_ref());
            if actual != Some(expected) {
                return Err(AttestError::VerificationFailed(format!(
                    "Confidential Space project_id mismatch: expected {expected}, got {:?}",
                    actual
                )));
            }
        }
        if let Some(expected) = &self.policy.zone {
            let actual = claims
                .submods
                .gce
                .as_ref()
                .and_then(|gce| gce.zone.as_ref());
            if actual != Some(expected) {
                return Err(AttestError::VerificationFailed(format!(
                    "Confidential Space zone mismatch: expected {expected}, got {:?}",
                    actual
                )));
            }
        }
        if let Some(expected) = &self.policy.instance_name {
            let actual = claims
                .submods
                .gce
                .as_ref()
                .and_then(|gce| gce.instance_name.as_ref());
            if actual != Some(expected) {
                return Err(AttestError::VerificationFailed(format!(
                    "Confidential Space instance_name mismatch: expected {expected}, got {:?}",
                    actual
                )));
            }
        }

        let container = claims.submods.container.as_ref().ok_or_else(|| {
            AttestError::VerificationFailed(
                "Confidential Space token lacks submods.container claims".to_string(),
            )
        })?;
        if self.enforce_workload_identity {
            if let Some(expected) = &self.policy.image_digest {
                let expected = normalize_digest(expected);
                let actual = container
                    .image_digest
                    .as_deref()
                    .map(normalize_digest)
                    .ok_or_else(|| {
                        AttestError::VerificationFailed(
                            "Confidential Space token lacks container.image_digest".to_string(),
                        )
                    })?;
                if actual != expected {
                    return Err(AttestError::MeasurementMismatch { expected, actual });
                }
            }
            if let Some(expected) = &self.policy.image_reference {
                if container.image_reference.as_ref() != Some(expected) {
                    return Err(AttestError::VerificationFailed(format!(
                        "Confidential Space image_reference mismatch: expected {expected}, got {:?}",
                        container.image_reference
                    )));
                }
            }
            if !self.policy.signature_key_ids.is_empty() {
                let expected: HashSet<&str> = self
                    .policy
                    .signature_key_ids
                    .iter()
                    .map(String::as_str)
                    .collect();
                let matched = container
                    .image_signatures
                    .iter()
                    .flatten()
                    .any(|signature| expected.contains(signature.key_id.as_str()));
                if !matched {
                    return Err(AttestError::VerificationFailed(format!(
                        "Confidential Space container image signature key mismatch: expected one of {:?}",
                        self.policy.signature_key_ids
                    )));
                }
            }
        }

        let reportdata = nonce_reportdata(&claims.eat_nonce)?;
        if let Some(expected) = expected_reportdata {
            if reportdata != expected {
                return Err(AttestError::ReportDataMismatch);
            }
        }
        Ok(reportdata)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct ConfidentialSpaceClaims {
    aud: String,
    dbgstat: String,
    eat_nonce: NonceClaim,
    exp: u64,
    #[serde(default)]
    google_service_accounts: Vec<String>,
    iat: u64,
    iss: String,
    nbf: u64,
    #[serde(default)]
    secboot: bool,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    submods: SubmodsClaims,
    swname: String,
    #[serde(default)]
    swversion: Vec<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
struct SubmodsClaims {
    #[serde(default)]
    container: Option<ContainerClaims>,
    #[serde(default)]
    gce: Option<GceClaims>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
struct ContainerClaims {
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    env_override: HashMap<String, String>,
    #[serde(default)]
    image_digest: Option<String>,
    #[serde(default)]
    image_id: Option<String>,
    #[serde(default)]
    image_reference: Option<String>,
    #[serde(default)]
    image_signatures: Option<Vec<ImageSignatureClaim>>,
    #[serde(default)]
    restart_policy: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
struct ImageSignatureClaim {
    key_id: String,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
struct GceClaims {
    #[serde(default)]
    instance_id: Option<String>,
    #[serde(default)]
    instance_name: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    project_number: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum NonceClaim {
    One(String),
    Many(Vec<String>),
}

fn nonce_reportdata(nonce_claim: &NonceClaim) -> Result<[u8; 64], AttestError> {
    let nonces: Vec<&str> = match nonce_claim {
        NonceClaim::One(nonce) => nonce.split(',').collect(),
        NonceClaim::Many(nonces) => nonces.iter().map(String::as_str).collect(),
    };

    let mut spki = None;
    let mut config = None;
    for nonce in nonces {
        if let Some(encoded) = nonce.strip_prefix(NONCE_SPKI_PREFIX) {
            spki = Some(decode_nonce_part(encoded, 48, "SPKI")?);
        } else if let Some(encoded) = nonce.strip_prefix(NONCE_CONFIG_PREFIX) {
            config = Some(decode_nonce_part(encoded, 16, "config")?);
        }
    }

    let spki = spki.ok_or_else(|| {
        AttestError::VerificationFailed(
            "Confidential Space token lacks trusted-relay SPKI nonce".to_string(),
        )
    })?;
    let config = config.ok_or_else(|| {
        AttestError::VerificationFailed(
            "Confidential Space token lacks trusted-relay config nonce".to_string(),
        )
    })?;

    let mut reportdata = [0u8; 64];
    reportdata[..48].copy_from_slice(&spki);
    reportdata[48..64].copy_from_slice(&config);
    Ok(reportdata)
}

fn decode_nonce_part(encoded: &str, len: usize, label: &str) -> Result<Vec<u8>, AttestError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| {
            AttestError::VerificationFailed(format!(
                "Confidential Space {label} nonce is not base64url: {e}"
            ))
        })?;
    if bytes.len() != len {
        return Err(AttestError::VerificationFailed(format!(
            "Confidential Space {label} nonce decoded to {} bytes, expected {len}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub fn reportdata_nonces(reportdata: &[u8; 64]) -> [String; 2] {
    [
        format!(
            "{NONCE_SPKI_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&reportdata[..48])
        ),
        format!(
            "{NONCE_CONFIG_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&reportdata[48..64])
        ),
    ]
}

pub fn reportdata_nonce(reportdata: &[u8; 64]) -> String {
    reportdata_nonces(reportdata).join(",")
}

fn normalize_digest(raw: &str) -> String {
    let clean = raw.trim().to_ascii_lowercase();
    if clean.starts_with("sha256:") {
        clean
    } else {
        format!("sha256:{clean}")
    }
}

fn validate_image_digest(raw: &str) -> Result<(), AttestError> {
    let digest = normalize_digest(raw);
    let hex = digest.trim_start_matches("sha256:");
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AttestError::VerificationFailed(format!(
            "Confidential Space image digest must be sha256:<64 hex>, got {raw}"
        )));
    }
    Ok(())
}

fn now_secs() -> Result<u64, AttestError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| AttestError::VerificationFailed(format!("system clock before epoch: {e}")))
}

#[derive(Debug, Clone, Deserialize)]
struct WellKnown {
    jwks_uri: String,
}

fn fetch_well_known(issuer: &str) -> Result<WellKnown, AttestError> {
    let url = format!(
        "{}{}",
        issuer.trim_end_matches('/'),
        DEFAULT_WELL_KNOWN_PATH
    );
    fetch_json_cached(&url, DEFAULT_JWKS_TTL)
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwksSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub e: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    #[serde(rename = "use")]
    pub key_use: Option<String>,
}

trait JwksProvider: Send + Sync + std::fmt::Debug {
    fn jwks(&self, jwks_uri: &str) -> Result<JwksSet, AttestError>;
}

#[derive(Debug)]
struct HttpJwksProvider;

impl JwksProvider for HttpJwksProvider {
    fn jwks(&self, jwks_uri: &str) -> Result<JwksSet, AttestError> {
        fetch_json_cached(jwks_uri, DEFAULT_JWKS_TTL)
    }
}

#[derive(Debug)]
struct StaticJwksProvider {
    jwks: JwksSet,
}

impl JwksProvider for StaticJwksProvider {
    fn jwks(&self, _jwks_uri: &str) -> Result<JwksSet, AttestError> {
        Ok(self.jwks.clone())
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    fetched_at: Instant,
    body: Value,
}

static JSON_CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();

fn fetch_json_cached<T>(url: &str, ttl: Duration) -> Result<T, AttestError>
where
    T: for<'de> Deserialize<'de>,
{
    let cache = JSON_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(value) = cache
        .lock()
        .map_err(|_| AttestError::VerificationFailed("JSON cache poisoned".to_string()))?
        .get(url)
        .filter(|entry| entry.fetched_at.elapsed() < ttl)
        .map(|entry| entry.body.clone())
    {
        return serde_json::from_value(value).map_err(|e| {
            AttestError::VerificationFailed(format!("cached JSON from {url} is invalid: {e}"))
        });
    }

    let body = fetch_url_text(url)?;
    let value: Value = serde_json::from_str(&body).map_err(|e| {
        AttestError::VerificationFailed(format!("JSON response from {url} is invalid: {e}"))
    })?;
    cache
        .lock()
        .map_err(|_| AttestError::VerificationFailed("JSON cache poisoned".to_string()))?
        .insert(
            url.to_string(),
            CacheEntry {
                fetched_at: Instant::now(),
                body: value.clone(),
            },
        );
    serde_json::from_value(value).map_err(|e| {
        AttestError::VerificationFailed(format!("JSON response from {url} has wrong shape: {e}"))
    })
}

fn fetch_url_text(url: &str) -> Result<String, AttestError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                tokio::task::block_in_place(|| handle.block_on(fetch_url_text_async(url)))
            } else {
                let url = url.to_string();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            AttestError::VerificationFailed(format!(
                                "failed to create runtime for JWKS fetch: {e}"
                            ))
                        })?;
                    rt.block_on(fetch_url_text_async(&url))
                })
                .join()
                .map_err(|_| {
                    AttestError::VerificationFailed("JWKS fetch thread panicked".to_string())
                })?
            }
        }
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    AttestError::VerificationFailed(format!(
                        "failed to create runtime for JWKS fetch: {e}"
                    ))
                })?;
            rt.block_on(fetch_url_text_async(url))
        }
    }
}

async fn fetch_url_text_async(url: &str) -> Result<String, AttestError> {
    let parsed = url::Url::parse(url).map_err(|e| {
        AttestError::VerificationFailed(format!("invalid Confidential Space metadata URL: {e}"))
    })?;
    if parsed.scheme() != "https" {
        return Err(AttestError::VerificationFailed(format!(
            "Confidential Space metadata URL must be https: {url}"
        )));
    }
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AttestError::VerificationFailed(format!("HTTP client build: {e}")))?
        .get(url)
        .send()
        .await
        .map_err(|e| AttestError::VerificationFailed(format!("failed to fetch {url}: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(AttestError::VerificationFailed(format!(
            "fetch {url} returned {status}"
        )));
    }
    response
        .text()
        .await
        .map_err(|e| AttestError::VerificationFailed(format!("read {url}: {e}")))
}

#[allow(dead_code)]
fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    struct TestSigningKey {
        der: Vec<u8>,
        n: String,
        e: String,
    }

    fn test_signing_key() -> TestSigningKey {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPrivateKey;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.as_ref();
        let der = private_key.to_pkcs1_der().unwrap();
        TestSigningKey {
            der: der.as_bytes().to_vec(),
            n: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public_key.n().to_bytes_be()),
            e: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public_key.e().to_bytes_be()),
        }
    }

    fn jwks(key: &TestSigningKey) -> JwksSet {
        JwksSet {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: "test-kid".to_string(),
                n: key.n.clone(),
                e: key.e.clone(),
                alg: Some("RS256".to_string()),
                key_use: None,
            }],
        }
    }

    fn policy() -> GcpConfidentialSpacePolicy {
        let mut policy = GcpConfidentialSpacePolicy::strict_for_image(
            "trusted-relay-test",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        policy.issuer = "https://issuer.test".to_string();
        policy.jwks_uri = Some("https://issuer.test/jwks".to_string());
        policy.service_account = Some("relay@project.iam.gserviceaccount.com".to_string());
        policy.project_id = Some("project".to_string());
        policy.zone = Some("us-central1-a".to_string());
        policy
    }

    fn token(
        key: &TestSigningKey,
        reportdata: &[u8; 64],
        mutate: impl FnOnce(&mut Value),
    ) -> String {
        let now = now_secs().unwrap();
        let nonces = reportdata_nonces(reportdata);
        let mut claims = json!({
            "aud": "trusted-relay-test",
            "dbgstat": "disabled-since-boot",
            "eat_nonce": nonces,
            "exp": now + 3600,
            "google_service_accounts": ["relay@project.iam.gserviceaccount.com"],
            "iat": now,
            "iss": "https://issuer.test",
            "nbf": now.saturating_sub(5),
            "secboot": true,
            "sub": "https://www.googleapis.com/compute/v1/projects/project/zones/us-central1-a/instances/relay",
            "swname": "CONFIDENTIAL_SPACE",
            "swversion": ["260500"],
            "submods": {
                "container": {
                    "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "image_reference": "us-docker.pkg.dev/project/repo/relay:latest",
                    "image_signatures": [{"key_id": "key-1", "signature": "abc", "signature_algorithm": "RSASSA_PSS_SHA256"}],
                    "restart_policy": "Never"
                },
                "gce": {
                    "project_id": "project",
                    "zone": "us-central1-a",
                    "instance_name": "relay"
                }
            }
        });
        mutate(&mut claims);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());
        encode(&header, &claims, &EncodingKey::from_rsa_der(&key.der)).unwrap()
    }

    fn verify_token(
        key: &TestSigningKey,
        token: String,
        reportdata: &[u8; 64],
    ) -> Result<[u8; 64], AttestError> {
        let verifier = GcpConfidentialSpaceVerifier::with_static_jwks(policy(), jwks(key)).unwrap();
        verifier.verify(
            &Evidence {
                tee_type: TeeType::GcpConfidentialSpace,
                data: token.into_bytes(),
            },
            Some(reportdata),
        )
    }

    #[test]
    fn reportdata_nonce_round_trips() {
        let reportdata = [7u8; 64];
        let nonce = NonceClaim::Many(reportdata_nonces(&reportdata).to_vec());
        assert_eq!(nonce_reportdata(&nonce).unwrap(), reportdata);
    }

    #[test]
    fn parses_chunked_token_response() {
        let token = b"abc.def.ghi";
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc.\r\n7\r\ndef.ghi\r\n0\r\n\r\n";
        assert_eq!(parse_http_token_response(response).unwrap(), token);
    }

    #[test]
    fn accepts_matching_token() {
        let reportdata = [1u8; 64];
        let key = test_signing_key();
        let result = verify_token(&key, token(&key, &reportdata, |_| {}), &reportdata).unwrap();
        assert_eq!(result, reportdata);
    }

    #[test]
    fn rejects_changed_image_digest() {
        let reportdata = [1u8; 64];
        let key = test_signing_key();
        let tok = token(&key, &reportdata, |claims| {
            claims["submods"]["container"]["image_digest"] = Value::String(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            );
        });
        let err = verify_token(&key, tok, &reportdata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("measurement mismatch"), "{err}");
    }

    #[test]
    fn rejects_wrong_nonce() {
        let reportdata = [1u8; 64];
        let wrong = [2u8; 64];
        let key = test_signing_key();
        let err = verify_token(&key, token(&key, &wrong, |_| {}), &reportdata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("REPORTDATA mismatch"), "{err}");
    }

    #[test]
    fn rejects_debug_image() {
        let reportdata = [1u8; 64];
        let key = test_signing_key();
        let tok = token(&key, &reportdata, |claims| {
            claims["dbgstat"] = Value::String("enabled".to_string());
        });
        let err = verify_token(&key, tok, &reportdata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("debug status"), "{err}");
    }

    #[test]
    fn rejects_wrong_audience() {
        let reportdata = [1u8; 64];
        let key = test_signing_key();
        let tok = token(&key, &reportdata, |claims| {
            claims["aud"] = Value::String("wrong".to_string());
        });
        let err = verify_token(&key, tok, &reportdata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("JWT validation failed"), "{err}");
    }

    #[test]
    fn rejects_wrong_service_account() {
        let reportdata = [1u8; 64];
        let key = test_signing_key();
        let tok = token(&key, &reportdata, |claims| {
            claims["google_service_accounts"] = json!(["other@project.iam.gserviceaccount.com"]);
        });
        let err = verify_token(&key, tok, &reportdata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("service account mismatch"), "{err}");
    }

    #[test]
    fn rejects_expired_token() {
        let reportdata = [1u8; 64];
        let key = test_signing_key();
        let tok = token(&key, &reportdata, |claims| {
            claims["exp"] = json!(now_secs().unwrap() - 1000);
        });
        let err = verify_token(&key, tok, &reportdata)
            .unwrap_err()
            .to_string();
        assert!(err.contains("JWT validation failed"), "{err}");
    }

    #[test]
    fn can_pin_signature_key_instead_of_digest() {
        let reportdata = [1u8; 64];
        let mut policy = GcpConfidentialSpacePolicy::new("trusted-relay-test");
        policy.issuer = "https://issuer.test".to_string();
        policy.jwks_uri = Some("https://issuer.test/jwks".to_string());
        policy.signature_key_ids = vec!["key-1".to_string()];
        let key = test_signing_key();
        let verifier = GcpConfidentialSpaceVerifier::with_static_jwks(policy, jwks(&key)).unwrap();
        let tok = token(&key, &reportdata, |_| {});
        assert!(verifier
            .verify(
                &Evidence {
                    tee_type: TeeType::GcpConfidentialSpace,
                    data: tok.into_bytes(),
                },
                Some(&reportdata),
            )
            .is_ok());
    }
}
