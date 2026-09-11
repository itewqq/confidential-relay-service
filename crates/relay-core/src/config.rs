//! Relay configuration: upstream provider routing and server settings.
//!
//! ## Security: Allowed upstreams
//!
//! The `allowed_upstreams` list is an allowlist of upstream base URLs that the
//! relay is permitted to forward requests to. If set (non-empty), the relay will
//! **refuse** to forward to any URL whose **origin** (scheme + host + port) does
//! not match one of the entries.
//!
//! In production, the user pins the workload identity and REPORTDATA-bound
//! config hash so they can verify which upstreams the relay may contact.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use url::Url;

/// Top-level configuration for the relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Address to listen on (e.g. "0.0.0.0:8443").
    ///
    /// This is intentionally not included in `config_hash()` because it is a
    /// deployment coordinate; the local proxy pins the endpoint it connects to.
    pub listen_addr: String,

    /// Security-relevant process/runtime choices that clients should be able to
    /// verify through `config_hash()`. Keep deploy-only addresses and secret
    /// material out of this struct.
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Default upstream URL if no model-specific route matches.
    pub default_upstream: String,

    /// Model-prefix → upstream mapping.
    /// e.g. `{ "gpt-" => "https://api.openai.com", "claude-" => "https://api.anthropic.com" }`
    ///
    /// Uses BTreeMap for deterministic iteration order — longest prefix matches first
    /// because we sort by descending key length before matching.
    #[serde(default)]
    pub routes: BTreeMap<String, ProviderConfig>,

    /// Allowlist of upstream base URLs. If non-empty, the relay will refuse to
    /// forward to any upstream whose **origin** (scheme + host + port) does not
    /// match one of these entries.
    ///
    /// Example: `["https://api.openai.com", "https://api.anthropic.com"]`
    ///
    /// In production, this should be baked into the measured binary/config.
    #[serde(default)]
    pub allowed_upstreams: Vec<String>,

    /// Maximum accepted request body size in bytes.
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,

    /// Release/workload artifact digest published for this deployment.
    ///
    /// This is non-secret release metadata. When set, it is folded into
    /// `config_hash()` and therefore into REPORTDATA bytes 48..64. It lets the
    /// local proxy pin a reviewed image or release digest in addition to the
    /// platform TEE measurement. On platforms where the raw
    /// SEV-SNP launch measurement does not identify the custom workload bytes,
    /// this binding is necessary but still must be backed by a platform
    /// workload-image attestation mechanism such as vTPM measured boot or
    /// Confidential Space image-digest claims.
    #[serde(default)]
    pub release_artifact_digest: Option<String>,

    /// End-to-end upstream request timeout in seconds.
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    /// Optional SHA-256 pins for upstream TLS leaf certificates, keyed by URL
    /// origin (`https://host:port`). When present for an origin, the relay only
    /// forwards after the provider certificate matches one of the configured
    /// pins. This is folded into `config_hash()` so clients can verify it.
    #[serde(default)]
    pub upstream_tls_leaf_sha256: BTreeMap<String, Vec<String>>,
}

/// Configuration for a single upstream provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Base URL for the provider's API (e.g. "https://api.openai.com").
    pub base_url: String,

    /// Absolute path to forward to (e.g. "/v1/chat/completions").
    /// If not set, uses the same path as the incoming request.
    ///
    /// Paths are treated strictly as paths, never as URL references, so they
    /// cannot change scheme, authority, host, or port.
    pub path: Option<String>,
}

/// Security-relevant runtime choices that are not upstream routes but still
/// affect the confidentiality/integrity contract clients verify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// If true, the relay may forward a client-supplied Authorization header to
    /// the upstream when no provider credential has been injected.
    /// Production clients should expect this to be false.
    #[serde(default)]
    pub allow_client_provider_auth: bool,

    /// If true, the relay starts the one-shot private admin credential-injection
    /// endpoint. This does not include the listen address because that is a
    /// deploy-only network coordinate protected by VPC/firewall policy.
    #[serde(default)]
    pub private_admin_enabled: bool,

    /// Expected provider Authorization scheme for injected credentials.
    /// The token itself is secret runtime material and is never hashed.
    #[serde(default = "default_provider_auth_scheme")]
    pub provider_auth_scheme: String,

    /// Body logging policy for the relay-owned code path. Current production
    /// code supports only `metadata-only`; request/response bodies are not
    /// logged or persisted by the relay.
    #[serde(default = "default_body_log_policy")]
    pub body_log_policy: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            allow_client_provider_auth: false,
            private_admin_enabled: false,
            provider_auth_scheme: default_provider_auth_scheme(),
            body_log_policy: default_body_log_policy(),
        }
    }
}

fn default_provider_auth_scheme() -> String {
    "Bearer".to_string()
}

fn default_body_log_policy() -> String {
    "metadata-only".to_string()
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_http_token(&self.provider_auth_scheme, "provider_auth_scheme")?;
        if self.body_log_policy != "metadata-only" {
            return Err(format!(
                "body_log_policy must be 'metadata-only', got '{}'",
                self.body_log_policy
            ));
        }
        Ok(())
    }
}

fn validate_http_token(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if !value.bytes().all(is_http_tchar) {
        return Err(format!("{field} must be a valid HTTP token"));
    }
    Ok(())
}

fn is_http_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8443".to_string(),
            runtime: RuntimeConfig::default(),
            default_upstream: "https://api.openai.com".to_string(),
            routes: BTreeMap::new(),
            allowed_upstreams: Vec::new(),
            max_request_bytes: default_max_request_bytes(),
            release_artifact_digest: None,
            upstream_timeout_secs: default_upstream_timeout_secs(),
            upstream_tls_leaf_sha256: BTreeMap::new(),
        }
    }
}

fn default_max_request_bytes() -> usize {
    1024 * 1024
}

fn default_upstream_timeout_secs() -> u64 {
    120
}

/// Extract the **origin** (scheme + host + port) from a URL string.
///
/// Returns `Some("scheme://host:port")` — the port is always explicit so that
/// `https://example.com` and `https://example.com:8443` are distinct.
fn url_origin(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw).ok()?;
    let scheme = parsed.scheme();
    if scheme != "https" && !is_local_http_url(&parsed) {
        return None;
    }

    // Reject userinfo like "user@host" which can trick humans reviewing allowlists.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }

    let host = parsed.host_str()?.to_lowercase();
    let port = parsed.port_or_known_default()?;

    Some(format!("{scheme}://{host}:{port}"))
}

fn is_local_http_url(parsed: &Url) -> bool {
    parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            matches!(
                host.to_ascii_lowercase().as_str(),
                "localhost" | "127.0.0.1" | "::1"
            )
        })
}

fn validate_upstream_base_url(raw: &str, field: &str) -> Result<Url, String> {
    let parsed = Url::parse(raw).map_err(|e| format!("{field} is not a valid URL: {e}"))?;
    if url_origin(raw).is_none() {
        return Err(format!(
            "{field} must use https:// (or loopback http:// for development), include a host, and contain no userinfo"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!("{field} must not include a query or fragment"));
    }
    Ok(parsed)
}

fn validate_upstream_path(path: &str) -> Result<(), String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err("upstream path must be a non-empty absolute path beginning with '/'".to_string());
    }
    if path.starts_with("//") {
        return Err("upstream path must not be scheme-relative ('//...')".to_string());
    }
    if path.contains('?') || path.contains('#') || path.contains('\r') || path.contains('\n') {
        return Err("upstream path must not contain query, fragment, or control delimiters".to_string());
    }
    Ok(())
}

fn validate_release_artifact_digest(raw: &str) -> Result<(), String> {
    let digest = raw.trim();
    let hex = digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("SHA256:"))
        .unwrap_or(digest);

    if hex.len() != 64 {
        return Err(format!(
            "release_artifact_digest must be a 32-byte sha256 hex digest, got {} hex chars",
            hex.len()
        ));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("release_artifact_digest must be hex".to_string());
    }
    Ok(())
}

fn normalize_sha256_pin(raw: &str) -> Option<String> {
    let pin = raw.trim().to_ascii_lowercase();
    let hex = pin.strip_prefix("sha256:").unwrap_or(&pin);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(format!("sha256:{hex}"));
    }
    None
}

fn normalize_upstream_tls_pins(
    pins: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut normalized = BTreeMap::new();
    for (origin, values) in pins {
        let parsed = Url::parse(origin)
            .map_err(|_| format!("upstream TLS pin origin '{origin}' is not a valid URL"))?;
        if parsed.scheme() != "https" {
            return Err(format!(
                "upstream TLS pin origin '{origin}' must use https://"
            ));
        }
        let origin = url_origin(origin).ok_or_else(|| {
            format!("upstream TLS pin origin '{origin}' is not a valid HTTPS origin")
        })?;
        if values.is_empty() {
            return Err(format!(
                "upstream TLS pin origin '{origin}' must include at least one sha256 pin"
            ));
        }
        let mut normalized_values = Vec::new();
        for value in values {
            let pin = normalize_sha256_pin(value).ok_or_else(|| {
                format!("upstream TLS pin for '{origin}' must be sha256:<64 hex>, got {value}")
            })?;
            if !normalized_values.contains(&pin) {
                normalized_values.push(pin);
            }
        }
        normalized_values.sort();
        normalized.insert(origin, normalized_values);
    }
    Ok(normalized)
}

impl RelayConfig {
    /// Resolve the upstream URL for a given model name.
    ///
    /// Routes are matched by longest-prefix-first to ensure deterministic behavior
    /// when multiple prefixes could match (e.g. "gpt-4" and "gpt-").
    ///
    /// Returns `(base_url, optional_path_override)`.
    pub fn resolve_upstream(&self, model: &str) -> (&str, Option<&str>) {
        let mut routes: Vec<_> = self.routes.iter().collect();
        routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        for (prefix, config) in routes {
            if model.starts_with(prefix.as_str()) {
                return (&config.base_url, config.path.as_deref());
            }
        }
        (&self.default_upstream, None)
    }

    /// Construct an upstream request URL without ever interpreting the route
    /// path as a URL reference. The final URL is checked against the allowlist.
    pub fn build_upstream_url(&self, base_url: &str, path: &str) -> Result<Url, String> {
        validate_upstream_path(path)?;
        let mut url = validate_upstream_base_url(base_url, "upstream base URL")?;

        let base_path = url.path().trim_end_matches('/');
        let combined_path = if base_path.is_empty() || base_path == "/" {
            path.to_string()
        } else {
            format!("{base_path}{path}")
        };
        url.set_path(&combined_path);
        url.set_query(None);
        url.set_fragment(None);

        self.check_upstream_allowed(url.as_str())?;
        Ok(url)
    }

    /// Check whether a resolved upstream URL is allowed by the allowlist.
    ///
    /// Comparison is done on the URL **origin** (scheme + host + port) to prevent
    /// bypasses such as `https://api.openai.com.evil.com` or
    /// `https://api.openai.com@evil.com`.
    ///
    /// If `allowed_upstreams` is empty, all upstreams are allowed (development mode).
    /// In production, this list should be non-empty.
    pub fn check_upstream_allowed(&self, upstream_url: &str) -> Result<(), String> {
        if self.allowed_upstreams.is_empty() {
            tracing::warn!(
                "no upstream allowlist configured — all upstreams are allowed. \
                 Set `allowed_upstreams` in production!"
            );
            return Ok(());
        }

        let candidate_origin = url_origin(upstream_url).ok_or_else(|| {
            format!("upstream URL '{upstream_url}' is not a valid URL (cannot extract origin)")
        })?;

        for allowed in &self.allowed_upstreams {
            if let Some(allowed_origin) = url_origin(allowed) {
                if candidate_origin == allowed_origin {
                    return Ok(());
                }
            }
        }

        Err(format!(
            "upstream origin '{candidate_origin}' (from '{upstream_url}') is not in the allowed list: {:?}",
            self.allowed_upstreams
        ))
    }

    /// Return normalized sha256 pins for a resolved upstream origin, if configured.
    pub fn upstream_tls_pins_for(&self, upstream_url: &str) -> Result<Option<Vec<String>>, String> {
        let pins = normalize_upstream_tls_pins(&self.upstream_tls_leaf_sha256)?;
        let origin = url_origin(upstream_url).ok_or_else(|| {
            format!("upstream URL '{upstream_url}' is not a valid URL (cannot extract origin)")
        })?;
        Ok(pins.get(&origin).cloned())
    }

    /// Return normalized sha256 pins keyed by TLS server name.
    ///
    /// Rustls certificate verification receives the SNI/hostname, not the URL
    /// port, so origins that share a hostname intentionally share the union of
    /// their configured pins at handshake time.
    pub fn upstream_tls_pin_hosts(&self) -> Result<BTreeMap<String, Vec<String>>, String> {
        let pins = normalize_upstream_tls_pins(&self.upstream_tls_leaf_sha256)?;
        let mut by_host: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (origin, origin_pins) in pins {
            let parsed = Url::parse(&origin)
                .map_err(|_| format!("normalized upstream TLS pin origin '{origin}' is invalid"))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| format!("normalized upstream TLS pin origin '{origin}' lacks host"))?
                .to_ascii_lowercase();
            by_host.entry(host).or_default().extend(origin_pins);
        }
        Ok(by_host
            .into_iter()
            .map(|(host, pins)| (host, pins.into_iter().collect()))
            .collect())
    }

    /// Validate all security-relevant upstream configuration.
    pub fn validate(&self) -> Result<(), String> {
        self.runtime.validate()?;
        if let Some(digest) = &self.release_artifact_digest {
            validate_release_artifact_digest(digest)?;
        }
        normalize_upstream_tls_pins(&self.upstream_tls_leaf_sha256)?;

        validate_upstream_base_url(&self.default_upstream, "default upstream")?;
        if !self.allowed_upstreams.is_empty() {
            self.check_upstream_allowed(&self.default_upstream)
                .map_err(|e| format!("default upstream not allowed: {e}"))?;
        }

        for (prefix, config) in &self.routes {
            validate_upstream_base_url(&config.base_url, &format!("route '{prefix}' upstream"))?;
            if let Some(path) = &config.path {
                validate_upstream_path(path)
                    .map_err(|e| format!("route '{prefix}' has invalid path: {e}"))?;
                self.build_upstream_url(&config.base_url, path)
                    .map_err(|e| format!("route '{prefix}' invalid final upstream URL: {e}"))?;
            } else if !self.allowed_upstreams.is_empty() {
                self.check_upstream_allowed(&config.base_url)
                    .map_err(|e| format!("route '{prefix}' upstream not allowed: {e}"))?;
            }
        }
        Ok(())
    }

    /// Compute a deterministic hash of the security-critical configuration.
    ///
    /// Schema v3 uses length-prefixed fields rather than delimiter-based text.
    /// This makes field boundaries unambiguous even when values contain strings
    /// such as `|path:` or newlines, preventing two different configurations
    /// from producing the same serialized hash input.
    ///
    /// Returns a 32-byte SHA-256 hash.
    pub fn config_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        fn put(hasher: &mut Sha256, label: &str, value: &[u8]) {
            let label = label.as_bytes();
            hasher.update((label.len() as u64).to_be_bytes());
            hasher.update(label);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }

        let mut hasher = Sha256::new();
        put(&mut hasher, "schema", b"config_hash_schema:v3");
        put(
            &mut hasher,
            "runtime.allow_client_provider_auth",
            &[self.runtime.allow_client_provider_auth as u8],
        );
        put(
            &mut hasher,
            "runtime.private_admin_enabled",
            &[self.runtime.private_admin_enabled as u8],
        );
        put(
            &mut hasher,
            "runtime.provider_auth_scheme",
            self.runtime.provider_auth_scheme.as_bytes(),
        );
        put(
            &mut hasher,
            "runtime.body_log_policy",
            self.runtime.body_log_policy.as_bytes(),
        );
        put(
            &mut hasher,
            "default_upstream",
            self.default_upstream.as_bytes(),
        );

        put(
            &mut hasher,
            "routes.count",
            &(self.routes.len() as u64).to_be_bytes(),
        );
        for (prefix, config) in &self.routes {
            put(&mut hasher, "route.prefix", prefix.as_bytes());
            put(&mut hasher, "route.base_url", config.base_url.as_bytes());
            match &config.path {
                Some(path) => {
                    put(&mut hasher, "route.path.present", &[1]);
                    put(&mut hasher, "route.path", path.as_bytes());
                }
                None => put(&mut hasher, "route.path.present", &[0]),
            }
        }

        let mut sorted_allowed = self.allowed_upstreams.clone();
        sorted_allowed.sort();
        put(
            &mut hasher,
            "allowed_upstreams.count",
            &(sorted_allowed.len() as u64).to_be_bytes(),
        );
        for allowed in &sorted_allowed {
            put(&mut hasher, "allowed_upstream", allowed.as_bytes());
        }

        put(
            &mut hasher,
            "max_request_bytes",
            &(self.max_request_bytes as u64).to_be_bytes(),
        );
        match &self.release_artifact_digest {
            Some(digest) => {
                put(&mut hasher, "release_artifact_digest.present", &[1]);
                put(
                    &mut hasher,
                    "release_artifact_digest",
                    digest.trim().to_ascii_lowercase().as_bytes(),
                );
            }
            None => put(&mut hasher, "release_artifact_digest.present", &[0]),
        }
        put(
            &mut hasher,
            "upstream_timeout_secs",
            &self.upstream_timeout_secs.to_be_bytes(),
        );

        let normalized_pins = normalize_upstream_tls_pins(&self.upstream_tls_leaf_sha256)
            .expect("RelayConfig::validate checks upstream TLS pins");
        put(
            &mut hasher,
            "upstream_tls_leaf_sha256.count",
            &(normalized_pins.len() as u64).to_be_bytes(),
        );
        for (origin, pins) in normalized_pins {
            put(&mut hasher, "upstream_tls.origin", origin.as_bytes());
            put(
                &mut hasher,
                "upstream_tls.pins.count",
                &(pins.len() as u64).to_be_bytes(),
            );
            for pin in pins {
                put(&mut hasher, "upstream_tls.pin", pin.as_bytes());
            }
        }

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_basic() {
        assert_eq!(
            url_origin("https://api.openai.com"),
            Some("https://api.openai.com:443".into())
        );
        assert_eq!(
            url_origin("http://localhost:3000/v1"),
            Some("http://localhost:3000".into())
        );
        assert_eq!(url_origin("http://api.openai.com/v1"), None);
    }

    #[test]
    fn origin_normalises_case() {
        assert_eq!(
            url_origin("HTTPS://API.OpenAI.COM/v1"),
            Some("https://api.openai.com:443".into())
        );
    }

    #[test]
    fn origin_rejects_userinfo() {
        assert_eq!(url_origin("https://api.openai.com@evil.com"), None);
    }

    #[test]
    fn allowlist_permits_same_origin() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };
        assert!(config
            .check_upstream_allowed("https://api.openai.com/v1/chat")
            .is_ok());
        assert!(config
            .check_upstream_allowed("https://api.openai.com")
            .is_ok());
    }

    #[test]
    fn allowlist_blocks_subdomain_trick() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };
        assert!(config
            .check_upstream_allowed("https://api.openai.com.evil.com/steal")
            .is_err());
    }

    #[test]
    fn allowlist_blocks_userinfo_trick() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };
        assert!(config
            .check_upstream_allowed("https://api.openai.com@evil.com/steal")
            .is_err());
    }

    #[test]
    fn allowlist_blocks_unknown_upstream() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };
        assert!(config.check_upstream_allowed("https://evil.com/steal").is_err());
    }

    #[test]
    fn empty_allowlist_permits_all() {
        let config = RelayConfig::default();
        assert!(config.check_upstream_allowed("https://anything.com").is_ok());
    }

    #[test]
    fn longest_prefix_wins() {
        let mut routes = BTreeMap::new();
        routes.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                path: None,
            },
        );
        routes.insert(
            "gpt-4".to_string(),
            ProviderConfig {
                base_url: "https://api.openai-special.com".to_string(),
                path: None,
            },
        );
        let config = RelayConfig { routes, ..Default::default() };
        let (url, _) = config.resolve_upstream("gpt-4-turbo");
        assert_eq!(url, "https://api.openai-special.com");
        let (url, _) = config.resolve_upstream("gpt-3.5");
        assert_eq!(url, "https://api.openai.com");
    }

    #[test]
    fn falls_back_to_default() {
        let config = RelayConfig::default();
        let (url, _) = config.resolve_upstream("unknown-model");
        assert_eq!(url, "https://api.openai.com");
    }

    #[test]
    fn validate_catches_bad_routes() {
        let mut routes = BTreeMap::new();
        routes.insert(
            "evil-".to_string(),
            ProviderConfig {
                base_url: "https://evil.com".to_string(),
                path: None,
            },
        );
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            routes,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_authority_like_route_path() {
        let mut routes = BTreeMap::new();
        routes.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                path: Some("@evil.example/steal".to_string()),
            },
        );
        let config = RelayConfig {
            routes,
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn build_upstream_url_preserves_allowed_origin() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };
        let url = config
            .build_upstream_url("https://api.openai.com", "/v1/chat/completions")
            .unwrap();
        assert_eq!(url.as_str(), "https://api.openai.com/v1/chat/completions");
        assert_eq!(url.host_str(), Some("api.openai.com"));
    }

    #[test]
    fn config_hash_differs_when_path_changes() {
        let mut routes_a = BTreeMap::new();
        routes_a.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
            },
        );
        let mut routes_b = BTreeMap::new();
        routes_b.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                path: Some("/v1/evil/exfiltrate".to_string()),
            },
        );
        let config_a = RelayConfig { routes: routes_a, ..Default::default() };
        let config_b = RelayConfig { routes: routes_b, ..Default::default() };
        assert_ne!(config_a.config_hash(), config_b.config_hash());
    }

    #[test]
    fn config_hash_v3_breaks_legacy_delimiter_collision() {
        let mut routes_a = BTreeMap::new();
        routes_a.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com/|path:@evil.example".to_string(),
                path: None,
            },
        );
        let mut routes_b = BTreeMap::new();
        routes_b.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com/".to_string(),
                path: Some("@evil.example".to_string()),
            },
        );
        let config_a = RelayConfig { routes: routes_a, ..Default::default() };
        let config_b = RelayConfig { routes: routes_b, ..Default::default() };
        assert_ne!(
            config_a.config_hash(),
            config_b.config_hash(),
            "length-prefixed schema must distinguish legacy delimiter collision inputs"
        );
    }

    #[test]
    fn config_hash_differs_with_and_without_path() {
        let mut routes_a = BTreeMap::new();
        routes_a.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                path: None,
            },
        );
        let mut routes_b = BTreeMap::new();
        routes_b.insert(
            "gpt-".to_string(),
            ProviderConfig {
                base_url: "https://api.openai.com".to_string(),
                path: Some("/v1/chat/completions".to_string()),
            },
        );
        let config_a = RelayConfig { routes: routes_a, ..Default::default() };
        let config_b = RelayConfig { routes: routes_b, ..Default::default() };
        assert_ne!(config_a.config_hash(), config_b.config_hash());
    }

    #[test]
    fn config_hash_differs_when_release_artifact_digest_changes() {
        let config_a = RelayConfig {
            release_artifact_digest: Some(
                "5610754eb95be37c666c5240287027cc1173c26d249a3deaade30f12cdbf8bfd".to_string(),
            ),
            ..Default::default()
        };
        let config_b = RelayConfig {
            release_artifact_digest: Some(
                "9743b9e2023398158544ee5b46d8173a08b020e1d19afd6acb13e7f548768bd5".to_string(),
            ),
            ..Default::default()
        };
        assert_ne!(config_a.config_hash(), config_b.config_hash());
    }

    #[test]
    fn validate_rejects_bad_release_artifact_digest() {
        let config = RelayConfig {
            release_artifact_digest: Some("not-a-digest".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn upstream_tls_pins_are_normalized_by_origin() {
        let mut pins = BTreeMap::new();
        pins.insert(
            "https://API.OpenAI.COM/v1".to_string(),
            vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
        );
        let config = RelayConfig {
            upstream_tls_leaf_sha256: pins,
            ..Default::default()
        };
        assert_eq!(
            config
                .upstream_tls_pins_for("https://api.openai.com/v1/chat/completions")
                .unwrap(),
            Some(vec![
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string()
            ])
        );
    }

    #[test]
    fn validate_rejects_bad_upstream_tls_pin() {
        let mut pins = BTreeMap::new();
        pins.insert(
            "https://api.openai.com".to_string(),
            vec!["not-a-pin".to_string()],
        );
        let config = RelayConfig {
            upstream_tls_leaf_sha256: pins,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_http_upstream_tls_pin_origin() {
        let mut pins = BTreeMap::new();
        pins.insert(
            "http://localhost:3000".to_string(),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
        );
        let config = RelayConfig {
            upstream_tls_leaf_sha256: pins,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn upstream_tls_pin_hosts_union_same_host_pins() {
        let mut pins = BTreeMap::new();
        pins.insert(
            "https://api.openai.com".to_string(),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
        );
        pins.insert(
            "https://api.openai.com:8443".to_string(),
            vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()],
        );
        let config = RelayConfig {
            upstream_tls_leaf_sha256: pins,
            ..Default::default()
        };
        assert_eq!(
            config
                .upstream_tls_pin_hosts()
                .unwrap()
                .get("api.openai.com"),
            Some(&vec![
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            ])
        );
    }

    #[test]
    fn config_hash_differs_when_upstream_tls_pin_changes() {
        let mut pins_a = BTreeMap::new();
        pins_a.insert(
            "https://api.openai.com".to_string(),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
        );
        let mut pins_b = BTreeMap::new();
        pins_b.insert(
            "https://api.openai.com".to_string(),
            vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()],
        );
        let config_a = RelayConfig {
            upstream_tls_leaf_sha256: pins_a,
            ..Default::default()
        };
        let config_b = RelayConfig {
            upstream_tls_leaf_sha256: pins_b,
            ..Default::default()
        };
        assert_ne!(config_a.config_hash(), config_b.config_hash());
    }

    #[test]
    fn config_hash_differs_when_runtime_security_flags_change() {
        let config_a = RelayConfig::default();
        let config_b = RelayConfig {
            runtime: RuntimeConfig {
                allow_client_provider_auth: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let config_c = RelayConfig {
            runtime: RuntimeConfig {
                private_admin_enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(config_a.config_hash(), config_b.config_hash());
        assert_ne!(config_a.config_hash(), config_c.config_hash());
        assert_ne!(config_b.config_hash(), config_c.config_hash());
    }

    #[test]
    fn config_hash_differs_when_runtime_policy_changes() {
        let config_a = RelayConfig::default();
        let config_b = RelayConfig {
            runtime: RuntimeConfig {
                provider_auth_scheme: "Basic".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(config_a.config_hash(), config_b.config_hash());
    }

    #[test]
    fn validate_rejects_body_logging_policy_that_is_not_metadata_only() {
        let config = RelayConfig {
            runtime: RuntimeConfig {
                body_log_policy: "full-body".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_provider_auth_scheme() {
        let config = RelayConfig {
            runtime: RuntimeConfig {
                provider_auth_scheme: "Bearer token".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_hash_is_deterministic() {
        let config = RelayConfig::default();
        assert_eq!(config.config_hash(), config.config_hash());
    }
}
