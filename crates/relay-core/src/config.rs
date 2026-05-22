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
    pub listen_addr: String,

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

    /// The path to forward to (e.g. "/v1/chat/completions").
    /// If not set, uses the same path as the incoming request.
    pub path: Option<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8443".to_string(),
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
        // Sort routes by key length (descending) for longest-prefix-first matching.
        // BTreeMap gives us sorted order, but we need length-based ordering.
        let mut routes: Vec<_> = self.routes.iter().collect();
        routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        for (prefix, config) in routes {
            if model.starts_with(prefix.as_str()) {
                return (&config.base_url, config.path.as_deref());
            }
        }
        (&self.default_upstream, None)
    }

    /// Check whether a resolved upstream URL is allowed by the allowlist.
    ///
    /// Comparison is done on the URL **origin** (scheme + host + port) to prevent
    /// bypasses such as `https://api.openai.com.evil.com` or
    /// `https://api.openai.com@evil.com`.
    ///
    /// If `allowed_upstreams` is empty, all upstreams are allowed (development mode).
    /// In production, this list should be non-empty.
    ///
    /// Returns `Ok(())` if allowed, or `Err(reason)` if blocked.
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

    /// Validate that all configured routes point to allowed upstreams.
    /// Call this at startup to catch misconfiguration early.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(digest) = &self.release_artifact_digest {
            validate_release_artifact_digest(digest)?;
        }
        normalize_upstream_tls_pins(&self.upstream_tls_leaf_sha256)?;
        if !self.allowed_upstreams.is_empty() {
            // Check default upstream.
            self.check_upstream_allowed(&self.default_upstream)
                .map_err(|e| format!("default upstream not allowed: {e}"))?;

            // Check all route upstreams.
            for (prefix, config) in &self.routes {
                self.check_upstream_allowed(&config.base_url)
                    .map_err(|e| format!("route '{prefix}' upstream not allowed: {e}"))?;
            }
        }
        Ok(())
    }

    /// Compute a deterministic hash of the security-critical configuration.
    ///
    /// This hash covers:
    /// - The default upstream URL
    /// - All route upstream URLs (sorted deterministically)
    /// - The allowed upstreams list (sorted)
    ///
    /// The result can be embedded in the attestation REPORTDATA so clients can
    /// verify which upstream configuration the relay is running with.
    ///
    /// Returns a 32-byte SHA-256 hash.
    pub fn config_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Hash default upstream.
        hasher.update(b"default_upstream:");
        hasher.update(self.default_upstream.as_bytes());
        hasher.update(b"\n");

        // Hash routes (BTreeMap is already sorted by key).
        for (prefix, config) in &self.routes {
            hasher.update(b"route:");
            hasher.update(prefix.as_bytes());
            hasher.update(b"=>");
            hasher.update(config.base_url.as_bytes());
            if let Some(ref path) = config.path {
                hasher.update(b"|path:");
                hasher.update(path.as_bytes());
            }
            hasher.update(b"\n");
        }

        // Hash allowed upstreams (sorted for determinism).
        let mut sorted_allowed = self.allowed_upstreams.clone();
        sorted_allowed.sort();
        for allowed in &sorted_allowed {
            hasher.update(b"allowed:");
            hasher.update(allowed.as_bytes());
            hasher.update(b"\n");
        }

        hasher.update(b"max_request_bytes:");
        hasher.update(self.max_request_bytes.to_string().as_bytes());
        hasher.update(b"\n");

        if let Some(digest) = &self.release_artifact_digest {
            hasher.update(b"release_artifact_digest:");
            hasher.update(digest.trim().to_ascii_lowercase().as_bytes());
            hasher.update(b"\n");
        }

        hasher.update(b"upstream_timeout_secs:");
        hasher.update(self.upstream_timeout_secs.to_string().as_bytes());
        hasher.update(b"\n");

        for (origin, pins) in normalize_upstream_tls_pins(&self.upstream_tls_leaf_sha256)
            .expect("RelayConfig::validate checks upstream TLS pins")
        {
            hasher.update(b"upstream_tls_leaf_sha256:");
            hasher.update(origin.as_bytes());
            hasher.update(b"=>");
            for pin in pins {
                hasher.update(pin.as_bytes());
                hasher.update(b",");
            }
            hasher.update(b"\n");
        }

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── url_origin ──────────────────────────────────────────────────────

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
        // `https://api.openai.com@evil.com` — the real host is evil.com.
        assert_eq!(url_origin("https://api.openai.com@evil.com"), None);
    }

    // ── allowlist ───────────────────────────────────────────────────────

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

        // Must be blocked — the real host is api.openai.com.evil.com
        assert!(
            config
                .check_upstream_allowed("https://api.openai.com.evil.com/steal")
                .is_err(),
            "subdomain impersonation must be blocked"
        );
    }

    #[test]
    fn allowlist_blocks_userinfo_trick() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };

        // Must be blocked — the real host is evil.com (userinfo is ignored by browsers)
        assert!(
            config
                .check_upstream_allowed("https://api.openai.com@evil.com/steal")
                .is_err(),
            "userinfo-based bypass must be blocked"
        );
    }

    #[test]
    fn allowlist_blocks_unknown_upstream() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };

        assert!(config
            .check_upstream_allowed("https://evil.com/steal")
            .is_err());
    }

    #[test]
    fn empty_allowlist_permits_all() {
        let config = RelayConfig::default();
        assert!(config
            .check_upstream_allowed("https://anything.com")
            .is_ok());
    }

    // ── routing ─────────────────────────────────────────────────────────

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

        let config = RelayConfig {
            routes,
            ..Default::default()
        };

        // "gpt-4-turbo" should match "gpt-4" (longer prefix), not "gpt-"
        let (url, _) = config.resolve_upstream("gpt-4-turbo");
        assert_eq!(url, "https://api.openai-special.com");

        // "gpt-3.5" should match "gpt-"
        let (url, _) = config.resolve_upstream("gpt-3.5");
        assert_eq!(url, "https://api.openai.com");
    }

    #[test]
    fn falls_back_to_default() {
        let config = RelayConfig::default();
        let (url, _) = config.resolve_upstream("unknown-model");
        assert_eq!(url, "https://api.openai.com");
    }

    // ── validate ────────────────────────────────────────────────────────

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

    // ── config_hash ───────────────────────────────────────────────────────

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

        let config_a = RelayConfig {
            routes: routes_a,
            ..Default::default()
        };
        let config_b = RelayConfig {
            routes: routes_b,
            ..Default::default()
        };

        assert_ne!(
            config_a.config_hash(),
            config_b.config_hash(),
            "configs differing only in path must produce different hashes"
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

        let config_a = RelayConfig {
            routes: routes_a,
            ..Default::default()
        };
        let config_b = RelayConfig {
            routes: routes_b,
            ..Default::default()
        };

        assert_ne!(
            config_a.config_hash(),
            config_b.config_hash(),
            "config with path=None vs path=Some must differ"
        );
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

        assert_ne!(
            config_a.config_hash(),
            config_b.config_hash(),
            "artifact digest changes must alter the config hash bound into REPORTDATA"
        );
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
    fn config_hash_is_deterministic() {
        let config = RelayConfig::default();
        assert_eq!(config.config_hash(), config.config_hash());
    }
}
