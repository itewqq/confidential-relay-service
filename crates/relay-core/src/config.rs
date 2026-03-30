//! Relay configuration: upstream provider routing and server settings.
//!
//! ## Security: Allowed upstreams
//!
//! The `allowed_upstreams` list is an allowlist of upstream base URLs that the
//! relay is permitted to forward requests to. If set (non-empty), the relay will
//! **refuse** to forward to any URL whose **origin** (scheme + host + port) does
//! not match one of the entries.
//!
//! In a production deployment, the allowed upstreams should be baked into the
//! binary or configuration that is included in the TEE measurement, so users can
//! verify the relay will only talk to known-good providers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
        }
    }
}

/// Extract the **origin** (scheme + host + port) from a URL string.
///
/// Returns `Some("scheme://host:port")` — the port is always explicit so that
/// `https://example.com` and `https://example.com:8443` are distinct.
fn url_origin(raw: &str) -> Option<String> {
    // Minimal URL parsing: split on "://" then extract host:port.
    let (scheme, rest) = raw.split_once("://")?;
    let scheme = scheme.to_lowercase();
    // `rest` is e.g. "api.openai.com/v1/chat" or "api.openai.com:443/v1".
    // Strip path (and any userinfo — we reject `@` below).
    let authority = rest.split('/').next().unwrap_or(rest);

    // Reject userinfo like "user@host" which could be used to trick the check.
    if authority.contains('@') {
        return None;
    }

    // Split host:port. If no port, infer default from scheme.
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        // Make sure the "port" is actually numeric (not an IPv6 bracket group).
        if p.chars().all(|c| c.is_ascii_digit()) {
            (h.to_string(), p.to_string())
        } else {
            // Probably an IPv6 address like [::1], treat whole thing as host.
            (authority.to_string(), default_port(&scheme).to_string())
        }
    } else {
        (authority.to_string(), default_port(&scheme).to_string())
    };

    // Normalise host to lowercase.
    Some(format!("{}://{}:{}", scheme, host.to_lowercase(), port))
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    }
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

    /// Validate that all configured routes point to allowed upstreams.
    /// Call this at startup to catch misconfiguration early.
    pub fn validate(&self) -> Result<(), String> {
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

        assert!(config.check_upstream_allowed("https://api.openai.com/v1/chat").is_ok());
        assert!(config.check_upstream_allowed("https://api.openai.com").is_ok());
    }

    #[test]
    fn allowlist_blocks_subdomain_trick() {
        let config = RelayConfig {
            allowed_upstreams: vec!["https://api.openai.com".to_string()],
            ..Default::default()
        };

        // Must be blocked — the real host is api.openai.com.evil.com
        assert!(
            config.check_upstream_allowed("https://api.openai.com.evil.com/steal").is_err(),
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
            config.check_upstream_allowed("https://api.openai.com@evil.com/steal").is_err(),
            "userinfo-based bypass must be blocked"
        );
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
    fn config_hash_is_deterministic() {
        let config = RelayConfig::default();
        assert_eq!(config.config_hash(), config.config_hash());
    }
}
