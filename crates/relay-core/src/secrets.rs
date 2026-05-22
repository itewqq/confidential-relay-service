//! Provider credential handling for the relay data plane.
//!
//! Provider credentials are intentionally runtime inputs. They must not be baked
//! into the measured image or VM metadata; production deployments inject them
//! through the relay's private admin interface after the CVM starts.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Provider credential material used by the relay when calling upstream APIs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ProviderCredential {
    /// HTTP authorization scheme. Most providers use `Bearer`.
    #[serde(default = "default_auth_scheme")]
    pub auth_scheme: String,
    /// Secret token value. Never log this field.
    pub token: String,
}

fn default_auth_scheme() -> String {
    "Bearer".to_string()
}

impl std::fmt::Debug for ProviderCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderCredential")
            .field("auth_scheme", &self.auth_scheme)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl ProviderCredential {
    /// Build the `Authorization` header value for upstream requests.
    pub fn authorization_value(
        &self,
    ) -> Result<reqwest::header::HeaderValue, http::header::InvalidHeaderValue> {
        reqwest::header::HeaderValue::from_str(&format!("{} {}", self.auth_scheme, self.token))
    }

    /// Validate enough to ensure the credential can become an Authorization
    /// header without accidentally allowing header splitting.
    pub fn validate(&self) -> Result<(), String> {
        let scheme = self.auth_scheme.trim();
        if scheme.is_empty() {
            return Err("auth_scheme must not be empty".to_string());
        }
        if scheme
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err("auth_scheme must be a single HTTP token".to_string());
        }
        if self.token.is_empty() {
            return Err("token must not be empty".to_string());
        }
        if self
            .token
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err("token must not contain whitespace or control bytes".to_string());
        }
        self.authorization_value()
            .map_err(|_| "credential is not a valid Authorization header".to_string())?;
        Ok(())
    }
}

/// Shared runtime provider credential state.
#[derive(Clone, Default)]
pub struct ProviderCredentialStore {
    inner: Arc<RwLock<Option<ProviderCredential>>>,
}

impl ProviderCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self) -> Option<ProviderCredential> {
        self.inner.read().await.clone()
    }

    pub async fn is_loaded(&self) -> bool {
        self.inner.read().await.is_some()
    }

    pub async fn set(&self, credential: ProviderCredential) {
        *self.inner.write().await = Some(credential);
    }

    pub async fn set_once(&self, credential: ProviderCredential) -> Result<(), ProviderCredential> {
        let mut guard = self.inner.write().await;
        if guard.is_some() {
            return Err(credential);
        }
        *guard = Some(credential);
        Ok(())
    }
}
