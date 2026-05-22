//! Provider credential handling for the relay data plane.
//!
//! Provider credentials are intentionally runtime inputs. They must not be baked
//! into the measured image; production deployments should inject them only after
//! the CVM proves its attested measurement/configuration to a secret broker.

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

    pub async fn set(&self, credential: ProviderCredential) {
        *self.inner.write().await = Some(credential);
    }
}
