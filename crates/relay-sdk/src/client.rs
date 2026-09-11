//! SDK client for connecting to a Trusted Relay server with attested TLS.
//!
//! # Security: Fail-closed verifier selection
//!
//! Callers must explicitly choose a verification policy. There is deliberately
//! no default `Audit` policy because Audit verifies TEE presence but does not pin
//! operator-controlled workload code.
//!
//! For `Strict`, `Audit`, and `TrustOnFirstUse` policies, you **must** either:
//! - Provide an explicit verifier via `.verifier(Arc::new(SevSnpVerifier))`, or
//! - Enable the `sev-snp` feature so the SDK can auto-select the correct backend.
//!
//! The SDK will **never** silently fall back to mock verification for production
//! policies. Only `MockDev` uses the mock verifier, and only when the `mock`
//! feature is enabled.

use std::sync::Arc;

use relay_attest::Verifier;
use relay_tls::client::attested_client_config;

use crate::types::{ChatRequest, ChatResponse};
use crate::verify::VerificationPolicy;

/// A client that connects to a Trusted Relay server and verifies its attestation
/// evidence during the TLS handshake.
pub struct TrustedRelayClient {
    endpoint: String,
    api_key: Option<String>,
    http_client: reqwest::Client,
}

/// Builder for [`TrustedRelayClient`].
pub struct TrustedRelayClientBuilder {
    endpoint: String,
    api_key: Option<String>,
    policy: Option<VerificationPolicy>,
    /// Explicit verifier override. If set, the builder uses this instead of
    /// auto-selecting based on features. Required for production policies
    /// unless a TEE feature is enabled.
    explicit_verifier: Option<Arc<dyn Verifier>>,
    /// Expected config hash (32 bytes). If set, the client will verify that the
    /// relay's REPORTDATA includes this config hash, binding the attestation to a
    /// specific upstream routing configuration.
    expected_config_hash: Option<[u8; 32]>,
}

impl TrustedRelayClientBuilder {
    /// Set the relay server endpoint (e.g. "https://relay.example.com:8443").
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Set a local compatibility token. `trusted-relay-local` strips this before
    /// forwarding, and production relays overwrite it with the injected provider
    /// credential before calling the upstream provider.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the verification policy.
    ///
    /// This is mandatory. Callers that intentionally want diagnostic Audit mode
    /// must opt into it explicitly instead of inheriting it as a default.
    pub fn verification(mut self, policy: VerificationPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Provide an explicit attestation verifier (e.g. `SevSnpVerifier`).
    ///
    /// This is required for `Strict`, `Audit`, and `TrustOnFirstUse` policies
    /// unless a TEE verifier feature (`sev-snp`) is enabled.
    pub fn verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.explicit_verifier = Some(verifier);
        self
    }

    /// Set the expected config hash for upstream binding verification.
    ///
    /// When set, the client verifies that the relay's attestation REPORTDATA
    /// includes this config hash, ensuring the relay is configured to talk
    /// only to the expected upstreams.
    ///
    /// The hash should be computed the same way as `RelayConfig::config_hash()`.
    pub fn expected_config_hash(mut self, hash: [u8; 32]) -> Self {
        self.expected_config_hash = Some(hash);
        self
    }

    /// Build the client.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No verification policy was explicitly selected.
    /// - A production policy (`Strict`/`Audit`/`TOFU`) is used without a verifier
    ///   and without a TEE verifier feature enabled.
    /// - `MockDev` is used without the `mock` feature.
    pub fn build(self) -> anyhow::Result<TrustedRelayClient> {
        let policy = self.policy.ok_or_else(|| {
            anyhow::anyhow!(
                "verification policy must be selected explicitly; use Strict/GcpConfidentialSpace for operator-resistant verification or opt into Audit intentionally"
            )
        })?;

        let verifier: Arc<dyn Verifier> = match &policy {
            VerificationPolicy::GcpConfidentialSpace {
                audience,
                image_digest,
            } => {
                #[cfg(not(feature = "gcp-confidential-space"))]
                let _ = (audience, image_digest);
                if let Some(v) = self.explicit_verifier {
                    v
                } else {
                    #[cfg(feature = "gcp-confidential-space")]
                    {
                        let policy = relay_attest::gcp_confidential_space::GcpConfidentialSpacePolicy::strict_for_image(
                            audience.clone(),
                            image_digest.clone(),
                        );
                        Arc::new(
                            relay_attest::gcp_confidential_space::GcpConfidentialSpaceVerifier::new(
                                policy,
                            )?,
                        )
                    }
                    #[cfg(not(feature = "gcp-confidential-space"))]
                    {
                        anyhow::bail!(
                            "GcpConfidentialSpace policy requires the gcp-confidential-space feature or an explicit verifier"
                        );
                    }
                }
            }
            VerificationPolicy::MockDev => {
                if self.explicit_verifier.is_some() {
                    tracing::warn!(
                        "explicit verifier provided with MockDev policy — using mock verifier instead"
                    );
                }
                #[cfg(feature = "mock")]
                {
                    Arc::new(relay_attest::mock::MockVerifier)
                }
                #[cfg(not(feature = "mock"))]
                {
                    anyhow::bail!("MockDev policy requires the 'mock' feature");
                }
            }
            _production_policy => {
                if matches!(&policy, VerificationPolicy::TrustOnFirstUse) {
                    anyhow::bail!(
                        "VerificationPolicy::TrustOnFirstUse is not implemented yet. \
                         Use Strict with an expected measurement, Audit, or MockDev."
                    );
                }

                if let Some(v) = self.explicit_verifier {
                    v
                } else {
                    #[cfg(feature = "sev-snp")]
                    {
                        tracing::info!("auto-selected SEV-SNP verifier for production policy");
                        Arc::new(relay_attest::sev_snp::SevSnpVerifier)
                    }
                    #[cfg(not(feature = "sev-snp"))]
                    {
                        anyhow::bail!(
                            "production verification policy ({:?}) requires a concrete verifier. Enable 'sev-snp', provide one via .verifier(), or use VerificationPolicy::GcpConfidentialSpace with an image digest.",
                            policy
                        );
                    }
                }
            }
        };

        if matches!(
            &policy,
            VerificationPolicy::Strict { .. } | VerificationPolicy::GcpConfidentialSpace { .. }
        ) && self.expected_config_hash.is_none()
        {
            anyhow::bail!(
                "Strict/GCP Confidential Space verification requires expected_config_hash() so the client pins \
                 the relay's upstream routing configuration as well as its workload identity."
            );
        }

        if self.endpoint.trim().is_empty() {
            anyhow::bail!("relay endpoint must not be empty");
        }

        let expected_measurement = policy.expected_measurement().map(|m| m.to_vec());
        let tls_config =
            attested_client_config(verifier, expected_measurement, self.expected_config_hash);

        let http_client = reqwest::Client::builder()
            .use_preconfigured_tls((*tls_config).clone())
            .build()?;

        Ok(TrustedRelayClient {
            endpoint: self.endpoint,
            api_key: self.api_key,
            http_client,
        })
    }
}

impl TrustedRelayClient {
    /// Create a new builder. A verification policy must be selected explicitly
    /// before calling [`TrustedRelayClientBuilder::build`].
    pub fn builder() -> TrustedRelayClientBuilder {
        TrustedRelayClientBuilder {
            endpoint: String::new(),
            api_key: None,
            policy: None,
            explicit_verifier: None,
            expected_config_hash: None,
        }
    }

    /// Send a chat completion request through the attested relay.
    pub async fn chat_completions(&self, request: ChatRequest) -> anyhow::Result<ChatResponse> {
        let url = format!(
            "{}/v1/chat/completions",
            self.endpoint.trim_end_matches('/')
        );

        let mut req = self.http_client.post(&url).json(&request);

        if let Some(ref key) = self.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req.send().await?;
        let status = resp.status();

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("upstream error {status}: {body}");
        }

        let chat_response: ChatResponse = resp.json().await?;
        Ok(chat_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_explicit_verification_policy() {
        let error = TrustedRelayClient::builder()
            .endpoint("https://relay.example.com:8443")
            .build()
            .err()
            .expect("builder without verification policy must fail");
        assert!(error
            .to_string()
            .contains("verification policy must be selected explicitly"));
    }
}
