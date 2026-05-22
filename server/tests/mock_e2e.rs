//! End-to-end test: start a relay server with mock attestation, connect with the
//! SDK using mock verification, and proxy a chat completion request through.
//!
//! This test runs entirely on Mac — no TEE hardware needed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use relay_attest::mock::{get_mock_measurement, MockAttester, MockVerifier};
use relay_attest::Verifier;
use relay_core::config::RelayConfig;
use relay_core::proxy::AppState;
use relay_core::router::build_router;
use relay_core::secrets::{ProviderCredential, ProviderCredentialStore};
use relay_sdk::client::TrustedRelayClient;
use relay_sdk::types::ChatRequest;
use relay_sdk::verify::VerificationPolicy;
use relay_tls::server::AttestedTlsServer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Start a mock upstream server that returns a fake OpenAI response.
async fn start_mock_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    start_mock_upstream_with_auth_check(None).await
}

async fn start_mock_upstream_with_auth_check(
    expected_auth: Option<&'static str>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::Json;

    #[derive(Clone)]
    struct UpstreamState {
        expected_auth: Option<&'static str>,
    }

    async fn fake_chat_completions(
        State(state): State<UpstreamState>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        // Parse incoming to verify it's valid JSON.
        let _: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if let Some(expected) = state.expected_auth {
            assert_eq!(
                headers.get("authorization").and_then(|v| v.to_str().ok()),
                Some(expected)
            );
        }

        Json(serde_json::json!({
            "id": "chatcmpl-test123",
            "object": "chat.completion",
            "created": 1700000000u64,
            "model": "gpt-4",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello from the mock upstream!"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 7,
                "total_tokens": 17
            }
        }))
    }

    let app = axum::Router::new()
        .route("/v1/chat/completions", post(fake_chat_completions))
        .with_state(UpstreamState { expected_auth });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

/// Start the relay server with mock attestation on a random port.
async fn start_relay_server(
    upstream_addr: SocketAddr,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    start_relay_server_with_credentials(upstream_addr, None).await
}

async fn start_relay_server_with_credentials(
    upstream_addr: SocketAddr,
    provider_credential: Option<ProviderCredential>,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    // Install crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Arc::new(RelayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        default_upstream: format!("http://{}", upstream_addr),
        ..Default::default()
    });
    let config_hash = config.config_hash();

    let attester = MockAttester;
    let tls_server = AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap();
    let tls_acceptor = TlsAcceptor::from(tls_server.server_config());

    let http_client = reqwest::Client::new();
    let provider_credentials = ProviderCredentialStore::new();
    if let Some(provider_credential) = provider_credential {
        provider_credentials.set(provider_credential).await;
    }
    let state = AppState {
        config,
        http_client,
        provider_credentials,
    };
    let app = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let tls_acceptor = tls_acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                let Ok(tls_stream) = tls_acceptor.accept(stream).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let service = hyper_util::service::TowerToHyperService::new(app);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await;
            });
        }
    });

    (addr, config_hash, handle)
}

#[tokio::test]
async fn e2e_mock_attestation_proxy() {
    // 1. Start mock upstream.
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;

    // 2. Start relay server with mock attestation.
    let (relay_addr, _config_hash, _relay_handle) = start_relay_server(upstream_addr).await;

    // Give servers a moment to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Create SDK client with mock verification.
    let client = TrustedRelayClient::builder()
        .endpoint(format!("https://127.0.0.1:{}", relay_addr.port()))
        .api_key("local-test-token")
        .verification(VerificationPolicy::MockDev)
        .build()
        .unwrap();

    // 4. Send a chat completion request.
    let response = client
        .chat_completions(ChatRequest::simple("gpt-4", "Hello, world!"))
        .await
        .unwrap();

    // 5. Verify the response came through correctly.
    assert_eq!(response.id, "chatcmpl-test123");
    assert_eq!(response.choices.len(), 1);
    assert_eq!(
        response.choices[0].message.content,
        "Hello from the mock upstream!"
    );
    assert_eq!(response.usage.as_ref().unwrap().total_tokens, 17);
}

#[tokio::test]
async fn e2e_wrong_measurement_rejected() {
    // 1. Start mock upstream.
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;

    // 2. Start relay server.
    let (relay_addr, config_hash, _relay_handle) = start_relay_server(upstream_addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Create SDK client with WRONG expected measurement.
    //    Use explicit mock verifier since Strict policy no longer falls back to mock.
    let client = TrustedRelayClient::builder()
        .endpoint(format!("https://127.0.0.1:{}", relay_addr.port()))
        .api_key("local-test-token")
        .verifier(Arc::new(MockVerifier) as Arc<dyn Verifier>)
        .verification(VerificationPolicy::Strict {
            expected_measurement: vec![0xFF; 32], // wrong!
        })
        .expected_config_hash(config_hash)
        .build()
        .unwrap();

    // 4. The request should fail because measurement doesn't match.
    let result = client
        .chat_completions(ChatRequest::simple("gpt-4", "Hello"))
        .await;

    assert!(
        result.is_err(),
        "should reject connection with wrong measurement"
    );
}

#[tokio::test]
async fn e2e_correct_measurement_accepted() {
    // 1. Start mock upstream.
    let (upstream_addr, _upstream_handle) = start_mock_upstream().await;

    // 2. Start relay server.
    let (relay_addr, config_hash, _relay_handle) = start_relay_server(upstream_addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Create SDK client with CORRECT expected measurement.
    //    Use explicit mock verifier since Strict policy no longer falls back to mock.
    let measurement = get_mock_measurement();
    let client = TrustedRelayClient::builder()
        .endpoint(format!("https://127.0.0.1:{}", relay_addr.port()))
        .api_key("local-test-token")
        .verifier(Arc::new(MockVerifier) as Arc<dyn Verifier>)
        .verification(VerificationPolicy::Strict {
            expected_measurement: measurement.to_vec(),
        })
        .expected_config_hash(config_hash)
        .build()
        .unwrap();

    // 4. Should succeed.
    let response = client
        .chat_completions(ChatRequest::simple("gpt-4", "Hello"))
        .await
        .unwrap();

    assert_eq!(
        response.choices[0].message.content,
        "Hello from the mock upstream!"
    );
}

#[tokio::test]
async fn e2e_injected_provider_credential_overrides_client_authorization() {
    // 1. Start mock upstream that requires the injected provider credential.
    let (upstream_addr, _upstream_handle) =
        start_mock_upstream_with_auth_check(Some("Bearer provider-secret")).await;

    // 2. Start relay with provider credential already injected into its runtime store.
    let credential = ProviderCredential {
        auth_scheme: "Bearer".to_string(),
        token: "provider-secret".to_string(),
    };
    let (relay_addr, _config_hash, _relay_handle) =
        start_relay_server_with_credentials(upstream_addr, Some(credential)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 3. Client sends a different local token; upstream must still see provider-secret.
    let client = TrustedRelayClient::builder()
        .endpoint(format!("https://127.0.0.1:{}", relay_addr.port()))
        .api_key("local-user-token-not-provider-key")
        .verification(VerificationPolicy::MockDev)
        .build()
        .unwrap();

    let response = client
        .chat_completions(ChatRequest::simple("gpt-4", "Hello"))
        .await
        .unwrap();

    assert_eq!(
        response.choices[0].message.content,
        "Hello from the mock upstream!"
    );
}
