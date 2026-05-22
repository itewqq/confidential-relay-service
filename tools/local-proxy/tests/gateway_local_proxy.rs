use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::Json;
#[cfg(feature = "gcp-confidential-space")]
use relay_attest::gcp_confidential_space::{
    reportdata_nonces, GcpConfidentialSpacePolicy, GcpConfidentialSpaceVerifier, Jwk, JwksSet,
};
use relay_attest::mock::{get_mock_measurement, MockAttester};
#[cfg(feature = "gcp-confidential-space")]
use relay_attest::types::{Evidence, TeeType};
#[cfg(feature = "gcp-confidential-space")]
use relay_attest::Attester;
use relay_core::config::RelayConfig;
use relay_core::proxy::AppState;
use relay_core::router::build_router;
use relay_core::secrets::{ProviderCredential, ProviderCredentialStore};
use relay_tls::server::AttestedTlsServer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const ARTIFACT_DIGEST_A: &str = "5610754eb95be37c666c5240287027cc1173c26d249a3deaade30f12cdbf8bfd";
const ARTIFACT_DIGEST_B: &str = "9743b9e2023398158544ee5b46d8173a08b020e1d19afd6acb13e7f548768bd5";

async fn start_mock_upstream(
    expected_auth: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    #[derive(Clone)]
    struct UpstreamState {
        expected_auth: &'static str,
    }

    async fn fake_chat_completions(
        State(state): State<UpstreamState>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Json<serde_json::Value> {
        let _: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some(state.expected_auth),
            "relay must replace local user Authorization with injected provider credential"
        );

        Json(serde_json::json!({
            "id": "chatcmpl-local-proxy-test",
            "object": "chat.completion",
            "created": 1700000000u64,
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok through gateway"},
                "finish_reason": "stop"
            }]
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

async fn start_attested_relay(
    upstream_addr: SocketAddr,
    provider_credential: ProviderCredential,
    measurement_override: Option<[u8; 32]>,
    release_artifact_digest: Option<&str>,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Arc::new(RelayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        default_upstream: format!("http://{upstream_addr}"),
        allowed_upstreams: vec![format!("http://{upstream_addr}")],
        release_artifact_digest: release_artifact_digest.map(str::to_owned),
        ..Default::default()
    });
    let config_hash = config.config_hash();

    let tls_server = if let Some(measurement) = measurement_override {
        let attester = MockAttester::with_measurement(measurement);
        AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap()
    } else {
        let attester = MockAttester;
        AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap()
    };
    let tls_acceptor = TlsAcceptor::from(tls_server.server_config());

    let provider_credentials = ProviderCredentialStore::new();
    provider_credentials.set(provider_credential).await;
    let state = AppState {
        config,
        http_client: reqwest::Client::new(),
        provider_credentials,
        require_provider_credential: false,
    };
    let app = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
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

async fn start_gateway(
    relay_addr: SocketAddr,
    token: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(handle_gateway_connection(stream, relay_addr, token));
        }
    });
    (addr, handle)
}

async fn handle_gateway_connection(
    stream: TcpStream,
    relay_addr: SocketAddr,
    expected_token: &str,
) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.unwrap() == 0 {
        return;
    }

    let mut authorized = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap() == 0 {
            return;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorized = value.trim() == format!("Bearer {expected_token}");
            }
        }
    }

    if !request_line.starts_with("CONNECT ") || !authorized {
        let _ = reader
            .get_mut()
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }

    let mut relay = TcpStream::connect(relay_addr).await.unwrap();
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .unwrap();
    let mut client = reader.into_inner();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
}

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn local_proxy_verifies_attested_relay_through_gateway() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream("Bearer provider-secret").await;
    let (relay_addr, config_hash, _relay_handle) = start_attested_relay(
        upstream_addr,
        ProviderCredential {
            auth_scheme: "Bearer".to_string(),
            token: "provider-secret".to_string(),
        },
        None,
        None,
    )
    .await;
    let (gateway_addr, _gateway_handle) = start_gateway(relay_addr, "gateway-token").await;
    let local_addr = free_addr().await;

    let local_handle = tokio::spawn(async move {
        trusted_relay_local::run(trusted_relay_local::RunConfig {
            listen: local_addr,
            relay_endpoint: format!("https://127.0.0.1:{}", relay_addr.port()),
            gateway_addr: Some(gateway_addr.to_string()),
            gateway_token: Some("gateway-token".to_string()),
            verifier: Arc::new(relay_attest::mock::MockVerifier),
            expected_measurement: Some(get_mock_measurement().to_vec()),
            expected_config_hash: Some(config_hash),
        })
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let response: serde_json::Value = reqwest::Client::new()
        .post(format!("http://{local_addr}/v1/chat/completions"))
        .bearer_auth("local-user-token-not-provider-key")
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(response["id"], "chatcmpl-local-proxy-test");
    assert_eq!(
        response["choices"][0]["message"]["content"],
        "ok through gateway"
    );

    local_handle.abort();
}

#[tokio::test]
async fn local_proxy_rejects_wrong_config_hash_before_forwarding() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream("Bearer provider-secret").await;
    let (relay_addr, _config_hash, _relay_handle) = start_attested_relay(
        upstream_addr,
        ProviderCredential {
            auth_scheme: "Bearer".to_string(),
            token: "provider-secret".to_string(),
        },
        None,
        None,
    )
    .await;
    let local_addr = free_addr().await;

    let local_handle = tokio::spawn(async move {
        trusted_relay_local::run(trusted_relay_local::RunConfig {
            listen: local_addr,
            relay_endpoint: format!("https://127.0.0.1:{}", relay_addr.port()),
            gateway_addr: None,
            gateway_token: None,
            verifier: Arc::new(relay_attest::mock::MockVerifier),
            expected_measurement: Some(get_mock_measurement().to_vec()),
            expected_config_hash: Some([0xFF; 32]),
        })
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{local_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);

    local_handle.abort();
}

#[tokio::test]
async fn local_proxy_rejects_relay_with_changed_trusted_measurement() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream("Bearer provider-secret").await;
    let changed_measurement = [0x42; 32];
    let (relay_addr, config_hash, _relay_handle) = start_attested_relay(
        upstream_addr,
        ProviderCredential {
            auth_scheme: "Bearer".to_string(),
            token: "provider-secret".to_string(),
        },
        Some(changed_measurement),
        None,
    )
    .await;
    let local_addr = free_addr().await;

    let local_handle = tokio::spawn(async move {
        trusted_relay_local::run(trusted_relay_local::RunConfig {
            listen: local_addr,
            relay_endpoint: format!("https://127.0.0.1:{}", relay_addr.port()),
            gateway_addr: None,
            gateway_token: None,
            verifier: Arc::new(relay_attest::mock::MockVerifier),
            expected_measurement: Some(get_mock_measurement().to_vec()),
            expected_config_hash: Some(config_hash),
        })
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{local_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);

    local_handle.abort();
}

#[tokio::test]
async fn local_proxy_rejects_relay_with_changed_release_artifact_digest() {
    let (upstream_addr, _upstream_handle) = start_mock_upstream("Bearer provider-secret").await;
    let (relay_addr, _config_hash_b, _relay_handle) = start_attested_relay(
        upstream_addr,
        ProviderCredential {
            auth_scheme: "Bearer".to_string(),
            token: "provider-secret".to_string(),
        },
        None,
        Some(ARTIFACT_DIGEST_B),
    )
    .await;

    let expected_config_hash_a = RelayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        default_upstream: format!("http://{upstream_addr}"),
        allowed_upstreams: vec![format!("http://{upstream_addr}")],
        release_artifact_digest: Some(ARTIFACT_DIGEST_A.to_string()),
        ..Default::default()
    }
    .config_hash();
    let local_addr = free_addr().await;

    let local_handle = tokio::spawn(async move {
        trusted_relay_local::run(trusted_relay_local::RunConfig {
            listen: local_addr,
            relay_endpoint: format!("https://127.0.0.1:{}", relay_addr.port()),
            gateway_addr: None,
            gateway_token: None,
            verifier: Arc::new(relay_attest::mock::MockVerifier),
            expected_measurement: Some(get_mock_measurement().to_vec()),
            expected_config_hash: Some(expected_config_hash_a),
        })
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{local_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);

    local_handle.abort();
}

#[test]
fn local_proxy_cli_requires_pins_unless_audit_is_explicit() {
    let bin = env!("CARGO_BIN_EXE_trusted-relay-local");
    let output = Command::new(bin)
        .arg("--relay-endpoint")
        .arg("https://127.0.0.1:8443")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--expected-config-hash"), "{stderr}");
}

#[test]
fn local_proxy_cli_allows_pinless_mode_only_with_audit_flag() {
    let bin = env!("CARGO_BIN_EXE_trusted-relay-local");
    let output = Command::new(bin)
        .arg("--relay-endpoint")
        .arg("https://127.0.0.1:1")
        .arg("--allow-audit")
        .arg("--listen")
        .arg("not-a-socket-addr")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required arguments were not provided"),
        "{stderr}"
    );
}

#[cfg(feature = "gcp-confidential-space")]
struct GcpCsTestKey {
    der: Vec<u8>,
    n: String,
    e: String,
}

#[cfg(feature = "gcp-confidential-space")]
fn gcp_cs_test_key() -> Arc<GcpCsTestKey> {
    use base64::Engine as _;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = private_key.as_ref();
    let der = private_key.to_pkcs1_der().unwrap();
    Arc::new(GcpCsTestKey {
        der: der.as_bytes().to_vec(),
        n: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        e: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
    })
}

#[cfg(feature = "gcp-confidential-space")]
struct GcpCsTestAttester {
    image_digest: &'static str,
    signing_key: Arc<GcpCsTestKey>,
}

#[cfg(feature = "gcp-confidential-space")]
impl Attester for GcpCsTestAttester {
    fn attest(&self, user_data: &[u8; 64]) -> Result<Evidence, relay_attest::types::AttestError> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());
        let nonces = reportdata_nonces(user_data);
        let claims = serde_json::json!({
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
                    "image_digest": self.image_digest,
                    "image_reference": "us-docker.pkg.dev/project/repo/relay:latest",
                    "restart_policy": "Never"
                },
                "gce": {"project_id": "project", "zone": "us-central1-a", "instance_name": "relay"}
            }
        });
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_der(&self.signing_key.der),
        )
        .unwrap();
        Ok(Evidence {
            tee_type: TeeType::GcpConfidentialSpace,
            data: token.into_bytes(),
        })
    }
}

#[cfg(feature = "gcp-confidential-space")]
fn gcp_cs_verifier(
    image_digest: &'static str,
    signing_key: Arc<GcpCsTestKey>,
) -> GcpConfidentialSpaceVerifier {
    let mut policy =
        GcpConfidentialSpacePolicy::strict_for_image("trusted-relay-test", image_digest);
    policy.issuer = "https://issuer.test".to_string();
    policy.jwks_uri = Some("https://issuer.test/jwks".to_string());
    policy.service_account = Some("relay@project.iam.gserviceaccount.com".to_string());
    policy.project_id = Some("project".to_string());
    let jwks = JwksSet {
        keys: vec![Jwk {
            kty: "RSA".to_string(),
            kid: "test-kid".to_string(),
            n: signing_key.n.clone(),
            e: signing_key.e.clone(),
            alg: Some("RS256".to_string()),
            key_use: None,
        }],
    };
    GcpConfidentialSpaceVerifier::with_static_jwks(policy, jwks).unwrap()
}

#[cfg(feature = "gcp-confidential-space")]
async fn start_gcp_cs_attested_relay(
    upstream_addr: SocketAddr,
    provider_credential: ProviderCredential,
    image_digest: &'static str,
    signing_key: Arc<GcpCsTestKey>,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = Arc::new(RelayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        default_upstream: format!("http://{upstream_addr}"),
        allowed_upstreams: vec![format!("http://{upstream_addr}")],
        ..Default::default()
    });
    let config_hash = config.config_hash();
    let attester = GcpCsTestAttester {
        image_digest,
        signing_key,
    };
    let tls_server = AttestedTlsServer::new(&attester, Some(&config_hash)).unwrap();
    let tls_acceptor = TlsAcceptor::from(tls_server.server_config());
    let provider_credentials = ProviderCredentialStore::new();
    provider_credentials.set(provider_credential).await;
    let state = AppState {
        config,
        http_client: reqwest::Client::new(),
        provider_credentials,
        require_provider_credential: false,
    };
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
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

#[cfg(feature = "gcp-confidential-space")]
#[tokio::test]
async fn local_proxy_rejects_changed_confidential_space_container_digest() {
    const IMAGE_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IMAGE_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (upstream_addr, _upstream_handle) = start_mock_upstream("Bearer provider-secret").await;
    let signing_key = gcp_cs_test_key();
    let (relay_addr, config_hash, _relay_handle) = start_gcp_cs_attested_relay(
        upstream_addr,
        ProviderCredential {
            auth_scheme: "Bearer".to_string(),
            token: "provider-secret".to_string(),
        },
        IMAGE_B,
        signing_key.clone(),
    )
    .await;
    let local_addr = free_addr().await;

    let local_handle = tokio::spawn(async move {
        trusted_relay_local::run(trusted_relay_local::RunConfig {
            listen: local_addr,
            relay_endpoint: format!("https://127.0.0.1:{}", relay_addr.port()),
            gateway_addr: None,
            gateway_token: None,
            verifier: Arc::new(gcp_cs_verifier(IMAGE_A, signing_key.clone())),
            expected_measurement: None,
            expected_config_hash: Some(config_hash),
        })
        .await
        .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let response = reqwest::Client::new()
        .post(format!("http://{local_addr}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    local_handle.abort();
}
