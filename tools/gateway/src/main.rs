use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "trusted-relay-gateway",
    about = "Blind HTTP CONNECT gateway for private CVM relay"
)]
struct Cli {
    /// Public listen address.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: String,

    /// Private CVM relay address, for example 10.128.0.6:8443.
    #[arg(long)]
    relay_addr: String,

    /// Shared user tunnel token. This is a minimal MVP auth mechanism.
    #[arg(long, env = "TRUSTED_RELAY_GATEWAY_TOKEN")]
    token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let addr: SocketAddr = cli.listen.parse().context("invalid --listen")?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, relay_addr = %cli.relay_addr, "gateway listening");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let relay_addr = cli.relay_addr.clone();
        let token = cli.token.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &relay_addr, &token).await {
                tracing::debug!(%peer_addr, error = %e, "gateway connection closed");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    relay_addr: &str,
    expected_token: &str,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }

    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let authority = parts.next().unwrap_or_default();
    if method != "CONNECT" {
        reject(
            reader.get_mut(),
            "405 Method Not Allowed",
            "CONNECT required",
        )
        .await?;
        return Ok(());
    }

    let mut authorized = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                let value = value.trim();
                authorized = value == format!("Bearer {expected_token}");
            }
        }
    }

    if !authorized {
        reject(reader.get_mut(), "403 Forbidden", "invalid tunnel token").await?;
        return Ok(());
    }
    if authority != relay_addr {
        reject(
            reader.get_mut(),
            "403 Forbidden",
            "relay target not allowed",
        )
        .await?;
        return Ok(());
    }

    let mut relay = TcpStream::connect(relay_addr)
        .await
        .with_context(|| format!("failed to connect private relay {relay_addr}"))?;
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let mut client = reader.into_inner();
    let (from_client, from_relay) = tokio::io::copy_bidirectional(&mut client, &mut relay).await?;
    tracing::info!(from_client, from_relay, "tunnel closed");
    Ok(())
}

async fn reject(stream: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}
