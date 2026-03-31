//! Binance PnL Prover using TLSNotary
//!
//! This prover connects to Binance API, fetches trade history,
//! and generates a cryptographic proof that can be independently verified.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};

use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;

use tlsn::{
    attestation::{
        request::{Request as AttestationRequest, RequestConfig},
        Attestation, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
    },
    connection::{HandshakeData, ServerName},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
    webpki::RootCertStore,
    Session,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

// Binance API settings
const BINANCE_HOST: &str = "api.binance.com";
const BINANCE_PORT: u16 = 443;

// TLSNotary settings
const MAX_SENT_DATA: usize = 1 << 10; // 1KB sent
const MAX_RECV_DATA: usize = 1 << 15; // 32KB received (enough for account balances or many trades)

/// User agent to use for requests
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// Binance recvWindow in milliseconds (max 60000)
const BINANCE_RECV_WINDOW_MS: u64 = 60_000;

/// Which Binance API endpoint to notarise.
#[derive(clap::ValueEnum, Debug, Clone, Default)]
enum Endpoint {
    /// Trade history for a symbol (`/api/v3/myTrades`).
    #[default]
    Trades,
    /// Full account snapshot including all asset balances (`/api/v3/account`).
    Account,
}

#[derive(Parser, Debug)]
#[command(name = "binance-pnl-prover")]
#[command(about = "Generate a TLSNotary proof of your Binance trading PnL")]
struct Args {
    /// Trading pair symbol (e.g., BTCUSDT) — only used for the `trades` endpoint
    #[arg(short, long, default_value = "BTCUSDT")]
    symbol: String,

    /// Output file for the attestation
    #[arg(short, long, default_value = "attestation.tlsn")]
    attestation_output: String,

    /// Output file for the secrets (needed to create presentation)
    #[arg(short = 'k', long, default_value = "secrets.tlsn")]
    secrets_output: String,

    /// Number of trades to fetch (max 1000) — only used for the `trades` endpoint
    #[arg(short, long, default_value = "10")]
    limit: u32,

    /// Only include trades on or after this date (YYYY-MM-DD, UTC) — `trades` endpoint only
    #[arg(long)]
    start_time: Option<String>,

    /// Only include trades on or before this date (YYYY-MM-DD, UTC) — `trades` endpoint only
    #[arg(long)]
    end_time: Option<String>,

    /// Binance API endpoint to notarise
    #[arg(long, value_enum, default_value_t = Endpoint::Trades)]
    endpoint: Endpoint,

    /// Test mode - just fetch from Binance without notarization
    #[arg(long)]
    test: bool,

    /// Notary host (trusted third-party or self-hosted notary)
    #[arg(long, env = "NOTARY_HOST", default_value = "127.0.0.1")]
    notary_host: String,

    /// Notary port
    #[arg(long, env = "NOTARY_PORT", default_value_t = 7047)]
    notary_port: u16,
}

type HmacSha256 = Hmac<Sha256>;

fn sign_request(query_string: &str, secret_key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(query_string.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

/// Parse a YYYY-MM-DD date string (UTC midnight) to a Unix millisecond timestamp.
fn parse_date_to_ms(date_str: &str) -> Result<u64> {
    let date = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .with_context(|| format!("Invalid date '{}' – expected YYYY-MM-DD", date_str))?;
    let midnight = chrono::NaiveTime::from_hms_opt(0, 0, 0).expect("midnight is always valid");
    let dt = date.and_time(midnight).and_utc();
    Ok(dt.timestamp_millis() as u64)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BinanceServerTimeResponse {
    server_time: u64,
}

async fn get_binance_server_timestamp() -> Result<u64> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("https://{}/api/v3/time", BINANCE_HOST))
        .send()
        .await
        .context("Failed to fetch Binance server time")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());
        anyhow::bail!(
            "Failed to fetch Binance server time: {} - {}",
            status,
            body
        );
    }

    let payload: BinanceServerTimeResponse = response
        .json()
        .await
        .context("Failed to parse Binance server time response")?;

    Ok(payload.server_time)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("binance_pnl_prover=info".parse()?)
                .add_directive("tlsn=debug".parse()?),
        )
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    let args = Args::parse();

    // Get API credentials
    let api_key = std::env::var("BINANCE_API_KEY")
        .context("BINANCE_API_KEY not set. Please add it to .env file")?;
    let secret_key = std::env::var("BINANCE_SECRET_KEY")
        .context("BINANCE_SECRET_KEY not set. Please add it to .env file")?;

    info!("Starting Binance PnL prover");

    // Parse optional time range
    let start_ms = args
        .start_time
        .as_deref()
        .map(parse_date_to_ms)
        .transpose()?;
    let end_ms = args
        .end_time
        .as_deref()
        .map(parse_date_to_ms)
        .transpose()?;

    // Test mode - just fetch from Binance to verify API works
    if args.test {
        info!("Running in test mode (no notarization)...");
        test_binance_api(&api_key, &secret_key, &args.endpoint, &args.symbol, args.limit, start_ms, end_ms).await?;
        return Ok(());
    }

    info!(
        "Connecting to notary at {}:{}...",
        args.notary_host, args.notary_port
    );
    let notary_socket = match tokio::net::TcpStream::connect((args.notary_host.as_str(), args.notary_port)).await {
        Ok(socket) => socket,
        Err(err) => {
            let mut message = format!(
                "Failed to connect to notary at {}:{}",
                args.notary_host, args.notary_port
            );
            if args.notary_host == "notary.pse.dev" {
                message.push_str(
                    "\n\nThe public endpoint at notary.pse.dev was sunset by PSE and may be unavailable.\nRun a trusted self-hosted notary and set NOTARY_HOST/NOTARY_PORT (or pass --notary-host/--notary-port).",
                );
            } else {
                message.push_str(
                    "\n\nEnsure your trusted notary service is running and reachable, then retry with --notary-host/--notary-port.",
                );
            }
            return Err(anyhow::Error::new(err).context(message));
        }
    };

    let (attestation, secrets) = run_prover(
        notary_socket,
        &api_key,
        &secret_key,
        &args.endpoint,
        &args.symbol,
        args.limit,
        start_ms,
        end_ms,
    )
    .await?;

    // Save attestation and secrets to disk
    tokio::fs::write(&args.attestation_output, bincode::serialize(&attestation)?).await?;
    tokio::fs::write(&args.secrets_output, bincode::serialize(&secrets)?).await?;

    println!("\n=== Notarization Complete ===");
    println!("✓ Attestation saved to: {}", args.attestation_output);
    println!("✓ Secrets saved to: {}", args.secrets_output);
    println!("\nNext steps:");
    println!("  1. Run the presenter to create a verifiable presentation:");
    println!("     cargo run -p binance-pnl-prover -- present");
    println!("  2. Share the presentation with verifiers");
    println!("  3. Verifiers can run: cargo run -p binance-pnl-verifier presentation.tlsn");
    println!("\nNote: Ensure your verifier trusts the notary public key for {}:{}", args.notary_host, args.notary_port);

    Ok(())
}

/// Test mode - just fetch from Binance without notarization
async fn test_binance_api(
    api_key: &str,
    secret_key: &str,
    endpoint: &Endpoint,
    symbol: &str,
    limit: u32,
    start_ms: Option<u64>,
    end_ms: Option<u64>,
) -> Result<()> {
    let timestamp = get_binance_server_timestamp()
        .await
        .unwrap_or_else(|_| get_timestamp());

    let client = reqwest::Client::new();

    match endpoint {
        Endpoint::Trades => {
            let mut query = format!(
                "symbol={}&timestamp={}&recvWindow={}&limit={}",
                symbol, timestamp, BINANCE_RECV_WINDOW_MS, limit
            );
            if let Some(start) = start_ms {
                query.push_str(&format!("&startTime={}", start));
            }
            if let Some(end) = end_ms {
                query.push_str(&format!("&endTime={}", end));
            }
            let signature = sign_request(&query, secret_key);
            let url = format!(
                "https://{}/api/v3/myTrades?{}&signature={}",
                BINANCE_HOST, query, signature
            );

            info!("Fetching trades from Binance...");

            let response = client
                .get(&url)
                .header("X-MBX-APIKEY", api_key)
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;

            if !status.is_success() {
                anyhow::bail!("Binance API error: {} - {}", status, body);
            }

            let trades: Vec<serde_json::Value> = serde_json::from_str(&body)?;

            println!("\n=== Binance API Test Successful (trades) ===");
            println!("Received {} trades for {}", trades.len(), symbol);

            if !trades.is_empty() {
                let mut total_bought: f64 = 0.0;
                let mut total_sold: f64 = 0.0;
                let mut total_commission: f64 = 0.0;
                let mut buy_count = 0u32;
                let mut sell_count = 0u32;

                for trade in &trades {
                    let quote_qty: f64 =
                        trade["quoteQty"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                    let commission: f64 =
                        trade["commission"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                    let commission_asset = trade["commissionAsset"].as_str().unwrap_or("");
                    let is_buyer = trade["isBuyer"].as_bool().unwrap_or(false);
                    if is_buyer {
                        total_bought += quote_qty;
                        buy_count += 1;
                    } else {
                        total_sold += quote_qty;
                        sell_count += 1;
                    }
                    if matches!(commission_asset, "USDT" | "USDC" | "BUSD") {
                        total_commission += commission;
                    }
                }

                let total_volume = total_bought + total_sold;
                let net_pnl = total_sold - total_bought - total_commission;
                println!("Total volume:    ${:.2}", total_volume);
                println!("Total bought:    ${:.2}  ({} buys)", total_bought, buy_count);
                println!("Total sold:      ${:.2}  ({} sells)", total_sold, sell_count);
                println!("Commission paid: ${:.2}", total_commission);
                println!("Net PnL:         ${:+.2}", net_pnl);
            }

            println!("\nAPI credentials are working! Run without --test to generate proof.");
        }

        Endpoint::Account => {
            let query = format!(
                "timestamp={}&recvWindow={}",
                timestamp, BINANCE_RECV_WINDOW_MS
            );
            let signature = sign_request(&query, secret_key);
            let url = format!(
                "https://{}/api/v3/account?{}&signature={}",
                BINANCE_HOST, query, signature
            );

            info!("Fetching account snapshot from Binance...");

            let response = client
                .get(&url)
                .header("X-MBX-APIKEY", api_key)
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;

            if !status.is_success() {
                anyhow::bail!("Binance API error: {} - {}", status, body);
            }

            let account: serde_json::Value = serde_json::from_str(&body)?;

            println!("\n=== Binance API Test Successful (account) ===");
            if let Some(balances) = account["balances"].as_array() {
                let non_zero: Vec<_> = balances
                    .iter()
                    .filter(|b| {
                        let free: f64 = b["free"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                        let locked: f64 =
                            b["locked"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                        free + locked > 0.0
                    })
                    .collect();
                println!("Non-zero balances ({}):", non_zero.len());
                for b in &non_zero {
                    let asset = b["asset"].as_str().unwrap_or("?");
                    let free: f64 = b["free"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                    let locked: f64 = b["locked"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                    println!("  {}: free={:.8}  locked={:.8}", asset, free, locked);
                }
            }

            println!("\nAPI credentials are working! Run without --test to generate proof.");
        }
    }

    Ok(())
}

async fn run_prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    api_key: &str,
    secret_key: &str,
    endpoint: &Endpoint,
    symbol: &str,
    limit: u32,
    start_ms: Option<u64>,
    end_ms: Option<u64>,
) -> Result<(Attestation, Secrets)> {
    // Build the request URI for the chosen endpoint
    let timestamp = get_binance_server_timestamp()
        .await
        .unwrap_or_else(|_| get_timestamp());

    let uri = match endpoint {
        Endpoint::Trades => {
            let mut query = format!(
                "symbol={}&timestamp={}&recvWindow={}&limit={}",
                symbol, timestamp, BINANCE_RECV_WINDOW_MS, limit
            );
            if let Some(start) = start_ms {
                query.push_str(&format!("&startTime={}", start));
            }
            if let Some(end) = end_ms {
                query.push_str(&format!("&endTime={}", end));
            }
            let signature = sign_request(&query, secret_key);
            format!("/api/v3/myTrades?{}&signature={}", query, signature)
        }
        Endpoint::Account => {
            let query = format!(
                "timestamp={}&recvWindow={}",
                timestamp, BINANCE_RECV_WINDOW_MS
            );
            let signature = sign_request(&query, secret_key);
            format!("/api/v3/account?{}&signature={}", query, signature)
        }
    };

    info!("Connecting to notary...");

    // Create session with the notary
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver
    let driver_task = tokio::spawn(driver);

    info!("Creating prover and setting up MPC-TLS (this may take a minute)...");

    // Create a new prover
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_recv_data(MAX_RECV_DATA)
                        .build()?,
                )
                .build()?,
        )
        .await?;

    info!("MPC-TLS setup complete. Connecting to Binance API...");

    // Connect to Binance
    let client_socket = tokio::net::TcpStream::connect((BINANCE_HOST, BINANCE_PORT)).await?;

    info!("TCP connection established. Starting TLS handshake...");

    // Build root certificate store from Mozilla roots
    let root_store = RootCertStore::mozilla();

    // Connect with TLS using the root store
    let (tls_connection, prover_fut) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(BINANCE_HOST.try_into()?))
            .root_store(root_store)
            .build()?,
        client_socket.compat(),
    )?;

    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the prover task
    let prover_task = tokio::spawn(prover_fut);

    info!("Setting up HTTP connection...");

    // Set up HTTP connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    tokio::spawn(connection);

    // Build the HTTP request
    let request = Request::builder()
        .uri(&uri)
        .method("GET")
        .header("Host", BINANCE_HOST)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity") // No compression
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .header("X-MBX-APIKEY", api_key)
        .body(Empty::<Bytes>::new())?;

    info!("Sending request to Binance...");

    // Send request
    let response = request_sender.send_request(request).await?;
    let status = response.status();

    info!("Response status: {}", status);

    if status != StatusCode::OK {
        let body = response.collect().await?.to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        anyhow::bail!("Binance API error: {} - {}", status, body_str);
    }

    // Read response body
    let body = response.collect().await?.to_bytes();
    let body_str = String::from_utf8_lossy(&body);
    
    // Parse and display a summary of the notarised data
    match endpoint {
        Endpoint::Trades => {
            if let Ok(trades) = serde_json::from_str::<Vec<serde_json::Value>>(&body_str) {
                info!("Received {} trades", trades.len());

                let mut total_bought: f64 = 0.0;
                let mut total_sold: f64 = 0.0;
                let mut buy_count = 0u32;
                let mut sell_count = 0u32;

                for trade in &trades {
                    let quote_qty: f64 = trade["quoteQty"]
                        .as_str()
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0.0);
                    let is_buyer = trade["isBuyer"].as_bool().unwrap_or(false);

                    if is_buyer {
                        total_bought += quote_qty;
                        buy_count += 1;
                    } else {
                        total_sold += quote_qty;
                        sell_count += 1;
                    }
                }

                let net_pnl = total_sold - total_bought;
                println!("\n--- Trade Summary for {} ---", symbol);
                println!("Total trades:  {} ({} buys, {} sells)", trades.len(), buy_count, sell_count);
                println!("Total volume:  ${:.2}", total_bought + total_sold);
                println!("Total bought:  ${:.2}", total_bought);
                println!("Total sold:    ${:.2}", total_sold);
                println!("Net PnL:       ${:+.2}", net_pnl);
            }
        }
        Endpoint::Account => {
            if let Ok(account) = serde_json::from_str::<serde_json::Value>(&body_str) {
                if let Some(balances) = account["balances"].as_array() {
                    let non_zero: Vec<_> = balances
                        .iter()
                        .filter(|b| {
                            let free: f64 =
                                b["free"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                            let locked: f64 =
                                b["locked"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                            free + locked > 0.0
                        })
                        .collect();
                    println!("\n--- Account Snapshot ---");
                    println!("Non-zero balances: {}", non_zero.len());
                    for b in &non_zero {
                        let asset = b["asset"].as_str().unwrap_or("?");
                        let free: f64 = b["free"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                        let locked: f64 =
                            b["locked"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                        println!("  {}: free={:.8}  locked={:.8}", asset, free, locked);
                    }
                }
            }
        }
    }

    // Wait for prover to complete
    let mut prover = prover_task.await??;

    info!("Parsing HTTP transcript...");

    // Parse HTTP transcript for structured commitments
    let transcript = HttpTranscript::parse(prover.transcript())?;

    // Commit to transcript using HTTP-aware committer
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    let transcript_commit = builder.build()?;

    // Build attestation request config
    let mut request_config_builder = RequestConfig::builder();
    request_config_builder.transcript_commit(transcript_commit);
    let request_config = request_config_builder.build()?;

    // Build prove config
    let mut prove_config_builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_config_builder.transcript_commit(config.clone());
    }
    let prove_config = prove_config_builder.build()?;

    info!("Generating proof...");

    // Generate proof
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    // Build attestation request
    let mut att_request_builder = AttestationRequest::builder(&request_config);
    att_request_builder
        .server_name(ServerName::Dns(BINANCE_HOST.try_into()?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = att_request_builder.build(&CryptoProvider::default())?;

    // Close session and reclaim socket
    handle.close();
    let mut socket = driver_task.await??;

    // Send attestation request to notary
    let request_bytes = bincode::serialize(&request)?;
    socket.write_all(&request_bytes).await?;
    socket.close().await?;

    // Receive attestation from notary
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    // Validate attestation
    let provider = CryptoProvider::default();
    request.validate(&attestation, &provider)?;

    info!("Attestation validated successfully!");

    Ok((attestation, secrets))
}

