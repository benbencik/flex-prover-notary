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
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::VerifierOutput,
    webpki::{CertificateDer, RootCertStore},
    Session,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

// Binance API settings
const BINANCE_HOST: &str = "api.binance.com";
const BINANCE_PORT: u16 = 443;

// TLSNotary settings - minimal limits for faster MPC
const MAX_SENT_DATA: usize = 1 << 10; // 1KB sent
const MAX_RECV_DATA: usize = 1 << 12; // 4KB received

/// User agent to use for requests
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

#[derive(Parser, Debug)]
#[command(name = "binance-pnl-prover")]
#[command(about = "Generate a TLSNotary proof of your Binance trading PnL")]
struct Args {
    /// Trading pair symbol (e.g., BTCUSDT)
    #[arg(short, long, default_value = "BTCUSDT")]
    symbol: String,

    /// Output file for the attestation
    #[arg(short, long, default_value = "attestation.tlsn")]
    attestation_output: String,

    /// Output file for the secrets (needed to create presentation)
    #[arg(short = 'k', long, default_value = "secrets.tlsn")]
    secrets_output: String,

    /// Number of trades to fetch (max 1000)
    #[arg(short, long, default_value = "10")]
    limit: u32,

    /// Test mode - just fetch from Binance without notarization
    #[arg(long)]
    test: bool,
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

    info!("Starting Binance PnL prover for {}", args.symbol);
    info!("Fetching up to {} trades", args.limit);

    // Test mode - just fetch from Binance to verify API works
    if args.test {
        info!("Running in test mode (no notarization)...");
        test_binance_api(&api_key, &secret_key, &args.symbol, args.limit).await?;
        return Ok(());
    }

    // Create duplex channel for prover-verifier communication (local notary)
    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 23);

    // Run the prover and notary concurrently
    let (prover_result, _notary_result) = tokio::try_join!(
        run_prover(prover_socket, &api_key, &secret_key, &args.symbol, args.limit),
        run_notary(notary_socket)
    )?;

    let (attestation, secrets) = prover_result;

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

    Ok(())
}

/// Test mode - just fetch from Binance without notarization
async fn test_binance_api(api_key: &str, secret_key: &str, symbol: &str, limit: u32) -> Result<()> {
    let timestamp = get_timestamp();
    let query_without_sig = format!("symbol={}&timestamp={}&limit={}", symbol, timestamp, limit);
    let signature = sign_request(&query_without_sig, secret_key);
    let full_query = format!("{}&signature={}", query_without_sig, signature);
    
    let url = format!("https://{}/api/v3/myTrades?{}", BINANCE_HOST, full_query);
    
    info!("Fetching from Binance...");
    
    let client = reqwest::Client::new();
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
    
    println!("\n=== Binance API Test Successful ===");
    println!("Received {} trades for {}", trades.len(), symbol);
    
    if !trades.is_empty() {
        let mut total_bought: f64 = 0.0;
        let mut total_sold: f64 = 0.0;
        
        for trade in &trades {
            let quote_qty: f64 = trade["quoteQty"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
            let is_buyer = trade["isBuyer"].as_bool().unwrap_or(false);
            if is_buyer {
                total_bought += quote_qty;
            } else {
                total_sold += quote_qty;
            }
        }
        
        println!("Total bought: ${:.2}", total_bought);
        println!("Total sold: ${:.2}", total_sold);
        println!("Net PnL: ${:+.2}", total_sold - total_bought);
    }
    
    println!("\nAPI credentials are working! Run without --test to generate proof.");
    
    Ok(())
}

async fn run_prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    api_key: &str,
    secret_key: &str,
    symbol: &str,
    limit: u32,
) -> Result<(Attestation, Secrets)> {
    // Build the request parameters
    let timestamp = get_timestamp();
    let query_without_sig = format!("symbol={}&timestamp={}&limit={}", symbol, timestamp, limit);
    let signature = sign_request(&query_without_sig, secret_key);
    let full_query = format!("{}&signature={}", query_without_sig, signature);
    let uri = format!("/api/v3/myTrades?{}", full_query);

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
    
    // Parse and display trade summary
    if let Ok(trades) = serde_json::from_str::<Vec<serde_json::Value>>(&body_str) {
        info!("Received {} trades", trades.len());
        
        // Calculate PnL summary
        let mut total_bought: f64 = 0.0;
        let mut total_sold: f64 = 0.0;
        
        for trade in &trades {
            let quote_qty: f64 = trade["quoteQty"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0.0);
            let is_buyer = trade["isBuyer"].as_bool().unwrap_or(false);
            
            if is_buyer {
                total_bought += quote_qty;
            } else {
                total_sold += quote_qty;
            }
        }
        
        let net_pnl = total_sold - total_bought;
        println!("\n--- Trade Summary for {} ---", symbol);
        println!("Total trades: {}", trades.len());
        println!("Total bought: ${:.2}", total_bought);
        println!("Total sold:   ${:.2}", total_sold);
        println!("Net PnL:      ${:+.2}", net_pnl);
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

async fn run_notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
) -> Result<()> {
    info!("Starting local notary...");

    // Create session with prover
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn session driver
    let driver_task = tokio::spawn(driver);

    // Build root certificate store from Mozilla roots
    let root_store = RootCertStore::mozilla();

    // Create verifier (acts as notary)
    let verifier_config = VerifierConfig::builder().root_store(root_store).build()?;

    let verifier = handle
        .new_verifier(verifier_config)?
        .commit()
        .await?
        .accept()
        .await?
        .run()
        .await?;

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    // Calculate transcript lengths
    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    // Close session and reclaim socket
    handle.close();
    let mut socket = driver_task.await??;

    // Receive attestation request
    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    // Create signing key (in production, use a real key)
    let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Log the public key for verification
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_sec1_bytes();
    info!("Notary public key: {}", hex::encode(&pubkey_bytes));

    // Build attestation config
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    // Build attestation
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: *tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    // Send attestation to prover
    let attestation_bytes = bincode::serialize(&attestation)?;
    socket.write_all(&attestation_bytes).await?;
    socket.close().await?;

    info!("Notarization complete!");

    Ok(())
}
