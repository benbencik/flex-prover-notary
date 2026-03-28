//! Binance PnL Verifier using TLSNotary
//!
//! This verifier reads a TLSNotary presentation and verifies that the
//! trade data genuinely came from Binance, computing the verified PnL.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        signing::VerifyingKey,
        CryptoProvider,
    },
    connection::ServerName,
};

/// Expected Binance API host for verification
const BINANCE_HOST: &str = "api.binance.com";

#[derive(Parser, Debug)]
#[command(name = "binance-pnl-verifier")]
#[command(about = "Verify a TLSNotary proof of Binance trading PnL")]
struct Args {
    /// Path to the presentation file
    #[arg(default_value = "presentation.tlsn")]
    presentation: String,

    /// Show raw transcript data
    #[arg(short, long)]
    verbose: bool,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BinanceTrade {
    symbol: String,
    id: u64,
    #[serde(default)]
    order_id: u64,
    price: String,
    qty: String,
    quote_qty: String,
    commission: String,
    commission_asset: String,
    time: u64,
    is_buyer: bool,
    is_maker: bool,
    #[serde(default)]
    is_best_match: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("binance_pnl_verifier=info".parse()?),
        )
        .init();

    let args = Args::parse();

    println!("\n=== TLSNotary Proof Verification ===\n");

    // Read presentation from disk
    let presentation_bytes = std::fs::read(&args.presentation)
        .with_context(|| format!("Failed to read presentation from {}", args.presentation))?;

    let presentation: Presentation = bincode::deserialize(&presentation_bytes)
        .context("Failed to deserialize presentation")?;

    // Get the verifying key info
    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();

    println!("Notary signature algorithm: {}", alg);
    println!("Notary public key: {}", hex::encode(key_data));
    println!("\n⚠️  IMPORTANT: Verify this key belongs to a trusted notary!\n");

    // Use default crypto provider for verification
    let crypto_provider = CryptoProvider::default();

    // Verify the presentation
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .verify(&crypto_provider)
        .context("Presentation verification failed")?;

    println!("✓ Notary signature valid");

    // Verify server name
    let server_name = server_name.context("Server name not revealed")?;
    let ServerName::Dns(dns_name) = &server_name;
    if dns_name.as_str() != BINANCE_HOST {
        anyhow::bail!(
            "Server name mismatch: expected {}, got {}",
            BINANCE_HOST,
            dns_name.as_str()
        );
    }
    println!("✓ Server: {}", dns_name.as_str());

    // Get connection info
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    println!("✓ Timestamp: {}", time.format("%Y-%m-%d %H:%M:%S UTC"));
    println!(
        "✓ Transcript: {} bytes sent, {} bytes received",
        connection_info.transcript_length.sent, connection_info.transcript_length.received
    );

    // Get and process transcript
    let mut partial_transcript = transcript.context("Transcript not revealed in presentation")?;

    // Set unauthed bytes to be visible
    partial_transcript.set_unauthed(b'X');

    let sent = partial_transcript.sent_unsafe();
    let recv = partial_transcript.received_unsafe();

    // Extract HTTP method and path from request
    let sent_str = String::from_utf8_lossy(sent);
    if let Some(first_line) = sent_str.lines().next() {
        println!("✓ Request: {}", first_line.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
    }

    if args.verbose {
        println!("\n--- Raw Request (redacted parts shown as X) ---");
        println!("{}", sent_str);
    }

    // Parse the response
    let recv_str = String::from_utf8_lossy(recv);

    if args.verbose {
        println!("\n--- Raw Response (redacted parts shown as X) ---");
        println!("{}", recv_str);
    }

    // Try to extract and parse the JSON body from the response
    // HTTP response format: headers\r\n\r\nbody
    let body_start = recv_str.find("\r\n\r\n").map(|i| i + 4);

    if let Some(start) = body_start {
        let body = &recv_str[start..];

        // Find JSON array in body (might have trailing data)
        if let Some(json_start) = body.find('[') {
            let json_end = body.rfind(']').map(|i| i + 1).unwrap_or(body.len());
            let json_str = &body[json_start..json_end];

            match serde_json::from_str::<Vec<BinanceTrade>>(json_str) {
                Ok(trades) => {
                    println!("\n--- Verified Response Body ---");
                    println!("Number of trades: {}", trades.len());

                    if !trades.is_empty() {
                        let symbol = &trades[0].symbol;

                        // Calculate PnL
                        let mut total_bought: f64 = 0.0;
                        let mut total_sold: f64 = 0.0;
                        let mut total_commission: f64 = 0.0;

                        for trade in &trades {
                            let quote_qty: f64 = trade.quote_qty.parse().unwrap_or(0.0);
                            let commission: f64 = trade.commission.parse().unwrap_or(0.0);

                            if trade.is_buyer {
                                total_bought += quote_qty;
                            } else {
                                total_sold += quote_qty;
                            }

                            // Only count commission if it's in a stablecoin
                            if trade.commission_asset == "USDT"
                                || trade.commission_asset == "USDC"
                                || trade.commission_asset == "BUSD"
                            {
                                total_commission += commission;
                            }
                        }

                        let net_pnl = total_sold - total_bought - total_commission;

                        println!("\n--- Computed PnL ({}) ---", symbol);
                        println!("Total bought:     ${:>12.2}", total_bought);
                        println!("Total sold:       ${:>12.2}", total_sold);
                        println!("Commission paid:  ${:>12.2}", total_commission);
                        println!("─────────────────────────────");

                        if net_pnl >= 0.0 {
                            println!("Net PnL:          \x1b[32m${:>+12.2} USDT ✓\x1b[0m", net_pnl);
                        } else {
                            println!("Net PnL:          \x1b[31m${:>+12.2} USDT\x1b[0m", net_pnl);
                        }

                        // Show trade time range
                        let first_time = trades.iter().map(|t| t.time).min().unwrap_or(0);
                        let last_time = trades.iter().map(|t| t.time).max().unwrap_or(0);
                        let first_dt =
                            chrono::DateTime::UNIX_EPOCH + Duration::from_millis(first_time);
                        let last_dt =
                            chrono::DateTime::UNIX_EPOCH + Duration::from_millis(last_time);

                        println!("\nTrade period:");
                        println!(
                            "  From: {}",
                            first_dt.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                        println!(
                            "  To:   {}",
                            last_dt.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
                Err(e) => {
                    println!("\n--- Response Body (raw) ---");
                    println!("{}", body);
                    if body.contains('X') {
                        println!("\nNote: Parts of the response were redacted (shown as X)");
                    }
                    println!("\nCould not parse as trade data: {}", e);
                }
            }
        } else {
            println!("\n--- Response Body ---");
            println!("{}", body);
        }
    }

    // Show redaction summary
    let sent_redacted = sent.iter().filter(|&&b| b == b'X' || b == 0).count();
    let recv_redacted = recv.iter().filter(|&&b| b == b'X' || b == 0).count();

    if sent_redacted > 0 || recv_redacted > 0 {
        println!("\n--- Redaction Summary ---");
        if sent_redacted > 0 {
            println!("Request: {} bytes redacted (API key, signature)", sent_redacted);
        }
        if recv_redacted > 0 {
            println!("Response: {} bytes redacted", recv_redacted);
        }
    }

    println!("\n✓ Verification complete!");
    println!("\nThe above PnL data has been cryptographically verified to have");
    println!("originated from {} at the stated time.", BINANCE_HOST);

    Ok(())
}
