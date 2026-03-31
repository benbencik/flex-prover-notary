//! Binance PnL Verifier using TLSNotary
//!
//! This verifier reads a TLSNotary presentation and verifies that the
//! trade data genuinely came from Binance, computing the verified PnL
//! and additional trading statistics. It also supports account-balance
//! proofs produced with `--endpoint account`.

use std::collections::HashMap;
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
#[command(about = "Verify a TLSNotary proof of Binance trading data")]
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

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BinanceBalance {
    asset: String,
    free: String,
    locked: String,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BinanceAccount {
    maker_commission: Option<i64>,
    taker_commission: Option<i64>,
    buyer_commission: Option<i64>,
    seller_commission: Option<i64>,
    can_trade: Option<bool>,
    can_withdraw: Option<bool>,
    can_deposit: Option<bool>,
    update_time: Option<u64>,
    balances: Vec<BinanceBalance>,
    #[serde(default)]
    permissions: Vec<String>,
}

fn print_trade_stats(trades: &[BinanceTrade]) {
    if trades.is_empty() {
        println!("No trades found.");
        return;
    }

    let symbol = &trades[0].symbol;

    // -- basic accumulators --
    let mut total_bought: f64 = 0.0;
    let mut total_sold: f64 = 0.0;
    let mut buy_count: u32 = 0;
    let mut sell_count: u32 = 0;
    // commission by asset
    let mut commissions: HashMap<String, f64> = HashMap::new();
    // individual trade notional values (for avg / largest / smallest)
    let mut buy_notionals: Vec<f64> = Vec::new();
    let mut sell_notionals: Vec<f64> = Vec::new();

    for trade in trades {
        let quote_qty: f64 = trade.quote_qty.parse().unwrap_or(0.0);
        let commission: f64 = trade.commission.parse().unwrap_or(0.0);

        if trade.is_buyer {
            total_bought += quote_qty;
            buy_count += 1;
            buy_notionals.push(quote_qty);
        } else {
            total_sold += quote_qty;
            sell_count += 1;
            sell_notionals.push(quote_qty);
        }

        *commissions.entry(trade.commission_asset.clone()).or_default() += commission;
    }

    // Commission denominated in stablecoins → deduct from PnL
    let stable_commission: f64 = commissions
        .iter()
        .filter(|(a, _)| matches!(a.as_str(), "USDT" | "USDC" | "BUSD"))
        .map(|(_, v)| v)
        .sum();

    let total_volume = total_bought + total_sold;
    let net_pnl = total_sold - total_bought - stable_commission;

    // avg trade sizes
    let avg_buy = if buy_count > 0 {
        total_bought / buy_count as f64
    } else {
        0.0
    };
    let avg_sell = if sell_count > 0 {
        total_sold / sell_count as f64
    } else {
        0.0
    };

    // time range
    let first_time = trades.iter().map(|t| t.time).min().unwrap_or(0);
    let last_time = trades.iter().map(|t| t.time).max().unwrap_or(0);
    let first_dt = chrono::DateTime::UNIX_EPOCH + Duration::from_millis(first_time);
    let last_dt = chrono::DateTime::UNIX_EPOCH + Duration::from_millis(last_time);

    println!("\n--- Computed PnL ({}) ---", symbol);
    println!("Total bought:     ${:>12.2}", total_bought);
    println!("Total sold:       ${:>12.2}", total_sold);

    // Print stablecoin commissions deducted in PnL calculation
    for asset in ["USDT", "USDC", "BUSD"] {
        if let Some(&c) = commissions.get(asset) {
            if c > 0.0 {
                println!("Commission ({}):  ${:>12.4}", asset, c);
            }
        }
    }
    // Print non-stablecoin commissions informatively (not deducted)
    for (asset, &amount) in &commissions {
        if !matches!(asset.as_str(), "USDT" | "USDC" | "BUSD") && amount > 0.0 {
            println!("Commission ({}):    {:>12.8} (not deducted – valued separately)", asset, amount);
        }
    }

    println!("─────────────────────────────");
    if net_pnl >= 0.0 {
        println!("Net PnL:          \x1b[32m${:>+12.2} USDT ✓\x1b[0m", net_pnl);
    } else {
        println!("Net PnL:          \x1b[31m${:>+12.2} USDT\x1b[0m", net_pnl);
    }

    println!("\n--- Trade Statistics ---");
    println!(
        "Total trades:     {:>6}  ({} buys, {} sells)",
        trades.len(),
        buy_count,
        sell_count
    );
    println!("Total volume:     ${:>12.2}", total_volume);

    if buy_count > 0 {
        println!("Avg buy size:     ${:>12.2}", avg_buy);
        if let Some(max) = buy_notionals.iter().cloned().reduce(f64::max) {
            println!("Largest buy:      ${:>12.2}", max);
        }
        if let Some(min) = buy_notionals.iter().cloned().reduce(f64::min) {
            println!("Smallest buy:     ${:>12.2}", min);
        }
    }
    if sell_count > 0 {
        println!("Avg sell size:    ${:>12.2}", avg_sell);
        if let Some(max) = sell_notionals.iter().cloned().reduce(f64::max) {
            println!("Largest sell:     ${:>12.2}", max);
        }
        if let Some(min) = sell_notionals.iter().cloned().reduce(f64::min) {
            println!("Smallest sell:    ${:>12.2}", min);
        }
    }

    // Maker vs taker ratio
    let maker_count = trades.iter().filter(|t| t.is_maker).count();
    let taker_count = trades.len() - maker_count;
    println!(
        "Maker / Taker:    {:>6} / {:>6}  ({:.1}% maker)",
        maker_count,
        taker_count,
        100.0 * maker_count as f64 / trades.len() as f64
    );

    println!("\nTrade period:");
    println!("  From: {}", first_dt.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  To:   {}", last_dt.format("%Y-%m-%d %H:%M:%S UTC"));
}

fn print_account_stats(account: &BinanceAccount) {
    let non_zero: Vec<_> = account
        .balances
        .iter()
        .filter(|b| {
            let free: f64 = b.free.parse().unwrap_or(0.0);
            let locked: f64 = b.locked.parse().unwrap_or(0.0);
            free + locked > 0.0
        })
        .collect();

    println!("\n--- Account Snapshot ---");
    println!("Permissions: {}", account.permissions.join(", "));
    if let (Some(m), Some(t)) = (account.maker_commission, account.taker_commission) {
        println!("Commission rates: maker={} bps  taker={} bps", m, t);
    }
    println!("\nNon-zero balances ({}):", non_zero.len());
    println!("  {:<8}  {:>20}  {:>20}", "Asset", "Free", "Locked");
    println!("  {}", "─".repeat(52));
    for b in &non_zero {
        let free: f64 = b.free.parse().unwrap_or(0.0);
        let locked: f64 = b.locked.parse().unwrap_or(0.0);
        println!("  {:<8}  {:>20.8}  {:>20.8}", b.asset, free, locked);
    }
    if let Some(ts) = account.update_time {
        let dt = chrono::DateTime::UNIX_EPOCH + Duration::from_millis(ts);
        println!("\nSnapshot time: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
    }
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

        // Determine endpoint from the request path
        let is_account = sent_str.contains("/api/v3/account");

        if is_account {
            // Parse as account snapshot (JSON object)
            if let Some(json_start) = body.find('{') {
                let json_end = body.rfind('}').map(|i| i + 1).unwrap_or(body.len());
                let json_str = &body[json_start..json_end];

                match serde_json::from_str::<BinanceAccount>(json_str) {
                    Ok(account) => {
                        println!("\n--- Verified Response Body ---");
                        print_account_stats(&account);
                    }
                    Err(e) => {
                        println!("\n--- Response Body (raw) ---");
                        println!("{}", body);
                        println!("\nCould not parse as account data: {}", e);
                    }
                }
            } else {
                println!("\n--- Response Body ---");
                println!("{}", body);
            }
        } else {
            // Parse as trade history (JSON array)
            if let Some(json_start) = body.find('[') {
                let json_end = body.rfind(']').map(|i| i + 1).unwrap_or(body.len());
                let json_str = &body[json_start..json_end];

                match serde_json::from_str::<Vec<BinanceTrade>>(json_str) {
                    Ok(trades) => {
                        println!("\n--- Verified Response Body ---");
                        println!("Number of trades: {}", trades.len());
                        print_trade_stats(&trades);
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
    println!("\nThe above data has been cryptographically verified to have");
    println!("originated from {} at the stated time.", BINANCE_HOST);

    Ok(())
}
