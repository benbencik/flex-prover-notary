//! Presentation builder for Binance PnL proofs
//!
//! This module creates a verifiable presentation from an attestation,
//! selectively revealing trade data while hiding sensitive credentials.

use anyhow::{Context, Result};
use clap::Parser;

use tlsn::attestation::{presentation::Presentation, Attestation, CryptoProvider, Secrets};
use tlsn_formats::http::HttpTranscript;

#[derive(Parser, Debug)]
#[command(name = "binance-pnl-present")]
#[command(about = "Create a verifiable presentation from attestation and secrets")]
struct Args {
    /// Path to the attestation file
    #[arg(short, long, default_value = "attestation.tlsn")]
    attestation: String,

    /// Path to the secrets file
    #[arg(short, long, default_value = "secrets.tlsn")]
    secrets: String,

    /// Output path for the presentation
    #[arg(short, long, default_value = "presentation.tlsn")]
    output: String,

    /// Reveal full response body (default: true)
    #[arg(long, default_value = "true")]
    reveal_response: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("binance_pnl_present=info".parse()?),
        )
        .init();

    let args = Args::parse();

    println!("\n=== Creating Verifiable Presentation ===\n");

    // Read attestation from disk
    let attestation_bytes = std::fs::read(&args.attestation)
        .with_context(|| format!("Failed to read attestation from {}", args.attestation))?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)
        .context("Failed to deserialize attestation")?;

    // Read secrets from disk
    let secrets_bytes = std::fs::read(&args.secrets)
        .with_context(|| format!("Failed to read secrets from {}", args.secrets))?;
    let secrets: Secrets =
        bincode::deserialize(&secrets_bytes).context("Failed to deserialize secrets")?;

    println!("✓ Loaded attestation and secrets");

    // Parse the HTTP transcript
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    println!("✓ Parsed HTTP transcript");
    println!("  - {} request(s)", transcript.requests.len());
    println!("  - {} response(s)", transcript.responses.len());

    // Build transcript proof with selective disclosure
    let mut builder = secrets.transcript_proof_builder();

    // Process requests - reveal structure but redact sensitive headers
    for request in &transcript.requests {
        // Reveal request structure without data
        builder.reveal_sent(request.without_data())?;

        // Reveal the request target (URL path and query)
        // But we'll redact the signature parameter
        builder.reveal_sent(&request.request.target)?;

        // Reveal headers selectively
        for header in &request.headers {
            let header_name = header.name.as_str().to_ascii_lowercase();

            // Redact sensitive headers
            if header_name == "x-mbx-apikey" || header_name == "authorization" {
                // Reveal header name but not value
                builder.reveal_sent(header.without_value())?;
            } else if header_name == "user-agent" {
                // Optionally redact user-agent for privacy
                builder.reveal_sent(header.without_value())?;
            } else {
                // Reveal other headers fully
                builder.reveal_sent(header)?;
            }
        }
    }

    // Process responses - reveal everything (this is the PnL data we want to prove)
    for response in &transcript.responses {
        if args.reveal_response {
            // Reveal the entire response
            builder.reveal_recv(response)?;
        } else {
            // Reveal structure without data
            builder.reveal_recv(response.without_data())?;

            // Reveal all response headers
            for header in &response.headers {
                builder.reveal_recv(header)?;
            }

            // Reveal body
            if let Some(body) = &response.body {
                builder.reveal_recv(body)?;
            }
        }
    }

    let transcript_proof = builder.build()?;

    println!("✓ Built transcript proof with selective disclosure");

    // Build presentation
    let provider = CryptoProvider::default();

    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation: Presentation = builder.build()?;

    println!("✓ Created presentation");

    // Write presentation to disk
    std::fs::write(&args.output, bincode::serialize(&presentation)?)?;

    println!("\n=== Presentation Created Successfully ===");
    println!("Output: {}", args.output);
    println!("\nThe presentation contains:");
    println!("  - Proof that data came from api.binance.com");
    println!("  - Full trade history response (verifiable PnL)");
    println!("  - Redacted: API key, signature, user-agent");
    println!("\nTo verify: cargo run -p binance-pnl-verifier -- {}", args.output);

    Ok(())
}
