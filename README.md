# Binance PnL Verifier using TLSNotary

Cryptographically prove your Binance trading PnL to third parties **without sharing your API keys**.

```
User's Binance API → TLSNotary Prover → proof.tlsn → Verifier → "PnL is +$432.50 USDT ✓"
```

## How It Works

This project uses [TLSNotary](https://tlsnotary.org/) to create cryptographic proofs of HTTPS responses. The protocol allows you to:

1. **Prove** that specific data came from Binance's API
2. **Redact** sensitive information (API keys) from the proof
3. **Share** the proof with anyone who can verify it independently

The verifier can confirm the PnL data is authentic without ever seeing your credentials.

## Prerequisites

### Using Nix (Recommended)

```bash
nix-shell
```

This sets up all dependencies automatically.

### Manual Setup

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- OpenSSL development libraries
- Clang 16+ (for WASM compilation)

On Ubuntu/Debian:
```bash
sudo apt install pkg-config libssl-dev clang
```

On macOS:
```bash
brew install openssl llvm
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
```

## Quick Start

### 1. Configure API Keys

```bash
cp .env.example .env
# Edit .env with your Binance API credentials
```

**Important:** Only enable "Read Info" permission on your API key. Do NOT enable trading!

### 2. Generate Proof

```bash
# Fetch trades and generate attestation
cargo run -p binance-pnl-prover -- --symbol BTCUSDT --limit 100
```

This creates:
- `attestation.tlsn` - The notarized attestation
- `secrets.tlsn` - Your private keys for creating presentations

### 3. Create Presentation (Selective Disclosure)

```bash
# Create a shareable presentation with redacted credentials
cargo run -p binance-pnl-prover --bin present
```

This creates:
- `presentation.tlsn` - Shareable proof with API key redacted

### 4. Verify Proof

```bash
# Anyone can verify the presentation
cargo run -p binance-pnl-verifier -- presentation.tlsn
```

Expected output:
```
=== TLSNotary Proof Verification ===

Notary signature algorithm: secp256k1
Notary public key: 04a1b2c3...

✓ Notary signature valid
✓ Server: api.binance.com
✓ Timestamp: 2024-01-15 14:32:01 UTC
✓ Transcript: 512 bytes sent, 4096 bytes received
✓ Request: GET /api/v3/myTrades

--- Computed PnL (BTCUSDT) ---
Total bought:     $  12,430.20
Total sold:       $  12,862.70
Commission paid:  $      12.50
─────────────────────────────
Net PnL:          $    +419.50 USDT ✓

✓ Verification complete!
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         PROVER                               │
│  (Your machine - has API keys)                              │
│                                                              │
│  ┌──────────┐     MPC-TLS      ┌──────────┐                │
│  │ Binance  │◄────────────────►│  Prover  │                │
│  │   API    │                  │  Binary  │                │
│  └──────────┘                  └────┬─────┘                │
│                                     │                       │
│                              ┌──────▼──────┐               │
│                              │   Notary    │               │
│                              │  (Local)    │               │
│                              └──────┬──────┘               │
│                                     │                       │
│                              ┌──────▼──────┐               │
│                              │ attestation │               │
│                              │   + secrets │               │
│                              └──────┬──────┘               │
│                                     │                       │
│                              ┌──────▼──────┐               │
│                              │ Presenter   │               │
│                              │  (redact)   │               │
│                              └──────┬──────┘               │
│                                     │                       │
│                              ┌──────▼──────┐               │
│                              │presentation │               │
│                              │   .tlsn     │◄─── Share this│
│                              └─────────────┘               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        VERIFIER                              │
│  (Anyone's machine - no keys needed)                        │
│                                                              │
│  ┌─────────────┐      ┌────────────────────────────────┐   │
│  │presentation │─────►│         Verifier Binary         │   │
│  │   .tlsn     │      │  • Check notary signature       │   │
│  └─────────────┘      │  • Verify server = binance.com  │   │
│                       │  • Parse trade data             │   │
│                       │  • Compute verified PnL         │   │
│                       └────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## CLI Options

### Prover

```
cargo run -p binance-pnl-prover -- [OPTIONS]

Options:
  -s, --symbol <SYMBOL>              Trading pair [default: BTCUSDT]
  -l, --limit <LIMIT>                Number of trades [default: 100]
  -a, --attestation-output <FILE>    Output attestation [default: attestation.tlsn]
  -k, --secrets-output <FILE>        Output secrets [default: secrets.tlsn]
```

### Presenter

```
cargo run -p binance-pnl-prover --bin present -- [OPTIONS]

Options:
  -a, --attestation <FILE>    Attestation file [default: attestation.tlsn]
  -s, --secrets <FILE>        Secrets file [default: secrets.tlsn]
  -o, --output <FILE>         Output presentation [default: presentation.tlsn]
```

### Verifier

```
cargo run -p binance-pnl-verifier -- [OPTIONS] <PRESENTATION>

Arguments:
  <PRESENTATION>    Presentation file [default: presentation.tlsn]

Options:
  -v, --verbose     Show raw transcript data
```

## Security Considerations

1. **API Key Safety**: Your API key is used to make the request but is redacted from the proof. The verifier never sees it.

2. **Local Notary**: This prototype uses a local notary. For production, use a trusted third-party notary like PSE's hosted service at `notary.pse.dev`.

3. **Key Permissions**: Only grant "Read Info" permissions to your API key. Never enable trading or withdrawal permissions for keys used with third-party tools.

4. **Signature Redaction**: The HMAC signature in the request URL is derived from your secret key. It's also redacted in the presentation.

## Limitations

- Currently uses a local notary (for development). Production use requires a trusted external notary.
- TLSNotary only supports TLS 1.2 (Binance supports this).
- Response size limited to ~16KB (configurable).

## Development

```bash
# Enter dev environment
nix-shell

# Build all crates
cargo build --release

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

## License

MIT

## Acknowledgments

- [TLSNotary](https://tlsnotary.org/) - The core protocol
- [Privacy & Scaling Explorations (PSE)](https://pse.dev/) - TLSNotary development team
