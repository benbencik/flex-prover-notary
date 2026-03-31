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

### 2. Start a Trusted Notary

Start the bundled notary service (terminal 1):

```bash
cargo run -p binance-pnl-notary
```

On first run it creates `notary.signing_key.hex` and prints the notary public key.
Keep this key file stable across restarts so verifiers can trust a consistent identity.

Then configure prover connection:

```bash
# .env
NOTARY_HOST=127.0.0.1
NOTARY_PORT=7047
```

### 3. Generate Proof

```bash
# Fetch trades and generate attestation (uses NOTARY_HOST/NOTARY_PORT)
cargo run -p binance-pnl-prover -- --symbol BTCUSDT --limit 100
```

This creates:
- `attestation.tlsn` - The notarized attestation
- `secrets.tlsn` - Your private keys for creating presentations

### 4. Create Presentation (Selective Disclosure)

```bash
# Create a shareable presentation with redacted credentials
cargo run -p binance-pnl-prover --bin present
```

This creates:
- `presentation.tlsn` - Shareable proof with API key redacted

### 5. Verify Proof

```bash
# Anyone can verify the presentation
cargo run -p binance-pnl-verifier -- presentation.tlsn
```

Expected output (trade proof):
```
=== TLSNotary Proof Verification ===

Notary signature algorithm: secp256k1
Notary public key: 04a1b2c3...

✓ Notary signature valid
✓ Server: api.binance.com
✓ Timestamp: 2024-01-15 14:32:01 UTC
✓ Transcript: 512 bytes sent, 4096 bytes received
✓ Request: GET /api/v3/myTrades

--- Verified Response Body ---
Number of trades: 50

--- Computed PnL (BTCUSDT) ---
Total bought:     $  12,430.20
Total sold:       $  12,862.70
Commission (USDT):$       12.50
─────────────────────────────
Net PnL:          $    +419.50 USDT ✓

--- Trade Statistics ---
Total trades:         50  (28 buys, 22 sells)
Total volume:     $  25,292.90
Avg buy size:     $     444.01
Largest buy:      $   1,200.00
Avg sell size:    $     584.67
Largest sell:     $   2,100.00
Maker / Taker:        30 /     20  (60.0% maker)

Trade period:
  From: 2024-01-01 00:00:00 UTC
  To:   2024-01-15 14:32:01 UTC

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
│                              │ (Trusted)   │               │
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
  -l, --limit <LIMIT>                Number of trades [default: 10]
      --start-time <YYYY-MM-DD>      Only include trades on/after this date (UTC)
      --end-time   <YYYY-MM-DD>      Only include trades on/before this date (UTC)
      --endpoint <ENDPOINT>          API endpoint to notarise: trades (default) | account
  -a, --attestation-output <FILE>    Output attestation [default: attestation.tlsn]
  -k, --secrets-output <FILE>        Output secrets [default: secrets.tlsn]
      --notary-host <HOST>           Notary host [default: 127.0.0.1]
      --notary-port <PORT>           Notary port [default: 7047]
      --test                         Fetch from Binance without notarisation (sanity-check)
```

#### Examples

```bash
# Prove last 50 trades for ETHUSDT
cargo run -p binance-pnl-prover -- --symbol ETHUSDT --limit 50

# Prove trades within a specific date range
cargo run -p binance-pnl-prover -- --symbol BTCUSDT --start-time 2024-01-01 --end-time 2024-03-31

# Prove your account balance snapshot
cargo run -p binance-pnl-prover -- --endpoint account
```

    ### Notary

    ```
    cargo run -p binance-pnl-notary -- [OPTIONS]

    Options:
      --bind-host <HOST>                Bind host [default: 127.0.0.1]
      --bind-port <PORT>                Bind port [default: 7047]
      --signing-key-file <FILE>         Signing key file [default: notary.signing_key.hex]
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

The verifier auto-detects the response type (trade history or account snapshot) and displays:

- **Trade history**: PnL, total volume, buy/sell counts, average/largest/smallest trade, maker/taker ratio, commission breakdown by asset, trade time range.
- **Account snapshot**: non-zero asset balances (free + locked), commission rates, account permissions.

## Security Considerations

1. **API Key Safety**: Your API key is used to make the request but is redacted from the proof. The verifier never sees it.

2. **Trusted Notary**: This prover connects to an external notary (`--notary-host`, `--notary-port`). Verifiers should only trust attestations signed by known, pinned notary keys.

3. **Hosted Notary Availability**: PSE sunset the public `notary.pse.dev` endpoint in March 2026. Run your own trusted notary service and configure `NOTARY_HOST`/`NOTARY_PORT`.

4. **Key Permissions**: Only grant "Read Info" permissions to your API key. Never enable trading or withdrawal permissions for keys used with third-party tools.

5. **Signature Redaction**: The HMAC signature in the request URL is derived from your secret key. It's also redacted in the presentation.

## Limitations

- Requires a reachable, trusted notary service.
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
