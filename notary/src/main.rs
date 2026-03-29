use std::{
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::Parser;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use k256::ecdsa::SigningKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{error, info};

use tlsn::{
    attestation::{
        request::Request as AttestationRequest,
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider,
    },
    config::verifier::VerifierConfig,
    connection::{ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::VerifierOutput,
    webpki::RootCertStore,
    Session,
};

#[derive(Parser, Debug)]
#[command(name = "binance-pnl-notary")]
#[command(about = "Run a trusted notary service for Binance PnL proofs")]
struct Args {
    /// Bind host for the notary TCP server
    #[arg(long, env = "NOTARY_BIND_HOST", default_value = "127.0.0.1")]
    bind_host: String,

    /// Bind port for the notary TCP server
    #[arg(long, env = "NOTARY_BIND_PORT", default_value_t = 7047)]
    bind_port: u16,

    /// File containing a 32-byte secp256k1 signing key in hex
    #[arg(long, env = "NOTARY_SIGNING_KEY_FILE", default_value = "notary.signing_key.hex")]
    signing_key_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("binance_pnl_notary=info".parse()?),
        )
        .init();

    let args = Args::parse();

    let signing_key_bytes = load_or_create_signing_key(&args.signing_key_file)?;
    let signing_key = SigningKey::from_bytes((&signing_key_bytes).into())
        .context("Invalid notary signing key bytes")?;
    let pubkey = signing_key.verifying_key().to_encoded_point(false);

    info!(
        "Notary signing public key (pin this in verifier policy): {}",
        hex::encode(pubkey.as_bytes())
    );

    let listener = tokio::net::TcpListener::bind((args.bind_host.as_str(), args.bind_port))
        .await
        .with_context(|| {
            format!(
                "Failed to bind notary server to {}:{}",
                args.bind_host, args.bind_port
            )
        })?;

    info!(
        "Notary listening on {}:{}",
        args.bind_host, args.bind_port
    );

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let signing_key_bytes = signing_key_bytes;
        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, signing_key_bytes).await {
                error!("Notarization failed for {}: {:#}", peer_addr, err);
            } else {
                info!("Notarization completed for {}", peer_addr);
            }
        });
    }
}

fn load_or_create_signing_key(path: &PathBuf) -> Result<[u8; 32]> {
    if path.exists() {
        let key_hex = fs::read_to_string(path)
            .with_context(|| format!("Failed to read key file {}", path.display()))?;
        return parse_key_hex(key_hex.trim());
    }

    let key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
    let key_hex = hex::encode(key.to_bytes());

    fs::write(path, format!("{}\n", key_hex))
        .with_context(|| format!("Failed to write key file {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    info!(
        "Created new notary signing key at {}. Keep this file secret and stable.",
        path.display()
    );

    parse_key_hex(&key_hex)
}

fn parse_key_hex(key_hex: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(key_hex).context("Notary key file is not valid hex")?;
    if raw.len() != 32 {
        anyhow::bail!(
            "Notary key must be exactly 32 bytes (64 hex chars), got {} bytes",
            raw.len()
        );
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

async fn handle_connection<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    signing_key_bytes: [u8; 32],
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    let driver_task = tokio::spawn(driver);

    let root_store = RootCertStore::mozilla();
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

    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    let signer = Box::new(Secp256k1Signer::new(&signing_key_bytes)?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

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

    let attestation_bytes = bincode::serialize(&attestation)?;
    socket.write_all(&attestation_bytes).await?;
    socket.close().await?;

    Ok(())
}
