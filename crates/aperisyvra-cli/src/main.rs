#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use aperisyvra_core::parameters::{
    CIPHERTEXT_BYTES, PROFILE_NAME, PUBLIC_KEY_BYTES, SEALED_HEADER_BYTES, SECRET_KEY_BYTES,
};
use aperisyvra_core::{
    decapsulate, encapsulate, generate_keypair, open, seal, Ciphertext, PublicKey, SealedMessage,
    SecretKey,
};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(
    name = "aperisyvra",
    version,
    about = "AperiSyVra P1 command-line tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a public and secret keypair.
    Keygen {
        #[arg(long, default_value = "aperisyvra.avpk")]
        public: PathBuf,
        #[arg(long, default_value = "aperisyvra.avsk")]
        secret: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Encapsulate a 32-byte shared secret.
    Encapsulate {
        #[arg(long)]
        public: PathBuf,
        #[arg(long, default_value = "shared.avct")]
        ciphertext: PathBuf,
        #[arg(long, default_value = "sender.shared")]
        shared: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Recover a shared secret from a ciphertext.
    Decapsulate {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        ciphertext: PathBuf,
        #[arg(long, default_value = "receiver.shared")]
        shared: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Encrypt and authenticate a message file.
    Seal {
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Decrypt and authenticate a sealed message.
    Open {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Show metadata for a key, KEM ciphertext, or sealed message.
    Inspect { input: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen {
            public,
            secret,
            force,
        } => {
            let (public_key, secret_key) = generate_keypair(&mut OsRng)?;
            write_output(&public, &public_key.to_bytes(), force)?;
            write_output(&secret, &secret_key.to_bytes(), force)?;
            println!("profile: {PROFILE_NAME}");
            println!("public key: {}", public.display());
            println!("secret key: {}", secret.display());
            println!("key id: {}", hex(public_key.id()));
        }
        Command::Encapsulate {
            public,
            ciphertext,
            shared,
            force,
        } => {
            let public_key = PublicKey::from_bytes(&read_exact(&public, PUBLIC_KEY_BYTES)?)?;
            let (capsule, shared_secret) = encapsulate(&public_key, &mut OsRng);
            write_output(&ciphertext, &capsule.to_bytes(), force)?;
            write_output(&shared, shared_secret.as_bytes(), force)?;
            println!("ciphertext: {}", ciphertext.display());
            println!("shared secret: {}", shared.display());
        }
        Command::Decapsulate {
            secret,
            ciphertext,
            shared,
            force,
        } => {
            let secret_key = SecretKey::from_bytes(&read_exact(&secret, SECRET_KEY_BYTES)?)?;
            let capsule = Ciphertext::from_bytes(&read_exact(&ciphertext, CIPHERTEXT_BYTES)?)?;
            let shared_secret = decapsulate(&secret_key, &capsule)?;
            write_output(&shared, shared_secret.as_bytes(), force)?;
            println!("shared secret: {}", shared.display());
        }
        Command::Seal {
            public,
            input,
            output,
            force,
        } => {
            let public_key = PublicKey::from_bytes(&read_exact(&public, PUBLIC_KEY_BYTES)?)?;
            let plaintext =
                fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            let message = seal(&public_key, &plaintext, &mut OsRng)?;
            write_output(&output, &message.to_bytes(), force)?;
            println!("sealed message: {}", output.display());
        }
        Command::Open {
            secret,
            input,
            output,
            force,
        } => {
            let secret_key = SecretKey::from_bytes(&read_exact(&secret, SECRET_KEY_BYTES)?)?;
            let encoded = fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            let message = SealedMessage::from_bytes(&encoded)?;
            let plaintext = open(&secret_key, &message)?;
            write_output(&output, &plaintext, force)?;
            println!("plaintext: {}", output.display());
        }
        Command::Inspect { input } => inspect(&input)?,
    }
    Ok(())
}

fn inspect(path: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    println!("file: {}", path.display());
    println!("profile: {PROFILE_NAME}");

    if bytes.len() == PUBLIC_KEY_BYTES {
        let key = PublicKey::from_bytes(&bytes)?;
        println!("type: public key");
        println!("key id: {}", hex(key.id()));
        println!("columns: {}", key.columns().len());
        return Ok(());
    }
    if bytes.len() == SECRET_KEY_BYTES {
        let key = SecretKey::from_bytes(&bytes)?;
        let public = key.public_key()?;
        println!("type: secret key");
        println!("key id: {}", hex(public.id()));
        return Ok(());
    }
    if bytes.len() == CIPHERTEXT_BYTES {
        let ciphertext = Ciphertext::from_bytes(&bytes)?;
        println!("type: KEM ciphertext");
        println!("key id: {}", hex(ciphertext.public_key_id()));
        return Ok(());
    }
    if bytes.len() >= SEALED_HEADER_BYTES {
        let message = SealedMessage::from_bytes(&bytes)?;
        println!("type: sealed message");
        println!("key id: {}", hex(message.recipient_id()));
        println!("plaintext bytes: {}", message.plaintext_len());
        return Ok(());
    }

    bail!("unrecognized AperiSyVra file")
}

fn read_exact(path: &Path, expected: usize) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != expected {
        bail!(
            "{} has {} bytes; expected {}",
            path.display(),
            bytes.len(),
            expected
        );
    }
    Ok(bytes)
}

fn write_output(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            path.display()
        );
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write to string");
    }
    output
}
