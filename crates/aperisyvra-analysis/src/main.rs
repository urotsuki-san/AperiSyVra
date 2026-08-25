#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use aperisyvra_core::parameters::{
    CODE_LENGTH, ERROR_WEIGHT, PROFILE_NAME, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SYNDROME_BITS,
};
use aperisyvra_core::research::{decoder_scan, inspect_matrix};
use aperisyvra_core::{PublicKey, SecretKey};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aperisyvra-analysis",
    version,
    about = "Analysis tools for the AperiSyVra P1 profile"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the active parameters and a generic search-space estimate.
    Profile,
    /// Measure the P1 decoder on deterministic random errors.
    DecoderScan {
        #[arg(long, default_value_t = 1_000)]
        trials: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// Report secret row degrees and public matrix density.
    MatrixReport {
        #[arg(long)]
        secret: PathBuf,
    },
    /// Report the column-weight distribution of a public key.
    PublicReport {
        #[arg(long)]
        public: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Profile => print_profile(),
        Command::DecoderScan { trials, seed } => {
            let stats = decoder_scan(expand_seed(seed, 0x41), expand_seed(seed, 0x9d), trials)?;
            println!("profile: {PROFILE_NAME}");
            println!("trials: {}", stats.trials);
            println!("failures: {}", stats.failures);
            println!("average rounds: {:.3}", stats.average_rounds);
            println!("maximum rounds: {}", stats.maximum_rounds);
        }
        Command::MatrixReport { secret } => {
            let bytes = fs::read(&secret).with_context(|| format!("read {}", secret.display()))?;
            if bytes.len() != SECRET_KEY_BYTES {
                anyhow::bail!("unexpected secret-key length");
            }
            let key = SecretKey::from_bytes(&bytes)?;
            let report = inspect_matrix(&key)?;
            println!("profile: {PROFILE_NAME}");
            println!(
                "secret row degree: {}..{} (average {:.3})",
                report.minimum_secret_row_degree,
                report.maximum_secret_row_degree,
                report.average_secret_row_degree
            );
            println!(
                "maximum secret column overlap: {}",
                report.maximum_secret_pair_overlap
            );
            println!(
                "public column weight: average {:.3}",
                report.average_public_column_weight
            );
            println!("public density: {:.4}", report.public_density);
        }
        Command::PublicReport { public } => {
            let bytes = fs::read(&public).with_context(|| format!("read {}", public.display()))?;
            if bytes.len() != PUBLIC_KEY_BYTES {
                anyhow::bail!("unexpected public-key length");
            }
            let key = PublicKey::from_bytes(&bytes)?;
            let weights = key
                .columns()
                .iter()
                .map(|column| column.count_ones() as usize)
                .collect::<Vec<_>>();
            let minimum = weights.iter().copied().min().unwrap_or(0);
            let maximum = weights.iter().copied().max().unwrap_or(0);
            let average = weights.iter().sum::<usize>() as f64 / weights.len() as f64;
            println!("profile: {PROFILE_NAME}");
            println!("key id: {}", hex(key.id()));
            println!("public column weight: {minimum}..{maximum} (average {average:.3})");
            println!("public density: {:.4}", average / SYNDROME_BITS as f64);
        }
    }
    Ok(())
}

fn print_profile() {
    println!("profile: {PROFILE_NAME}");
    println!("code length: {CODE_LENGTH}");
    println!("syndrome bits: {SYNDROME_BITS}");
    println!("error weight: {ERROR_WEIGHT}");
    println!(
        "weight-{ERROR_WEIGHT} subsets: about 2^{:.2}",
        log2_binomial(CODE_LENGTH, ERROR_WEIGHT)
    );
    println!("status: research prototype");
}

fn log2_binomial(n: usize, k: usize) -> f64 {
    let k = k.min(n - k);
    (0..k)
        .map(|index| ((n - index) as f64).log2() - ((index + 1) as f64).log2())
        .sum()
}

fn expand_seed(value: u64, marker: u8) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for index in 0..4 {
        let word = value
            .wrapping_add((index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .rotate_left((marker as u32 + index as u32 * 11) % 64);
        output[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    output[0] ^= marker;
    output
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write to string");
    }
    output
}
