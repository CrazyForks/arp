//! Release artifact signing tool.
//!
//! Reads an Ed25519 seed from the `RELEASE_SIGNING_KEY` environment variable
//! (hex-encoded, 64 hex chars = 32 bytes) and signs each file argument,
//! producing a `.sig` file containing the raw 64-byte Ed25519 signature.
//!
//! Usage:
//!   RELEASE_SIGNING_KEY=<hex> cargo run --example sign -- file1 file2 ...

use ed25519_dalek::{Signer, SigningKey};

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn main() {
    let seed_hex = std::env::var("RELEASE_SIGNING_KEY")
        .expect("RELEASE_SIGNING_KEY env var required (hex-encoded 32-byte Ed25519 seed)");
    let seed_bytes = hex_decode(seed_hex.trim());
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .expect("RELEASE_SIGNING_KEY must be exactly 32 bytes (64 hex chars)");
    let signing_key = SigningKey::from_bytes(&seed);

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: RELEASE_SIGNING_KEY=<hex> sign <file1> [file2] ...");
        eprintln!();
        eprintln!(
            "Public key: {}",
            hex_encode(&signing_key.verifying_key().to_bytes())
        );
        std::process::exit(1);
    }

    for path in &args {
        let data = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Error reading {path}: {e}");
            std::process::exit(1);
        });
        let signature = signing_key.sign(&data);
        let sig_path = format!("{path}.sig");
        std::fs::write(&sig_path, signature.to_bytes()).unwrap_or_else(|e| {
            eprintln!("Error writing {sig_path}: {e}");
            std::process::exit(1);
        });
        eprintln!("Signed: {path} -> {sig_path}");
    }

    eprintln!(
        "Public key (embed in update.rs): {:?}",
        signing_key.verifying_key().to_bytes()
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
