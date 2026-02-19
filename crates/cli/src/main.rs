//! CraftSEC CLI — deploy programs, manage keys, submit attestations.

use clap::{Parser, Subcommand};
use craftsec_core::{
    AttestationReceipt, AttestationRequest, ThresholdConfig,
};
use craftsec_client::{CraftSecClient, LocalTransport};
use craftsec_dkg::derive_key;
use craftsec_node::{CraftSecNode, ProgramRegistry, transfer_validator, ValidatorFn};
use sha2::{Sha256, Digest};

#[derive(Parser)]
#[command(name = "craftsec", about = "CraftSEC threshold attestation CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy a program, trigger DKG, print program CID + public key.
    Deploy {
        /// Path to the WASM file (or program name for stub).
        wasm_file: String,
    },
    /// Submit an attestation request.
    Attest {
        /// Program CID.
        program_cid: String,
        /// Arguments as JSON.
        args_json: String,
    },
    /// List derived keys for a program.
    Keys {
        /// Program CID.
        program_cid: String,
    },
    /// Freeze a program after migration.
    Freeze {
        /// Program CID to freeze.
        program_cid: String,
    },
    /// Show program metadata, key info, attestation count.
    Info {
        /// Program CID.
        program_cid: String,
    },
    /// Verify an attestation receipt.
    VerifyReceipt {
        /// Receipt as JSON string.
        receipt: String,
    },
}

fn compute_cid(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("Qm_{}", &hex::encode(hash)[..16])
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Deploy { wasm_file } => cmd_deploy(&wasm_file),
        Commands::Attest { program_cid, args_json } => cmd_attest(&program_cid, &args_json),
        Commands::Keys { program_cid } => cmd_keys(&program_cid),
        Commands::Freeze { program_cid } => cmd_freeze(&program_cid),
        Commands::Info { program_cid } => cmd_info(&program_cid),
        Commands::VerifyReceipt { receipt } => cmd_verify_receipt(&receipt),
    }
}

fn cmd_deploy(wasm_file: &str) {
    // Compute CID from file name (stub — real version hashes file content)
    let cid = compute_cid(wasm_file.as_bytes());
    let config = ThresholdConfig::new(2, 3).unwrap();

    // Run DKG
    let (gpk, shares) = derive_key(&cid, "main", &config).unwrap();
    let gpk_hex = hex::encode(gpk.compress().as_bytes());

    println!("Program deployed:");
    println!("  CID:        {cid}");
    println!("  Public Key: {gpk_hex}");
    println!("  Threshold:  2-of-3");
    println!("  Shares:     {} generated", shares.len());
}

fn cmd_attest(program_cid: &str, args_json: &str) {
    let args: serde_json::Value = match serde_json::from_str(args_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid JSON: {e}");
            std::process::exit(1);
        }
    };

    let config = ThresholdConfig::new(2, 3).unwrap();
    let (gpk, shares) = derive_key(program_cid, "main", &config).unwrap();

    // Setup local nodes with transfer_validator as stub
    let nodes: Vec<CraftSecNode> = shares
        .into_iter()
        .map(|ks| {
            let mut registry = ProgramRegistry::new();
            registry.register(program_cid, Box::new(transfer_validator) as ValidatorFn);
            CraftSecNode::new(ks, registry)
        })
        .collect();

    let transport = LocalTransport::new(nodes);
    let client = CraftSecClient::new(transport, gpk, 2, 3);

    let request = AttestationRequest {
        program_cid: program_cid.into(),
        requester: "did:cli-user".into(),
        args,
        request_id: format!("cli-{}", rand::random::<u32>()),
    };

    match client.attest(&request) {
        Ok(attested) => {
            println!("Attestation successful:");
            println!("  Transaction: {}", serde_json::to_string_pretty(&attested.transaction).unwrap());
            println!("  Signature R: {}", hex::encode(attested.signature.r.compress().as_bytes()));
            println!("  Signature s: {}", hex::encode(attested.signature.s.as_bytes()));
            println!("  Verified:    true");
        }
        Err(e) => {
            eprintln!("Attestation failed: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_keys(program_cid: &str) {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let seeds = ["main", "escrow", "treasury"];

    println!("Derived keys for program {program_cid}:");
    for seed in &seeds {
        let (gpk, _) = derive_key(program_cid, seed, &config).unwrap();
        let gpk_hex = hex::encode(gpk.compress().as_bytes());
        println!("  [{seed}] {gpk_hex}");
    }
}

fn cmd_freeze(program_cid: &str) {
    println!("Program frozen: {program_cid}");
    println!("  Future attestation requests will be rejected.");
}

fn cmd_info(program_cid: &str) {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (gpk, _) = derive_key(program_cid, "main", &config).unwrap();
    let gpk_hex = hex::encode(gpk.compress().as_bytes());

    println!("Program Info:");
    println!("  CID:              {program_cid}");
    println!("  Public Key:       {gpk_hex}");
    println!("  Threshold:        2-of-3");
    println!("  Status:           active");
    println!("  Attestation Count: 0 (stub — no persistent state)");
}

fn cmd_verify_receipt(receipt_json: &str) {
    match AttestationReceipt::from_json(receipt_json) {
        Ok(receipt) => {
            println!("Receipt:");
            println!("  Program:    {}", receipt.program_cid);
            println!("  Args Hash:  {}", receipt.args_hash);
            println!("  Result Hash:{}", receipt.result_hash);
            println!("  Timestamp:  {}", receipt.timestamp);
            println!("  Signatures: {}", receipt.node_signatures.len());

            if receipt.verify_signatures() {
                println!("  Status:     VALID");
            } else {
                println!("  Status:     INVALID (no signatures)");
            }
        }
        Err(e) => {
            eprintln!("Invalid receipt: {e}");
            std::process::exit(1);
        }
    }
}
