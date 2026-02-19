# CLAUDE.md — CraftSEC

## Architecture

```
craftsec/
├── crates/
│   ├── core/       Types, errors, receipts (ThresholdConfig, KeyShare, AttestationRequest, etc.)
│   ├── dkg/        Feldman VSS, PDK (Program Derived Keys), key rotation
│   ├── signing/    FROST threshold signing (Ed25519), Lagrange interpolation
│   ├── node/       CraftSEC node — validates requests, produces signature shares
│   ├── client/     SDK — orchestrates attestation flow (Local + P2P transport)
│   └── cli/        CLI — deploy, attest, keys, freeze, info, verify-receipt
├── examples/
│   └── transfer-validator/  WASM attestation program example
└── docs/
    └── CRAFTSEC_DESIGN.md
```

## Phase Status

- **Phase 1** ✅: Core types, DKG (Feldman VSS), FROST signing, node, client
- **Phase 2** ✅: WASM execution (wasmtime), PDK, P2P transport stub
- **Phase 3** ✅: Key rotation, multi-program attestation, program freeze/migration, CLI, receipts

## Key Concepts

- **Key Rotation**: `rotate_shares()` in `dkg/rotation.rs` — proactive secret sharing, zero-polynomial addition
- **Multi-Program**: `MultiAttestationRequest` with `Vec<ProgramCid>` — all must validate independently
- **Program Freeze**: `CraftSecNode.frozen_programs: HashSet` — refuses attestation for frozen CIDs
- **Migration**: `migrate_program(node, old_cid, new_cid)` — transfers key, freezes old
- **Receipts**: `AttestationReceipt` — program_cid, args_hash, result_hash, timestamp, node_signatures

## Build & Test

```bash
cargo test --workspace
cargo clippy --workspace
cargo run --bin craftsec -- deploy transfer.wasm
cargo run --bin craftsec -- attest <cid> '{"recipient":"did:bob","amount":50}'
```

## Dependencies

- curve25519-dalek (Ed25519), sha2, wasmtime, rusqlite, clap, serde
