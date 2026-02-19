# CraftSEC Design Document

## Overview

CraftSEC is the trust layer of the Craftec ecosystem. It provides MPC threshold signatures for transaction attestation — every financial write must be validated and co-signed by a program running on threshold nodes. No valid signature = no valid transaction.

Not optimistic. Not consensus. Deterministic. Cryptographic.

### Key Principles

- **Programs own keys**: Distributed Key Generation (DKG) creates keypairs for program CIDs — no human has the private key
- **Threshold signing**: 2-of-3 (or t-of-n) nodes must independently validate and sign
- **Stateless execution**: Nodes load function, read CraftSQL, validate, sign, forget
- **Instant finality**: Valid MPC signature = valid transaction. No challenge periods.
- **Program-attested writes**: Every financial entry has both user signature (intent) AND program signature (correctness)

---

## Architecture

```
craftsec/
├── crates/
│   ├── core/           MPC types, threshold config, program registry
│   ├── dkg/            Distributed Key Generation (Feldman VSS / FROST)
│   ├── signing/        Threshold signing protocol (FROST Schnorr / Ed25519)
│   ├── node/           CraftSEC node — receives requests, validates, signs
│   ├── client/         SDK for submitting attestation requests
│   └── cli/            Deploy programs, manage keys, inspect attestations
└── docs/
```

---

## How It Works

### Transaction Flow

```
Alice wants to send $50 to Bob:

1. Alice's app calls CraftSEC SDK:
   attest({fn: Qm_transfer, args: {to: bob, amount: 50}})

2. SDK routes request to 3 threshold nodes (randomly selected from eligible set)

3. Each node independently:
   a. Load function from CID (cached after first load)
   b. Read Alice's balance from CraftSQL
   c. Validate: balance >= 50? sender == Alice? no double-spend?
   d. Compute output transaction entry
   e. Produce Ed25519 signature SHARE (not full signature)
   Time: ~10-50ms (it's SQL queries + signing)

4. SDK collects 2-of-3 shares → combines → full threshold signature

5. Alice writes to her chain (CraftSQL):
   {
     seq: 42,
     prev_hash: "abc...",
     sender: "did:alice",
     recipient: "did:bob",
     amount: 50,
     user_sig: <Alice's Ed25519>,          ← proves intent
     program_cid: "Qm_transfer",          ← which code ran
     program_sig: <threshold signature>,   ← proves code validated it
     hash: "def..."
   }

Total added latency: ~100ms
```

### Why Both Signatures?

```
User signature alone:    Alice can write anything (lie about balance)
Program signature alone: Program can act without Alice's consent
Both required:           Alice authorized it AND the program validated it

Neither is sufficient alone. Both are necessary.
```

---

## Program Derived Keys (PDK)

Programs own cryptographic keys. No human has access. Same concept as Solana PDAs, enforced by threshold cryptography instead of a VM runtime.

### Key Generation

```
1. Developer publishes program code → CID (e.g., Qm_transfer)
2. DKG ceremony across N threshold nodes:
   - Feldman VSS generates key shares
   - Each node holds one share of the private key
   - Full private key never exists anywhere
   - Public key = the program's identity

Program CID:  Qm_transfer
Program key:  craft1_xyz... (public, derivable, verifiable)
Key shards:   distributed across N nodes (t-of-n required to sign)
```

### Multiple Keys Per Program

Programs derive multiple keys for different purposes (like Solana PDAs with seeds):

```rust
// Main program key
let main_key = derive_key(program_cid, "main");

// Per-user escrow keys
let escrow_alice_bob = derive_key(program_cid, "escrow:alice:bob");

// Treasury key
let treasury = derive_key(program_cid, "treasury");
```

Each derived key is independently threshold-managed. Program logic decides which key signs when.

### Programs Can Hold Assets

A program key can own balances — exactly like a Solana PDA holds tokens:

```sql
-- Program's treasury balance
SELECT amount FROM balances WHERE did = 'craft1_swap_treasury';

-- Only the swap program (verified by CID) can move these funds
-- No human can access them
```

This IS: smart contract wallets, DEX liquidity pools, DAO treasuries, escrows.

---

## Distributed Key Generation (DKG)

### Protocol: Feldman VSS + FROST

```
Setup (one-time per program key):

1. Each of N nodes generates random polynomial of degree t-1
2. Each node evaluates polynomial at other nodes' indices → shares
3. Shares sent encrypted to each other node
4. Each node verifies received shares against commitments (Feldman VSS)
5. Each node sums received shares → their key shard
6. Public key = sum of all commitments' constant terms

Result:
- N nodes each hold a key shard
- Any t nodes can produce a valid signature
- Fewer than t nodes learn nothing about the key
- Full private key never exists
```

### Key Rotation (Proactive Secret Sharing)

```
Periodically:
- Re-share key shards to new set of nodes
- Old shards become useless
- Public key stays the same
- Even if attacker stole old shards → can't use them

Adds time dimension to security.
Attacker must compromise t nodes simultaneously, not over time.
```

---

## Threshold Signing

### Protocol: FROST (Flexible Round-Optimized Schnorr Threshold)

```
Signing (per transaction):

Round 1 — Commitment:
  Each signer generates nonce pair (d, e)
  Broadcasts commitment (D, E) = (g^d, g^e)

Round 2 — Signature:
  Each signer computes partial signature:
    s_i = d_i + (e_i * rho_i) + lambda_i * sk_i * challenge
  Broadcasts s_i

Aggregation:
  Requester combines partial signatures:
    S = sum(s_i), R = product(D_i * E_i^rho_i)
  Final signature: (R, S) — standard Schnorr signature

Verification:
  Anyone verifies with public key — same as single-signer Schnorr
  No one can tell it was threshold-signed
```

### Why FROST?

- 2 rounds (most threshold schemes need 3+)
- Produces standard Schnorr signatures (compatible with Ed25519 ecosystem)
- Supports pre-processing: Round 1 can happen ahead of time → signing is 1 round
- Robust against malicious signers (identifiable abort)
- Proven secure in the literature

---

## CraftSEC Node

### What It Does

```
CraftSEC node is lightweight:

Per request:
1. Receive attestation request (program CID + args)
2. Load program from CID (cached after first load)
3. Read required state from CraftSQL (network calls)
4. Execute program (SQL queries + validation logic, ~10ms)
5. If valid: produce signature share
6. Return share to requester
7. Forget everything

No persistent state. No event loop. No database.
Stateless. On-demand. Milliseconds.
```

### Program Execution

Programs are functions, not smart contracts. They:
- Read CraftSQL (any database, read-only)
- Validate business logic (balance check, authorization, etc.)
- Return: valid/invalid + output transaction data

```rust
/// What a CraftSEC program looks like
pub trait AttestationProgram {
    /// Validate and produce the transaction to be signed
    fn attest(&self, ctx: &AttestContext, args: &Value) -> Result<AttestResult>;
}

pub struct AttestContext {
    pub requester: DID,        // Who's asking
    pub program_cid: Cid,      // Which program (self)
    pub sql: SqlReader,        // Read-only CraftSQL access
}

pub enum AttestResult {
    Valid(Transaction),        // Validated — sign this
    Invalid(String),           // Rejected — reason
}
```

### What Programs CAN'T Do
- Write to CraftSQL (read-only during attestation)
- Access network (no HTTP, no sockets)
- Access filesystem
- Call other programs
- Hold state between calls

Programs are pure functions: input → validate → output. That's their entire power.

---

## Trust Model

### Three Independent Guarantees

```
1. User signature    → proves Alice authorized this transaction
2. Program validation → proves the code checked balances/rules
3. Threshold signing  → proves multiple independent nodes ran the code

All three are cryptographic. None are optimistic.
```

### Attack Resistance

```
Single malicious node:
  Can't forge signature (needs t-of-n shares)
  Can produce invalid share → detected, excluded
  Reputation penalty → removed from signer set

Compromised program:
  New CID = new program = new key
  Old program's key can be frozen
  Users verify program_cid before trusting

Collusion (t nodes):
  CAN produce valid signatures → REAL threat
  Mitigation: large n, geographically distributed, key rotation
  Same trust model as every MPC system
  Threshold > 50% makes collusion harder than 51% attack on PoS
```

### Comparison

```
Blockchain consensus:
  Every validator runs the code (thousands)
  1000x redundancy
  Same guarantee: "trusted code ran"

CraftSEC:
  3-5 threshold nodes run the code
  3-5x redundancy
  Same guarantee: "trusted code ran"
  
  1000x less redundancy. Same security property.
  The math doesn't care how many nodes you add past the threshold.
```

---

## Transaction Schema

```sql
CREATE TABLE transactions (
    seq INTEGER PRIMARY KEY,       -- monotonic sequence number
    prev_hash TEXT NOT NULL,        -- hash chain (tamper-evident)
    sender TEXT NOT NULL,           -- DID
    recipient TEXT NOT NULL,        -- DID
    amount REAL NOT NULL,
    asset TEXT DEFAULT 'USDC',
    timestamp INTEGER NOT NULL,

    -- User authorization
    user_sig TEXT NOT NULL,         -- Ed25519 signature by sender

    -- Program attestation
    program_cid TEXT NOT NULL,      -- which code validated this (immutable CID)
    program_sig TEXT NOT NULL,      -- threshold signature (unforgeable)

    -- Optional: multiple attestors for high-value tx
    attestors JSON,                -- [{cid, sig}, ...] for multi-program attestation

    hash TEXT NOT NULL              -- blake3 of everything above
);
```

### Verification by Anyone

```sql
-- Check balance consistency
SELECT SUM(CASE
    WHEN recipient = 'did:alice' THEN amount
    WHEN sender = 'did:alice' THEN -amount
END) as balance
FROM transactions
WHERE sender = 'did:alice' OR recipient = 'did:alice';

-- Find unattested entries (should return zero rows)
SELECT * FROM transactions
WHERE program_sig IS NULL
   OR program_cid NOT IN (SELECT cid FROM trusted_programs);

-- Verify hash chain integrity
SELECT a.seq, a.hash, b.prev_hash
FROM transactions a
JOIN transactions b ON b.seq = a.seq + 1
WHERE a.hash != b.prev_hash;
-- Should return zero rows
```

---

## Program Registry

### Deploying a Program

```
1. Write attestation logic (Rust → WASM)
2. Upload to CraftOBJ → get CID
3. Register with CraftSEC: triggers DKG → program gets a key
4. Program is now live: anyone can request attestation against it
```

### Program Upgrades

Programs are immutable (CID = content hash). To upgrade:

1. Deploy new version → new CID → new key
2. Migration: new program reads old program's data, validates, re-signs
3. Users update their trusted_programs list
4. Old program's key can be frozen after migration period

No silent upgrades. Every version change is visible (different CID).

### Trusted Program Lists

Each user maintains a list of program CIDs they trust:

```sql
CREATE TABLE trusted_programs (
    cid TEXT PRIMARY KEY,
    name TEXT,
    version TEXT,
    added_at INTEGER
);
```

Verifiers check `program_cid IN trusted_programs`. Unknown programs = untrusted entries.

---

## Economics

### Free Tier
- CraftSEC nodes run attestation for the network altruistically
- Same model as CraftOBJ storage — community participation
- Suitable for low-value transactions

### Paid Tier
- Pay per attestation (micro-payments via payment channels)
- Guaranteed response time SLA
- Higher threshold (5-of-7 instead of 2-of-3) for high-value tx
- Settlement via Solana

### Pricing
- Per-attestation fee (fractions of a cent)
- Fee scales with threshold size (more signers = higher cost)
- Protocol fee on every attestation (funds network)

---

## Why Not Alternatives?

```
TEE (Intel SGX):
  ✗ Trusts hardware manufacturer
  ✗ Side-channel attacks (proven repeatedly)
  ✗ Vendor lock-in
  CraftSEC: pure cryptography, no hardware trust

Optimistic / Fraud Proofs:
  ✗ Nobody checks small transactions
  ✗ Challenge periods (7 days on L1 rollups)
  ✗ Requires watchers with economic stake
  CraftSEC: every tx validated before it exists

ZK Validity Proofs:
  ✗ Heavy computation for proof generation
  ✓ Strongest mathematical guarantee
  Used at APPLICATION level for privacy (not infrastructure)
  CraftSEC: lightweight (SQL + signing), infrastructure level

Full Consensus (blockchain):
  ✗ 1000x redundancy for same guarantee
  ✗ Gas, blocks, finality delays
  CraftSEC: 3-5 nodes, same cryptographic guarantee
```

---

## Repos and Dependencies

```
craftsec depends on:
  craftec-core    — identity, crypto, P2P transport
  craftsql        — reading user chains for validation

craftsec is used by:
  craftcpu        — gateway agents use CraftSEC for threshold withdrawal signing
  applications    — any app that needs attested writes
```

---

## What CraftSEC Is NOT

| Not This | Why |
|---|---|
| Consensus protocol | No blocks, no validators, no finality gadgets |
| Smart contract VM | Programs are functions, not long-running contracts |
| Key management service | Programs own keys, not users |
| Certificate authority | No certificates — just threshold signatures on transactions |
| Oracle network | Doesn't fetch external data — validates internal state |

CraftSEC is the simplest possible trust layer: run code, check math, sign if valid.
