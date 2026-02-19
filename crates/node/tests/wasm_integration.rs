//! Integration tests for WASM program execution.

use craftsec_core::{AttestationRequest, AttestationResult, ThresholdConfig};
use craftsec_dkg::run_dkg;
use craftsec_node::{WasmProgramRegistry, CraftSecNode};
use craftsec_signing::{aggregate, verify};
use rand::rngs::OsRng;

const WASM_BYTES: &[u8] = include_bytes!(
    "../../../examples/transfer-validator/wasm/transfer_validator.wasm"
);

fn make_wasm_registry() -> WasmProgramRegistry {
    let mut registry = WasmProgramRegistry::new();
    registry.register_wasm("Qm_transfer", WASM_BYTES).unwrap();
    registry.setup_database("balances", "
        CREATE TABLE accounts (did TEXT PRIMARY KEY, balance REAL);
        INSERT INTO accounts VALUES ('did:alice', 1000.0);
        INSERT INTO accounts VALUES ('did:bob', 500.0);
        INSERT INTO accounts VALUES ('did:charlie', 0.0);
    ").unwrap();
    registry
}

#[test]
fn wasm_valid_transfer() {
    let registry = make_wasm_registry();
    let request = AttestationRequest {
        program_cid: "Qm_transfer".into(),
        requester: "did:alice".into(),
        args: serde_json::json!({
            "recipient": "did:bob",
            "amount": 50.0,
            "seq": 1,
            "prev_hash": "0000",
            "timestamp": 1000
        }),
        request_id: "req-1".into(),
    };

    let result = registry.execute(&request).unwrap();
    match result {
        AttestationResult::Valid(tx) => {
            assert_eq!(tx.sender, "did:alice");
            assert_eq!(tx.recipient, "did:bob");
            assert_eq!(tx.amount, 50.0);
        }
        AttestationResult::Invalid(reason) => panic!("expected valid, got invalid: {reason}"),
    }
}

#[test]
fn wasm_insufficient_balance() {
    let registry = make_wasm_registry();
    let request = AttestationRequest {
        program_cid: "Qm_transfer".into(),
        requester: "did:alice".into(),
        args: serde_json::json!({
            "recipient": "did:bob",
            "amount": 5000.0,
        }),
        request_id: "req-2".into(),
    };

    let result = registry.execute(&request).unwrap();
    assert!(matches!(result, AttestationResult::Invalid(ref r) if r.contains("insufficient")));
}

#[test]
fn wasm_negative_amount() {
    let registry = make_wasm_registry();
    let request = AttestationRequest {
        program_cid: "Qm_transfer".into(),
        requester: "did:alice".into(),
        args: serde_json::json!({
            "recipient": "did:bob",
            "amount": -10.0,
        }),
        request_id: "req-3".into(),
    };

    let result = registry.execute(&request).unwrap();
    assert!(matches!(result, AttestationResult::Invalid(ref r) if r.contains("positive")));
}

#[test]
fn wasm_recipient_not_found() {
    let registry = make_wasm_registry();
    let request = AttestationRequest {
        program_cid: "Qm_transfer".into(),
        requester: "did:alice".into(),
        args: serde_json::json!({
            "recipient": "did:nonexistent",
            "amount": 10.0,
        }),
        request_id: "req-4".into(),
    };

    let result = registry.execute(&request).unwrap();
    assert!(matches!(result, AttestationResult::Invalid(ref r) if r.contains("recipient")));
}

#[test]
fn wasm_full_attestation_flow_2_of_3() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let key_shares = run_dkg(&config, &mut OsRng).unwrap();
    let gpk = key_shares[0].group_public_key;

    // Each node gets its own WASM registry (they share the same DB state for testing)
    let nodes: Vec<_> = key_shares
        .into_iter()
        .map(|ks| {
            let registry = make_wasm_registry();
            CraftSecNode::new(ks, registry)
        })
        .collect();

    let request = AttestationRequest {
        program_cid: "Qm_transfer".into(),
        requester: "did:alice".into(),
        args: serde_json::json!({
            "recipient": "did:bob",
            "amount": 50.0,
            "seq": 1,
            "prev_hash": "0000",
            "timestamp": 1000
        }),
        request_id: "req-5".into(),
    };

    // Round 1
    let signers = &[0usize, 1];
    let mut responses = Vec::new();
    for &i in signers {
        let resp = nodes[i].process_request(&request, &mut OsRng).unwrap();
        assert!(matches!(resp.result, AttestationResult::Valid(_)));
        responses.push(resp);
    }

    let tx = match &responses[0].result {
        AttestationResult::Valid(tx) => tx,
        _ => unreachable!(),
    };
    let message = tx.signing_bytes();

    let commitments: Vec<_> = responses.iter().map(|r| r.commitment.clone().unwrap()).collect();

    // Round 2
    let mut partials = Vec::new();
    for (idx, &i) in signers.iter().enumerate() {
        let nonce = responses[idx].nonce.as_ref().unwrap();
        let sig = nodes[i].sign(nonce, &message, &commitments).unwrap();
        partials.push(sig.partial);
    }

    let threshold_sig = aggregate(&message, &commitments, &partials);
    verify(&threshold_sig, &gpk, &message).unwrap();
}
