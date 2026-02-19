//! CraftSEC node — receives requests, validates, produces signature shares.

use craftsec_core::{
    AttestationRequest, AttestationResult, CraftSecError, KeyShare, Result,
};
use craftsec_signing::{
    SigningCommitment, SigningNonce, PartialSignature,
    generate_nonces, sign_partial,
};
use crate::executor::ProgramRegistry;
use crate::wasm_executor::WasmProgramRegistry;
use std::collections::{HashMap, HashSet};

/// Trait for program execution backends.
pub trait ProgramExecutor {
    fn execute(&self, request: &AttestationRequest) -> Result<AttestationResult>;
}

impl ProgramExecutor for ProgramRegistry {
    fn execute(&self, request: &AttestationRequest) -> Result<AttestationResult> {
        ProgramRegistry::execute(self, request)
    }
}

impl ProgramExecutor for WasmProgramRegistry {
    fn execute(&self, request: &AttestationRequest) -> Result<AttestationResult> {
        WasmProgramRegistry::execute(self, request)
    }
}

/// A CraftSEC threshold node.
pub struct CraftSecNode<E: ProgramExecutor = ProgramRegistry> {
    /// This node's key shares, keyed by program CID.
    pub key_shares: HashMap<String, KeyShare>,
    /// Default key share (for backwards compat / single-program mode).
    pub key_share: KeyShare,
    /// Program executor for validation.
    pub registry: E,
    /// Frozen programs — attestation refused for these CIDs.
    pub frozen_programs: HashSet<String>,
}

/// Result of processing an attestation request at a node.
#[derive(Debug)]
pub struct NodeResponse {
    /// The attestation result (valid/invalid).
    pub result: AttestationResult,
    /// If valid: the signing commitment for this node.
    pub commitment: Option<SigningCommitment>,
    /// If valid: the nonce (kept secret, used in round 2).
    pub nonce: Option<SigningNonce>,
}

/// Result of round 2 at a node.
pub struct NodeSignature {
    pub partial: PartialSignature,
}

impl<E: ProgramExecutor> CraftSecNode<E> {
    pub fn new(key_share: KeyShare, registry: E) -> Self {
        Self {
            key_shares: HashMap::new(),
            key_share,
            registry,
            frozen_programs: HashSet::new(),
        }
    }

    /// Register a key share for a specific program CID.
    pub fn register_key(&mut self, program_cid: impl Into<String>, key_share: KeyShare) {
        self.key_shares.insert(program_cid.into(), key_share);
    }

    /// Freeze a program — refuse future attestations for this CID.
    pub fn freeze_program(&mut self, program_cid: impl Into<String>) {
        self.frozen_programs.insert(program_cid.into());
    }

    /// Check if a program is frozen.
    pub fn is_frozen(&self, program_cid: &str) -> bool {
        self.frozen_programs.contains(program_cid)
    }

    /// Get the key share for a program CID (falls back to default).
    fn get_key_share(&self, program_cid: &str) -> &KeyShare {
        self.key_shares.get(program_cid).unwrap_or(&self.key_share)
    }

    /// Round 1: Validate request and produce commitment.
    pub fn process_request(
        &self,
        request: &AttestationRequest,
        rng: &mut impl rand::RngCore,
    ) -> Result<NodeResponse> {
        // Check if program is frozen
        if self.is_frozen(&request.program_cid) {
            return Err(CraftSecError::ProgramFrozen(request.program_cid.clone()));
        }

        let result = self.registry.execute(request)?;

        match &result {
            AttestationResult::Valid(_) => {
                let ks = self.get_key_share(&request.program_cid);
                let (nonce, commitment) = generate_nonces(ks.index, rng);
                Ok(NodeResponse {
                    result,
                    commitment: Some(commitment),
                    nonce: Some(nonce),
                })
            }
            AttestationResult::Invalid(_) => Ok(NodeResponse {
                result,
                commitment: None,
                nonce: None,
            }),
        }
    }

    /// Round 2: Produce partial signature given all commitments.
    pub fn sign(
        &self,
        nonce: &SigningNonce,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> Result<NodeSignature> {
        let partial = sign_partial(&self.key_share, nonce, message, commitments)?;
        Ok(NodeSignature { partial })
    }

    /// Round 2: Sign with a specific program's key share.
    pub fn sign_for_program(
        &self,
        program_cid: &str,
        nonce: &SigningNonce,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> Result<NodeSignature> {
        let ks = self.get_key_share(program_cid);
        let partial = sign_partial(ks, nonce, message, commitments)?;
        Ok(NodeSignature { partial })
    }
}

/// Migrate a program's key from old CID to new CID on a node.
/// The old program is frozen after migration.
pub fn migrate_program<E: ProgramExecutor>(
    node: &mut CraftSecNode<E>,
    old_cid: &str,
    new_cid: &str,
) {
    let key_share = node.get_key_share(old_cid).clone();
    node.register_key(new_cid, key_share);
    node.freeze_program(old_cid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{transfer_validator, ValidatorFn};
    use craftsec_core::ThresholdConfig;
    use craftsec_dkg::run_dkg;
    use craftsec_core::MultiAttestationRequest;
    use craftsec_signing::{aggregate, verify};
    use rand::rngs::OsRng;

    fn setup_nodes(t: u32, n: u32) -> Vec<CraftSecNode> {
        let config = ThresholdConfig::new(t, n).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();

        key_shares
            .into_iter()
            .map(|ks| {
                let mut registry = ProgramRegistry::new();
                registry.register(
                    "Qm_transfer",
                    Box::new(transfer_validator) as ValidatorFn,
                );
                CraftSecNode::new(ks, registry)
            })
            .collect()
    }

    #[test]
    fn end_to_end_attestation_2_of_3() {
        let nodes = setup_nodes(2, 3);
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

        let signers = &[0usize, 1];

        let mut responses: Vec<NodeResponse> = Vec::new();
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

        let commitments: Vec<SigningCommitment> = responses
            .iter()
            .map(|r| r.commitment.clone().unwrap())
            .collect();

        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let nonce = responses[idx].nonce.as_ref().unwrap();
            let sig = nodes[i].sign(nonce, &message, &commitments).unwrap();
            partials.push(sig.partial);
        }

        let threshold_sig = aggregate(&message, &commitments, &partials);
        verify(&threshold_sig, &nodes[0].key_share.group_public_key, &message).unwrap();
    }

    #[test]
    fn attestation_rejected_insufficient_balance() {
        let nodes = setup_nodes(2, 3);
        let request = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:bob",
                "amount": 50.0,
                "balance": 10.0
            }),
            request_id: "req-2".into(),
        };

        let resp = nodes[0].process_request(&request, &mut OsRng).unwrap();
        assert!(matches!(resp.result, AttestationResult::Invalid(_)));
        assert!(resp.commitment.is_none());
    }

    #[test]
    fn frozen_program_rejected() {
        let mut nodes = setup_nodes(2, 3);
        nodes[0].freeze_program("Qm_transfer");

        let request = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({"recipient": "did:bob", "amount": 50.0}),
            request_id: "req-3".into(),
        };

        let err = nodes[0].process_request(&request, &mut OsRng).unwrap_err();
        assert!(matches!(err, CraftSecError::ProgramFrozen(_)));
    }

    #[test]
    fn migrate_program_transfers_key_and_freezes_old() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let gpk = key_shares[0].group_public_key;

        let mut nodes: Vec<CraftSecNode> = key_shares
            .into_iter()
            .map(|ks| {
                let mut registry = ProgramRegistry::new();
                registry.register("Qm_transfer_v1", Box::new(transfer_validator) as ValidatorFn);
                registry.register("Qm_transfer_v2", Box::new(transfer_validator) as ValidatorFn);
                let mut node = CraftSecNode::new(ks.clone(), registry);
                node.register_key("Qm_transfer_v1", ks);
                node
            })
            .collect();

        // Migrate v1 -> v2
        for node in &mut nodes {
            migrate_program(node, "Qm_transfer_v1", "Qm_transfer_v2");
        }

        // v1 is frozen
        assert!(nodes[0].is_frozen("Qm_transfer_v1"));

        // v1 attestation should fail
        let req_v1 = AttestationRequest {
            program_cid: "Qm_transfer_v1".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({"recipient": "did:bob", "amount": 50.0}),
            request_id: "req-v1".into(),
        };
        assert!(nodes[0].process_request(&req_v1, &mut OsRng).is_err());

        // v2 attestation should work with same key
        let req_v2 = AttestationRequest {
            program_cid: "Qm_transfer_v2".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:bob", "amount": 50.0,
                "seq": 1, "prev_hash": "0000", "timestamp": 1000
            }),
            request_id: "req-v2".into(),
        };

        let signers = &[0usize, 1];
        let mut responses = Vec::new();
        for &i in signers {
            let resp = nodes[i].process_request(&req_v2, &mut OsRng).unwrap();
            responses.push(resp);
        }

        let tx = match &responses[0].result {
            AttestationResult::Valid(tx) => tx,
            _ => unreachable!(),
        };
        let message = tx.signing_bytes();
        let commitments: Vec<_> = responses.iter().map(|r| r.commitment.clone().unwrap()).collect();

        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let nonce = responses[idx].nonce.as_ref().unwrap();
            let sig = nodes[i].sign_for_program("Qm_transfer_v2", nonce, &message, &commitments).unwrap();
            partials.push(sig.partial);
        }

        let threshold_sig = aggregate(&message, &commitments, &partials);
        // v2 uses the same key as v1 — verify against original gpk
        verify(&threshold_sig, &gpk, &message).unwrap();
    }

    #[test]
    fn multi_program_all_accept() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();

        let nodes: Vec<CraftSecNode> = key_shares
            .into_iter()
            .map(|ks| {
                let mut registry = ProgramRegistry::new();
                registry.register("Qm_transfer", Box::new(transfer_validator) as ValidatorFn);
                // Compliance validator that always accepts
                registry.register("Qm_compliance", Box::new(|req: &AttestationRequest| {
                    transfer_validator(req)
                }) as ValidatorFn);
                CraftSecNode::new(ks, registry)
            })
            .collect();

        let multi_req = MultiAttestationRequest {
            program_cids: vec!["Qm_transfer".into(), "Qm_compliance".into()],
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:bob", "amount": 50.0,
                "seq": 1, "prev_hash": "0000", "timestamp": 1000
            }),
            request_id: "multi-1".into(),
        };

        // Each program must validate independently on each node
        let individual = multi_req.to_individual_requests();
        for req in &individual {
            for node in &nodes {
                let resp = node.process_request(req, &mut OsRng).unwrap();
                assert!(matches!(resp.result, AttestationResult::Valid(_)));
            }
        }
    }

    #[test]
    fn receipt_with_threshold_signature() {
        use craftsec_core::AttestationReceipt;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let gpk = key_shares[0].group_public_key;

        let mut receipt = AttestationReceipt::new(
            "Qm_transfer".into(),
            b"{\"amount\":50}",
            b"{\"status\":\"valid\"}",
            1706000000,
        );
        let message = receipt.signing_bytes();

        let signers = &[0usize, 1];
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &i in signers {
            let (n, c) = craftsec_signing::generate_nonces(key_shares[i].index, &mut OsRng);
            nonces.push(n);
            commitments.push(c);
        }

        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let p = craftsec_signing::sign_partial(&key_shares[i], &nonces[idx], &message, &commitments).unwrap();
            partials.push(p);
        }

        let sig = aggregate(&message, &commitments, &partials);
        let sig_bytes = [
            sig.r.compress().as_bytes().as_slice(),
            sig.s.as_bytes().as_slice(),
        ].concat();
        receipt.add_signature(0, hex::encode(&sig_bytes));

        verify(&sig, &gpk, &message).unwrap();
        assert!(receipt.verify_signatures());

        // Tamper detection
        let mut tampered = receipt.clone();
        tampered.timestamp = 9999;
        assert_ne!(receipt.signing_bytes(), tampered.signing_bytes());
    }

    #[test]
    fn multi_program_one_rejects() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();

        let nodes: Vec<CraftSecNode> = key_shares
            .into_iter()
            .map(|ks| {
                let mut registry = ProgramRegistry::new();
                registry.register("Qm_transfer", Box::new(transfer_validator) as ValidatorFn);
                // Compliance validator that always rejects
                registry.register("Qm_compliance", Box::new(|_req: &AttestationRequest| {
                    Ok(AttestationResult::Invalid("compliance check failed".into()))
                }) as ValidatorFn);
                CraftSecNode::new(ks, registry)
            })
            .collect();

        let multi_req = MultiAttestationRequest {
            program_cids: vec!["Qm_transfer".into(), "Qm_compliance".into()],
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:bob", "amount": 50.0,
                "seq": 1, "prev_hash": "0000", "timestamp": 1000
            }),
            request_id: "multi-2".into(),
        };

        // Check that compliance rejection causes overall rejection
        let individual = multi_req.to_individual_requests();
        let mut any_rejected = false;
        for req in &individual {
            let resp = nodes[0].process_request(req, &mut OsRng).unwrap();
            if matches!(resp.result, AttestationResult::Invalid(_)) {
                any_rejected = true;
            }
        }
        assert!(any_rejected, "at least one program should reject");
    }
}
