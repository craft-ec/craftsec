//! CraftSEC node — receives requests, validates, produces signature shares.

use craftsec_core::{
    AttestationRequest, AttestationResult, KeyShare, Result,
};
use craftsec_signing::{
    SigningCommitment, SigningNonce, PartialSignature,
    generate_nonces, sign_partial,
};
use crate::executor::ProgramRegistry;
use crate::wasm_executor::WasmProgramRegistry;

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
    /// This node's key share.
    pub key_share: KeyShare,
    /// Program executor for validation.
    pub registry: E,
}

/// Result of processing an attestation request at a node.
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
        Self { key_share, registry }
    }

    /// Round 1: Validate request and produce commitment.
    pub fn process_request(
        &self,
        request: &AttestationRequest,
        rng: &mut impl rand::RngCore,
    ) -> Result<NodeResponse> {
        let result = self.registry.execute(request)?;

        match &result {
            AttestationResult::Valid(_) => {
                let (nonce, commitment) = generate_nonces(self.key_share.index, rng);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{transfer_validator, ValidatorFn};
    use craftsec_core::ThresholdConfig;
    use craftsec_dkg::run_dkg;
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

        // Use nodes 0 and 1 as signers
        let signers = &[0usize, 1];

        // Round 1: Each signer validates and produces commitment
        let mut responses: Vec<NodeResponse> = Vec::new();
        for &i in signers {
            let resp = nodes[i].process_request(&request, &mut OsRng).unwrap();
            assert!(matches!(resp.result, AttestationResult::Valid(_)));
            responses.push(resp);
        }

        // Extract the transaction to sign
        let tx = match &responses[0].result {
            AttestationResult::Valid(tx) => tx,
            _ => unreachable!(),
        };
        let message = tx.signing_bytes();

        // Collect commitments
        let commitments: Vec<SigningCommitment> = responses
            .iter()
            .map(|r| r.commitment.clone().unwrap())
            .collect();

        // Round 2: Each signer produces partial signature
        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let nonce = responses[idx].nonce.as_ref().unwrap();
            let sig = nodes[i].sign(nonce, &message, &commitments).unwrap();
            partials.push(sig.partial);
        }

        // Aggregate
        let threshold_sig = aggregate(&message, &commitments, &partials);

        // Verify
        verify(
            &threshold_sig,
            &nodes[0].key_share.group_public_key,
            &message,
        )
        .unwrap();
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
}
