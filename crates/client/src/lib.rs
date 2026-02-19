//! CraftSEC client SDK — routes attestation requests to threshold nodes,
//! collects signature shares, aggregates into final signature.

pub mod transport;

use craftsec_core::{
    AttestationRequest, AttestationResult, CraftSecError, Result, Transaction,
};
use craftsec_signing::{
    PartialSignature, SigningCommitment, ThresholdSignature,
    aggregate, verify,
};
use curve25519_dalek::EdwardsPoint;

pub use transport::{LocalTransport, P2pTransport};

/// Response from a node for Round 1.
pub struct Round1Response {
    pub result: AttestationResult,
    pub commitment: Option<SigningCommitment>,
}

/// Response from a node for Round 2.
pub struct Round2Response {
    pub partial: PartialSignature,
}

/// The final attested transaction with its threshold signature.
#[derive(Debug)]
pub struct AttestedTransaction {
    pub transaction: Transaction,
    pub signature: ThresholdSignature,
    pub group_public_key: EdwardsPoint,
}

impl AttestedTransaction {
    /// Verify this attestation.
    pub fn verify(&self) -> Result<()> {
        let message = self.transaction.signing_bytes();
        verify(&self.signature, &self.group_public_key, &message)
    }
}

/// Trait for node communication (abstraction for network transport).
pub trait NodeTransport {
    /// Send Round 1 request to a node, get back validation result + commitment.
    fn round1(&self, node_index: usize, request: &AttestationRequest) -> Result<Round1Response>;

    /// Send Round 2 request to a node with all commitments, get back partial signature.
    fn round2(
        &self,
        node_index: usize,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> Result<Round2Response>;
}

/// CraftSEC client — orchestrates the attestation flow.
pub struct CraftSecClient<T: NodeTransport> {
    pub transport: T,
    pub group_public_key: EdwardsPoint,
    pub threshold: u32,
    pub node_count: usize,
}

impl<T: NodeTransport> CraftSecClient<T> {
    pub fn new(transport: T, group_public_key: EdwardsPoint, threshold: u32, node_count: usize) -> Self {
        Self {
            transport,
            group_public_key,
            threshold,
            node_count,
        }
    }

    /// Run the full attestation flow.
    pub fn attest(&self, request: &AttestationRequest) -> Result<AttestedTransaction> {
        // Round 1: Send to all nodes, collect responses
        let mut valid_responses: Vec<(usize, Round1Response)> = Vec::new();
        let mut transaction: Option<Transaction> = None;

        for i in 0..self.node_count {
            match self.transport.round1(i, request) {
                Ok(resp) => {
                    if let AttestationResult::Valid(ref tx) = resp.result {
                        if transaction.is_none() {
                            transaction = Some(tx.clone());
                        }
                        valid_responses.push((i, resp));
                    }
                }
                Err(_) => continue, // Node unavailable, skip
            }

            if valid_responses.len() >= self.threshold as usize {
                break;
            }
        }

        if valid_responses.len() < self.threshold as usize {
            return Err(CraftSecError::InsufficientShares {
                have: valid_responses.len(),
                need: self.threshold as usize,
            });
        }

        let transaction = transaction.unwrap();
        let message = transaction.signing_bytes();

        // Collect commitments from responding nodes
        let commitments: Vec<SigningCommitment> = valid_responses
            .iter()
            .map(|(_, r)| r.commitment.clone().unwrap())
            .collect();

        // Round 2: Get partial signatures
        let mut partials: Vec<PartialSignature> = Vec::new();
        for &(node_idx, _) in &valid_responses {
            let resp = self.transport.round2(node_idx, &message, &commitments)?;
            partials.push(resp.partial);
        }

        // Aggregate
        let signature = aggregate(&message, &commitments, &partials);

        // Verify before returning
        verify(&signature, &self.group_public_key, &message)?;

        Ok(AttestedTransaction {
            transaction,
            signature,
            group_public_key: self.group_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use craftsec_core::ThresholdConfig;
    use craftsec_dkg::run_dkg;
    use craftsec_node::{CraftSecNode, ProgramRegistry, transfer_validator, ValidatorFn};
    use rand::rngs::OsRng;
    use std::time::Duration;

    fn make_nodes(t: u32, n: u32) -> (Vec<CraftSecNode>, EdwardsPoint) {
        let config = ThresholdConfig::new(t, n).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let gpk = key_shares[0].group_public_key;
        let nodes = key_shares
            .into_iter()
            .map(|ks| {
                let mut registry = ProgramRegistry::new();
                registry.register("Qm_transfer", Box::new(transfer_validator) as ValidatorFn);
                CraftSecNode::new(ks, registry)
            })
            .collect();
        (nodes, gpk)
    }

    #[test]
    fn full_client_flow_2_of_3() {
        let (nodes, gpk) = make_nodes(2, 3);
        let transport = LocalTransport::new(nodes);
        let client = CraftSecClient::new(transport, gpk, 2, 3);

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

        let attested = client.attest(&request).unwrap();
        attested.verify().unwrap();
        assert_eq!(attested.transaction.sender, "did:alice");
        assert_eq!(attested.transaction.recipient, "did:bob");
        assert_eq!(attested.transaction.amount, 50.0);
    }

    #[test]
    fn full_client_flow_3_of_5() {
        let (nodes, gpk) = make_nodes(3, 5);
        let transport = LocalTransport::new(nodes);
        let client = CraftSecClient::new(transport, gpk, 3, 5);

        let request = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:charlie",
                "amount": 100.0,
                "seq": 42,
                "prev_hash": "abc123",
                "timestamp": 2000
            }),
            request_id: "req-2".into(),
        };

        let attested = client.attest(&request).unwrap();
        attested.verify().unwrap();
    }

    #[test]
    fn client_rejects_invalid_request() {
        let (nodes, gpk) = make_nodes(2, 3);
        let transport = LocalTransport::new(nodes);
        let client = CraftSecClient::new(transport, gpk, 2, 3);

        let request = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:bob",
                "amount": 50.0,
                "balance": 10.0
            }),
            request_id: "req-3".into(),
        };

        assert!(client.attest(&request).is_err());
    }

    #[test]
    fn full_flow_over_p2p_transport() {
        let (nodes, gpk) = make_nodes(2, 3);
        let transport = P2pTransport::new(nodes, Duration::from_millis(5));
        let client = CraftSecClient::new(transport, gpk, 2, 3);

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
            request_id: "req-p2p-1".into(),
        };

        let attested = client.attest(&request).unwrap();
        attested.verify().unwrap();
        assert_eq!(attested.transaction.sender, "did:alice");
    }

    #[test]
    fn p2p_transport_3_of_5() {
        let (nodes, gpk) = make_nodes(3, 5);
        let transport = P2pTransport::new(nodes, Duration::from_millis(2));
        let client = CraftSecClient::new(transport, gpk, 3, 5);

        let request = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:charlie",
                "amount": 100.0,
                "seq": 42,
                "prev_hash": "abc123",
                "timestamp": 2000
            }),
            request_id: "req-p2p-2".into(),
        };

        let attested = client.attest(&request).unwrap();
        attested.verify().unwrap();
    }

    #[test]
    fn p2p_rejects_invalid() {
        let (nodes, gpk) = make_nodes(2, 3);
        let transport = P2pTransport::new(nodes, Duration::from_millis(1));
        let client = CraftSecClient::new(transport, gpk, 2, 3);

        let request = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({
                "recipient": "did:bob",
                "amount": 50.0,
                "balance": 10.0
            }),
            request_id: "req-p2p-3".into(),
        };

        assert!(client.attest(&request).is_err());
    }
}
