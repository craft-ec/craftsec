//! Core types for CraftSEC MPC threshold attestation.

use curve25519_dalek::{EdwardsPoint, Scalar};
use serde::{Deserialize, Serialize};

/// Threshold configuration (t-of-n).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum signers required.
    pub threshold: u32,
    /// Total number of participants.
    pub total: u32,
}

impl ThresholdConfig {
    pub fn new(threshold: u32, total: u32) -> crate::Result<Self> {
        if threshold == 0 || threshold > total {
            return Err(crate::CraftSecError::InvalidThreshold {
                t: threshold,
                n: total,
            });
        }
        Ok(Self { threshold, total })
    }
}

/// A participant's index (1-based).
pub type ParticipantIndex = u32;

/// A key share held by one participant.
#[derive(Debug, Clone)]
pub struct KeyShare {
    /// Participant index (1-based).
    pub index: ParticipantIndex,
    /// The secret share (scalar).
    pub secret: Scalar,
    /// The group public key.
    pub group_public_key: EdwardsPoint,
    /// Per-participant public keys (verification shares): Y_i = s_i * G
    pub verification_shares: Vec<(ParticipantIndex, EdwardsPoint)>,
}

/// An attestation request from a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRequest {
    /// The program CID to execute.
    pub program_cid: String,
    /// The requester's DID.
    pub requester: String,
    /// Program arguments (JSON).
    pub args: serde_json::Value,
    /// Unique request ID.
    pub request_id: String,
}

/// Result of program attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationResult {
    /// Program validated — here's the transaction to sign.
    Valid(Transaction),
    /// Program rejected the request.
    Invalid(String),
}

/// A transaction to be attested (signed by the threshold group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub seq: u64,
    pub prev_hash: String,
    pub sender: String,
    pub recipient: String,
    pub amount: f64,
    pub asset: String,
    pub timestamp: u64,
    pub program_cid: String,
    /// User's Ed25519 signature (hex-encoded).
    pub user_sig: String,
}

impl Transaction {
    /// Compute the canonical bytes for signing.
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Deterministic JSON serialization for signing
        serde_json::to_vec(self).expect("transaction serialization cannot fail")
    }
}

/// A program specification in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramSpec {
    /// Content ID of the program.
    pub cid: String,
    /// Human-readable name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Threshold config for this program's key.
    pub threshold: ThresholdConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_config_valid() {
        assert!(ThresholdConfig::new(2, 3).is_ok());
        assert!(ThresholdConfig::new(3, 5).is_ok());
        assert!(ThresholdConfig::new(1, 1).is_ok());
    }

    #[test]
    fn threshold_config_invalid() {
        assert!(ThresholdConfig::new(0, 3).is_err());
        assert!(ThresholdConfig::new(4, 3).is_err());
    }

    #[test]
    fn transaction_signing_bytes_deterministic() {
        let tx = Transaction {
            seq: 1,
            prev_hash: "abc".into(),
            sender: "did:alice".into(),
            recipient: "did:bob".into(),
            amount: 50.0,
            asset: "USDC".into(),
            timestamp: 1000,
            program_cid: "Qm_transfer".into(),
            user_sig: "deadbeef".into(),
        };
        assert_eq!(tx.signing_bytes(), tx.signing_bytes());
    }

    #[test]
    fn attestation_request_serde() {
        let req = AttestationRequest {
            program_cid: "Qm_test".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({"amount": 50}),
            request_id: "req-1".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let _: AttestationRequest = serde_json::from_str(&json).unwrap();
    }
}
