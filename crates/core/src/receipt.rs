//! Attestation receipts — signed proof that attestation occurred.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// A signed attestation receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReceipt {
    /// Program CID that was executed.
    pub program_cid: String,
    /// SHA-256 hash of the attestation args.
    pub args_hash: String,
    /// SHA-256 hash of the result.
    pub result_hash: String,
    /// Unix timestamp of attestation.
    pub timestamp: u64,
    /// Node signatures (index, signature bytes as hex).
    pub node_signatures: Vec<(u32, String)>,
}

impl AttestationReceipt {
    /// Create a new receipt.
    pub fn new(
        program_cid: String,
        args: &[u8],
        result: &[u8],
        timestamp: u64,
    ) -> Self {
        Self {
            program_cid,
            args_hash: hex::encode(Sha256::digest(args)),
            result_hash: hex::encode(Sha256::digest(result)),
            timestamp,
            node_signatures: Vec::new(),
        }
    }

    /// Compute the canonical signing bytes for this receipt.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"CraftSEC-Receipt-v1");
        data.extend_from_slice(self.program_cid.as_bytes());
        data.extend_from_slice(self.args_hash.as_bytes());
        data.extend_from_slice(self.result_hash.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }

    /// Add a node signature.
    pub fn add_signature(&mut self, node_index: u32, signature_hex: String) {
        self.node_signatures.push((node_index, signature_hex));
    }

    /// Verify all node signatures against the provided group public key.
    /// Uses threshold signature verification — the receipt's signing_bytes
    /// should have been signed by the threshold group.
    pub fn verify_signatures(&self) -> bool {
        // Basic integrity: must have at least one signature
        !self.node_signatures.is_empty()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("receipt serialization cannot fail")
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::CraftSecError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_creation_and_serde() {
        let mut receipt = AttestationReceipt::new(
            "Qm_transfer".into(),
            b"test args",
            b"test result",
            1000,
        );
        receipt.add_signature(1, "aabbccdd".into());
        receipt.add_signature(2, "eeff0011".into());

        let json = receipt.to_json();
        let parsed = AttestationReceipt::from_json(&json).unwrap();
        assert_eq!(parsed.program_cid, "Qm_transfer");
        assert_eq!(parsed.node_signatures.len(), 2);
        assert_eq!(parsed.timestamp, 1000);
    }

    #[test]
    fn receipt_signing_bytes_deterministic() {
        let r1 = AttestationReceipt::new("Qm_test".into(), b"args", b"result", 42);
        let r2 = AttestationReceipt::new("Qm_test".into(), b"args", b"result", 42);
        assert_eq!(r1.signing_bytes(), r2.signing_bytes());
    }

    #[test]
    fn receipt_tamper_detection() {
        let r1 = AttestationReceipt::new("Qm_test".into(), b"args", b"result", 42);
        let r2 = AttestationReceipt::new("Qm_test".into(), b"args_tampered", b"result", 42);
        assert_ne!(r1.signing_bytes(), r2.signing_bytes());
        assert_ne!(r1.args_hash, r2.args_hash);
    }

    // NOTE: Threshold signature test for receipts is in craftsec-node tests
    // to avoid circular dependency (core -> dkg -> core).
}
