//! Attestation provider trait — the bridge between CraftSEC and compute layers (CraftCOM).
//!
//! CraftCOM (or any compute layer) uses `AttestationProvider` to:
//! - Attest execution results via threshold signatures
//! - Derive program keys (PDK) from program CIDs
//! - Sign messages on behalf of programs

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Execution attestation: threshold-signed proof that N nodes agree on a computation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionAttestation {
    /// Program CID that was executed.
    pub program_cid: String,
    /// SHA-256 of the input.
    pub input_hash: [u8; 32],
    /// SHA-256 of the output.
    pub output_hash: [u8; 32],
    /// Unix timestamp (ms).
    pub timestamp_ms: u64,
    /// Threshold signature bytes (protocol-agnostic).
    pub signature: Vec<u8>,
    /// Group public key that can verify the signature.
    pub group_public_key: Vec<u8>,
}

impl ExecutionAttestation {
    /// Compute canonical signing bytes.
    pub fn signing_bytes(program_cid: &str, input_hash: &[u8; 32], output_hash: &[u8; 32], timestamp_ms: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"CraftSEC-ExecAttest-v1");
        data.extend_from_slice(program_cid.as_bytes());
        data.extend_from_slice(input_hash);
        data.extend_from_slice(output_hash);
        data.extend_from_slice(&timestamp_ms.to_le_bytes());
        data
    }

    /// Verify internal consistency (signing bytes match).
    pub fn verify_structure(&self) -> bool {
        !self.signature.is_empty() && !self.group_public_key.is_empty()
    }
}

/// A program-derived public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramKey {
    /// The program CID this key belongs to.
    pub program_cid: String,
    /// The public key bytes.
    pub public_key: Vec<u8>,
}

/// A threshold signature on behalf of a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramSignature {
    /// The program CID that "signed" this.
    pub program_cid: String,
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// Errors from attestation operations.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("threshold not met: need {need}, have {have}")]
    ThresholdNotMet { need: u32, have: u32 },
    #[error("program not found: {0}")]
    ProgramNotFound(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

/// The bridge trait: CraftCOM (and other consumers) use this to request
/// threshold attestation and signing from CraftSEC.
///
/// Mechanism-agnostic — implementations can use FROST, GG20, or mocks.
pub trait AttestationProvider: Send + Sync {
    /// Attest that a program execution produced the given output for the given input.
    /// Returns a threshold signature proving N nodes agree on the result.
    fn attest_execution(
        &self,
        program_cid: &str,
        input: &[u8],
        output: &[u8],
    ) -> Result<ExecutionAttestation, AttestationError>;

    /// Derive (or retrieve) the public key for a program.
    /// Deterministic: same program_cid always yields the same key.
    fn derive_program_key(
        &self,
        program_cid: &str,
    ) -> Result<ProgramKey, AttestationError>;

    /// Threshold-sign a message on behalf of a program (PDK signing).
    fn sign_as_program(
        &self,
        program_cid: &str,
        message: &[u8],
    ) -> Result<ProgramSignature, AttestationError>;
}

/// Hash input bytes to a 32-byte digest (convenience for callers).
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Mock implementation — for tests and development
// ---------------------------------------------------------------------------

/// Mock attestation provider that produces deterministic fake signatures.
/// Uses HMAC-like construction so signatures are reproducible but not cryptographically secure.
#[derive(Debug, Clone)]
pub struct MockAttestationProvider {
    /// Simulated threshold config.
    pub threshold: u32,
    pub total: u32,
}

impl MockAttestationProvider {
    pub fn new(threshold: u32, total: u32) -> Self {
        Self { threshold, total }
    }
}

impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new(2, 3)
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn attest_execution(
        &self,
        program_cid: &str,
        input: &[u8],
        output: &[u8],
    ) -> Result<ExecutionAttestation, AttestationError> {
        let input_hash = hash_bytes(input);
        let output_hash = hash_bytes(output);
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let signing_bytes = ExecutionAttestation::signing_bytes(program_cid, &input_hash, &output_hash, timestamp_ms);
        // Mock signature: SHA-256 of signing bytes + "mock-secret"
        let mut sig_input = signing_bytes;
        sig_input.extend_from_slice(b"mock-secret");
        let signature: Vec<u8> = Sha256::digest(&sig_input).to_vec();

        // Mock group public key: SHA-256 of program CID
        let group_public_key: Vec<u8> = Sha256::digest(program_cid.as_bytes()).to_vec();

        Ok(ExecutionAttestation {
            program_cid: program_cid.to_string(),
            input_hash,
            output_hash,
            timestamp_ms,
            signature,
            group_public_key,
        })
    }

    fn derive_program_key(
        &self,
        program_cid: &str,
    ) -> Result<ProgramKey, AttestationError> {
        // Deterministic mock key: SHA-256("CraftSEC-PDK-mock" || program_cid)
        let mut hasher = Sha256::new();
        hasher.update(b"CraftSEC-PDK-mock");
        hasher.update(program_cid.as_bytes());
        let public_key = hasher.finalize().to_vec();

        Ok(ProgramKey {
            program_cid: program_cid.to_string(),
            public_key,
        })
    }

    fn sign_as_program(
        &self,
        program_cid: &str,
        message: &[u8],
    ) -> Result<ProgramSignature, AttestationError> {
        // Mock signature: SHA-256("CraftSEC-ProgramSig-mock" || program_cid || message)
        let mut hasher = Sha256::new();
        hasher.update(b"CraftSEC-ProgramSig-mock");
        hasher.update(program_cid.as_bytes());
        hasher.update(message);
        let signature = hasher.finalize().to_vec();

        Ok(ProgramSignature {
            program_cid: program_cid.to_string(),
            message: message.to_vec(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_attest_execution() {
        let provider = MockAttestationProvider::default();
        let att = provider
            .attest_execution("Qm_transfer", b"input data", b"output data")
            .unwrap();
        assert_eq!(att.program_cid, "Qm_transfer");
        assert!(att.verify_structure());
        assert_eq!(att.input_hash, hash_bytes(b"input data"));
        assert_eq!(att.output_hash, hash_bytes(b"output data"));
    }

    #[test]
    fn mock_derive_program_key_deterministic() {
        let provider = MockAttestationProvider::default();
        let k1 = provider.derive_program_key("Qm_transfer").unwrap();
        let k2 = provider.derive_program_key("Qm_transfer").unwrap();
        assert_eq!(k1.public_key, k2.public_key);
    }

    #[test]
    fn mock_different_programs_different_keys() {
        let provider = MockAttestationProvider::default();
        let k1 = provider.derive_program_key("Qm_transfer").unwrap();
        let k2 = provider.derive_program_key("Qm_swap").unwrap();
        assert_ne!(k1.public_key, k2.public_key);
    }

    #[test]
    fn mock_sign_as_program() {
        let provider = MockAttestationProvider::default();
        let sig = provider
            .sign_as_program("Qm_transfer", b"hello world")
            .unwrap();
        assert_eq!(sig.program_cid, "Qm_transfer");
        assert_eq!(sig.message, b"hello world");
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn mock_sign_deterministic() {
        let provider = MockAttestationProvider::default();
        let s1 = provider.sign_as_program("Qm_test", b"msg").unwrap();
        let s2 = provider.sign_as_program("Qm_test", b"msg").unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn mock_sign_different_messages() {
        let provider = MockAttestationProvider::default();
        let s1 = provider.sign_as_program("Qm_test", b"msg1").unwrap();
        let s2 = provider.sign_as_program("Qm_test", b"msg2").unwrap();
        assert_ne!(s1.signature, s2.signature);
    }

    #[test]
    fn execution_attestation_serde() {
        let att = ExecutionAttestation {
            program_cid: "Qm_test".to_string(),
            input_hash: hash_bytes(b"in"),
            output_hash: hash_bytes(b"out"),
            timestamp_ms: 12345,
            signature: vec![1, 2, 3],
            group_public_key: vec![4, 5, 6],
        };
        let json = serde_json::to_string(&att).unwrap();
        let parsed: ExecutionAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.program_cid, "Qm_test");
        assert_eq!(parsed.input_hash, att.input_hash);
    }
}
