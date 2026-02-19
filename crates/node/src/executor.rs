//! Program executor — validates attestation requests.
//!
//! For Phase 1: simple Rust function registry. WASM execution comes later.

use craftsec_core::{AttestationRequest, AttestationResult, CraftSecError, Result, Transaction};
use std::collections::HashMap;

/// A validation function that checks a request and produces a transaction.
pub type ValidatorFn = Box<dyn Fn(&AttestationRequest) -> Result<AttestationResult> + Send + Sync>;

/// Registry of program validators.
pub struct ProgramRegistry {
    programs: HashMap<String, ValidatorFn>,
}

impl ProgramRegistry {
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
        }
    }

    /// Register a program validator for a given CID.
    pub fn register(&mut self, cid: impl Into<String>, validator: ValidatorFn) {
        self.programs.insert(cid.into(), validator);
    }

    /// Execute a program against an attestation request.
    pub fn execute(&self, request: &AttestationRequest) -> Result<AttestationResult> {
        let validator = self.programs.get(&request.program_cid).ok_or_else(|| {
            CraftSecError::ProgramError(format!(
                "unknown program CID: {}",
                request.program_cid
            ))
        })?;
        validator(request)
    }
}

impl Default for ProgramRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple transfer validator for testing.
pub fn transfer_validator(request: &AttestationRequest) -> Result<AttestationResult> {
    let args = &request.args;

    let recipient = args["recipient"]
        .as_str()
        .ok_or_else(|| CraftSecError::ProgramError("missing recipient".into()))?;
    let amount = args["amount"]
        .as_f64()
        .ok_or_else(|| CraftSecError::ProgramError("missing amount".into()))?;

    if amount <= 0.0 {
        return Ok(AttestationResult::Invalid("amount must be positive".into()));
    }

    // Simulated balance check
    let balance = args.get("balance").and_then(|b| b.as_f64()).unwrap_or(1000.0);
    if amount > balance {
        return Ok(AttestationResult::Invalid("insufficient balance".into()));
    }

    Ok(AttestationResult::Valid(Transaction {
        seq: args.get("seq").and_then(|s| s.as_u64()).unwrap_or(1),
        prev_hash: args
            .get("prev_hash")
            .and_then(|h| h.as_str())
            .unwrap_or("0000")
            .to_string(),
        sender: request.requester.clone(),
        recipient: recipient.to_string(),
        amount,
        asset: args
            .get("asset")
            .and_then(|a| a.as_str())
            .unwrap_or("USDC")
            .to_string(),
        timestamp: args.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0),
        program_cid: request.program_cid.clone(),
        user_sig: args
            .get("user_sig")
            .and_then(|s| s.as_str())
            .unwrap_or("placeholder")
            .to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_valid() {
        let req = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({"recipient": "did:bob", "amount": 50.0}),
            request_id: "req-1".into(),
        };
        let result = transfer_validator(&req).unwrap();
        assert!(matches!(result, AttestationResult::Valid(_)));
    }

    #[test]
    fn transfer_insufficient_balance() {
        let req = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({"recipient": "did:bob", "amount": 50.0, "balance": 10.0}),
            request_id: "req-1".into(),
        };
        let result = transfer_validator(&req).unwrap();
        assert!(matches!(result, AttestationResult::Invalid(_)));
    }

    #[test]
    fn transfer_negative_amount() {
        let req = AttestationRequest {
            program_cid: "Qm_transfer".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({"recipient": "did:bob", "amount": -10.0}),
            request_id: "req-1".into(),
        };
        let result = transfer_validator(&req).unwrap();
        assert!(matches!(result, AttestationResult::Invalid(_)));
    }

    #[test]
    fn registry_unknown_program() {
        let registry = ProgramRegistry::new();
        let req = AttestationRequest {
            program_cid: "Qm_unknown".into(),
            requester: "did:alice".into(),
            args: serde_json::json!({}),
            request_id: "req-1".into(),
        };
        assert!(registry.execute(&req).is_err());
    }
}
