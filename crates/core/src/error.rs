use thiserror::Error;

#[derive(Debug, Error)]
pub enum CraftSecError {
    #[error("invalid threshold: t={t}, n={n}")]
    InvalidThreshold { t: u32, n: u32 },

    #[error("invalid share: {0}")]
    InvalidShare(String),

    #[error("invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("insufficient shares: have {have}, need {need}")]
    InsufficientShares { have: usize, need: usize },

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("program error: {0}")]
    ProgramError(String),

    #[error("program frozen: {0}")]
    ProgramFrozen(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, CraftSecError>;
