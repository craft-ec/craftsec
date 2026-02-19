//! CraftSEC threshold signing — FROST (Flexible Round-Optimized Schnorr Threshold).
//!
//! Implements threshold Ed25519 signing:
//! - Round 1: Nonce generation and commitment
//! - Round 2: Partial signature computation
//! - Aggregation: Combine partial signatures into a valid Ed25519 signature

pub mod frost;
pub mod lagrange;

pub use frost::*;
pub use lagrange::*;
