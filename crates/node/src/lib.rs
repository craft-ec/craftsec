//! CraftSEC node — holds key shares, validates attestation requests, produces signature shares.

pub mod executor;
pub mod node;

pub use executor::*;
pub use node::*;
