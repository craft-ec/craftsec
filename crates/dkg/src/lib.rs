//! CraftSEC Distributed Key Generation — Feldman VSS.
//!
//! Implements verifiable secret sharing where each participant generates
//! a random polynomial, distributes shares, and the group derives a
//! shared public key without any party knowing the full private key.

pub mod feldman;
pub mod pdk;
pub mod polynomial;

pub use feldman::*;
pub use pdk::*;
pub use polynomial::*;
