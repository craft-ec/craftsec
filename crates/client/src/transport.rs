//! Transport implementations for CraftSEC client.

use crate::{NodeTransport, Round1Response, Round2Response};
use craftsec_core::{AttestationRequest, Result};
use craftsec_node::{CraftSecNode, ProgramExecutor};
use craftsec_signing::SigningCommitment;
use rand::rngs::OsRng;
use std::cell::RefCell;
use std::time::Duration;
use std::thread;

/// In-memory transport that directly calls nodes (no network).
pub struct LocalTransport<E: ProgramExecutor> {
    pub nodes: Vec<CraftSecNode<E>>,
    nonces: RefCell<Vec<Option<craftsec_signing::SigningNonce>>>,
}

impl<E: ProgramExecutor> LocalTransport<E> {
    pub fn new(nodes: Vec<CraftSecNode<E>>) -> Self {
        let n = nodes.len();
        Self {
            nodes,
            nonces: RefCell::new(vec![None; n]),
        }
    }
}

impl<E: ProgramExecutor> NodeTransport for LocalTransport<E> {
    fn round1(&self, node_index: usize, request: &AttestationRequest) -> Result<Round1Response> {
        let resp = self.nodes[node_index].process_request(request, &mut OsRng)?;
        self.nonces.borrow_mut()[node_index] = resp.nonce;
        Ok(Round1Response {
            result: resp.result,
            commitment: resp.commitment,
        })
    }

    fn round2(
        &self,
        node_index: usize,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> Result<Round2Response> {
        let nonce = self.nonces.borrow()[node_index]
            .as_ref()
            .ok_or_else(|| craftsec_core::CraftSecError::InvalidSignature("no nonce".into()))?
            .clone();
        let sig = self.nodes[node_index].sign(&nonce, message, commitments)?;
        Ok(Round2Response { partial: sig.partial })
    }
}

/// Simulated P2P transport with configurable latency.
/// Uses channels internally to pass messages, with artificial delay.
pub struct P2pTransport<E: ProgramExecutor> {
    inner: LocalTransport<E>,
    latency: Duration,
}

impl<E: ProgramExecutor> P2pTransport<E> {
    pub fn new(nodes: Vec<CraftSecNode<E>>, latency: Duration) -> Self {
        Self {
            inner: LocalTransport::new(nodes),
            latency,
        }
    }
}

impl<E: ProgramExecutor> NodeTransport for P2pTransport<E> {
    fn round1(&self, node_index: usize, request: &AttestationRequest) -> Result<Round1Response> {
        thread::sleep(self.latency);
        self.inner.round1(node_index, request)
    }

    fn round2(
        &self,
        node_index: usize,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> Result<Round2Response> {
        thread::sleep(self.latency);
        self.inner.round2(node_index, message, commitments)
    }
}
