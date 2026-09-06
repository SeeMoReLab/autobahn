use crate::error::{MempoolError, MempoolResult};
use crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

fn default_max_queued_transactions() -> usize {
    20_000
}

fn default_max_queue_delay() -> u64 {
    5_000
}

#[derive(Serialize, Deserialize)]
pub struct Parameters {
    /// Bound on transactions in sealed-but-uncommitted payloads. Own intake
    /// is shed beyond it, which bounds queueing delay under overload (the
    /// backlog a committed transaction waits behind) instead of letting the
    /// queue grow past the clients' request timeout.
    #[serde(default = "default_max_queued_transactions")]
    pub max_queued_transactions: usize,
    /// Bound on the AGE of the pending backlog, in milliseconds: own intake
    /// is shed while the oldest queued payload is older than this. Unlike
    /// the transaction-count bound, this caps queueing delay independently
    /// of the current commit rate, keeping committed transactions younger
    /// than the clients' request timeout under any fault.
    #[serde(default = "default_max_queue_delay")]
    pub max_queue_delay: u64,
    pub sync_retry_delay: u64,
    pub max_payload_size: usize,
    pub min_block_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            max_queued_transactions: default_max_queued_transactions(),
            max_queue_delay: default_max_queue_delay(),
            sync_retry_delay: 1_000,
            max_payload_size: 100_000,
            min_block_delay: 100,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authority {
    pub name: PublicKey,
    pub front_address: SocketAddr,
    pub mempool_address: SocketAddr,
}

pub type EpochNumber = u128;

#[derive(Clone, Serialize, Deserialize)]
pub struct Committee {
    pub authorities: HashMap<PublicKey, Authority>,
    pub epoch: EpochNumber,
}

impl Committee {
    pub fn new(info: Vec<(PublicKey, SocketAddr, SocketAddr)>, epoch: EpochNumber) -> Self {
        Self {
            authorities: info
                .into_iter()
                .map(|(name, front_address, mempool_address)| {
                    let authority = Authority {
                        name,
                        front_address,
                        mempool_address,
                    };
                    (name, authority)
                })
                .collect(),
            epoch,
        }
    }

    pub fn exists(&self, name: &PublicKey) -> bool {
        self.authorities.contains_key(name)
    }

    pub fn front_address(&self, name: &PublicKey) -> MempoolResult<SocketAddr> {
        self.authorities
            .get(name)
            .map(|x| x.front_address)
            .ok_or_else(|| MempoolError::NotInCommittee(*name))
    }

    pub fn mempool_address(&self, name: &PublicKey) -> MempoolResult<SocketAddr> {
        self.authorities
            .get(name)
            .map(|x| x.mempool_address)
            .ok_or_else(|| MempoolError::NotInCommittee(*name))
    }

    pub fn broadcast_addresses(&self, myself: &PublicKey) -> Vec<SocketAddr> {
        self.authorities
            .values()
            .filter(|x| x.name != *myself)
            .map(|x| x.mempool_address)
            .collect()
    }
}
