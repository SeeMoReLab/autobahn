use crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

pub type Stake = u32;
pub type EpochNumber = u128;

/// Consensus parameters; the same JSON shape as the hotstuff consensus
/// section, so both protocols share committee.json / parameters.json.
#[derive(Clone, Serialize, Deserialize)]
pub struct Parameters {
    /// Election (view-change) timeout in ms; the adaptive knob's initial
    /// value.
    pub timeout_delay: u64,
    pub sync_retry_delay: u64,
    /// Max bytes of payload digests per pre-prepare.
    pub max_payload_size: usize,
    /// Pacing between pre-prepares; the leader also heartbeats empty batches
    /// at this cadence so a slow or censoring leader is visible as a
    /// delivery gap.
    pub min_block_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            timeout_delay: 5000,
            sync_retry_delay: 1_000,
            max_payload_size: 500,
            min_block_delay: 100,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Authority {
    pub name: PublicKey,
    pub stake: Stake,
    pub address: SocketAddr,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Committee {
    pub authorities: HashMap<PublicKey, Authority>,
    pub epoch: EpochNumber,
}

impl Committee {
    pub fn new(info: Vec<(PublicKey, Stake, SocketAddr)>, epoch: EpochNumber) -> Self {
        Self {
            authorities: info
                .into_iter()
                .map(|(name, stake, address)| {
                    (
                        name,
                        Authority {
                            name,
                            stake,
                            address,
                        },
                    )
                })
                .collect(),
            epoch,
        }
    }

    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Max tolerated faults: n = 3f + 1.
    pub fn faults(&self) -> usize {
        (self.size() - 1) / 3
    }

    /// 2f + 1.
    pub fn quorum_threshold(&self) -> usize {
        2 * self.faults() + 1
    }

    /// f + 1.
    pub fn join_threshold(&self) -> usize {
        self.faults() + 1
    }

    pub fn exists(&self, name: &PublicKey) -> bool {
        self.authorities.contains_key(name)
    }

    /// Replicas in a canonical order (sorted by public key); the round-robin
    /// leader schedule and the harness replica ids both use this order.
    pub fn sorted_names(&self) -> Vec<PublicKey> {
        let mut names: Vec<_> = self.authorities.keys().cloned().collect();
        names.sort_by_key(|pk| pk.0);
        names
    }

    pub fn leader(&self, view: u64) -> PublicKey {
        let names = self.sorted_names();
        names[(view as usize) % names.len()]
    }

    pub fn address(&self, name: &PublicKey) -> Option<SocketAddr> {
        self.authorities.get(name).map(|x| x.address)
    }

    pub fn broadcast_addresses(&self, myself: &PublicKey) -> Vec<SocketAddr> {
        self.authorities
            .values()
            .filter(|x| x.name != *myself)
            .map(|x| x.address)
            .collect()
    }
}
