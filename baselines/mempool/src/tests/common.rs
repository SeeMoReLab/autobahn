use crate::config::Committee;
use crate::interface::MempoolBlock;
use crate::messages::Payload;
use crypto::Hash as _;
use crypto::{generate_keypair, Digest, PublicKey, SecretKey, Signature};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use std::convert::TryInto as _;

/// Minimal consensus-block stand-in for mempool tests.
#[derive(Clone, Debug)]
pub struct TestBlock {
    pub author: PublicKey,
    pub round: u64,
    pub payload: Vec<Digest>,
}

impl crypto::Hash for TestBlock {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl MempoolBlock for TestBlock {
    fn digest(&self) -> Digest {
        crypto::Hash::digest(self)
    }

    fn author(&self) -> PublicKey {
        self.author
    }

    fn round(&self) -> u64 {
        self.round
    }

    fn payload(&self) -> &[Digest] {
        &self.payload
    }
}

// Fixture.
pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

// Fixture.
pub fn committee() -> Committee {
    Committee::new(
        keys()
            .into_iter()
            .enumerate()
            .map(|(i, (name, _))| {
                let front = format!("127.0.0.1:{}", i).parse().unwrap();
                let mempool = format!("127.0.0.1:{}", i + keys().len()).parse().unwrap();
                (name, front, mempool)
            })
            .collect(),
        /* epoch */ 1,
    )
}

impl Committee {
    pub fn increment_base_port(&mut self, base_port: u16) {
        for authority in self.authorities.values_mut() {
            let port = authority.front_address.port();
            authority.front_address.set_port(base_port + port);
        }
        for authority in self.authorities.values_mut() {
            let port = authority.mempool_address.port();
            authority.mempool_address.set_port(base_port + port);
        }
    }
}

// Fixture.
pub fn payload_with(tag: u8) -> Payload {
    let (author, secret) = keys().pop().unwrap();
    let payload = Payload {
        transactions: vec![vec![tag]],
        author,
        signature: Signature::default(),
    };
    let signature = Signature::new(&payload.digest(), &secret);
    Payload {
        signature,
        ..payload
    }
}

// Fixture.
pub fn payload() -> Payload {
    let (author, secret) = keys().pop().unwrap();
    let payload = Payload {
        transactions: vec![vec![1u8]],
        author,
        signature: Signature::default(),
    };
    let signature = Signature::new(&payload.digest(), &secret);
    Payload {
        signature,
        ..payload
    }
}

// Fixture.
pub fn block() -> TestBlock {
    let (author, _) = keys().pop().unwrap();
    TestBlock {
        author,
        round: 1,
        payload: Vec::new(),
    }
}
