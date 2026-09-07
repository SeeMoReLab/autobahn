use bytes::Bytes;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{debug, info, warn};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, unbounded_channel, Receiver, Sender, UnboundedSender};
use tokio::time::Instant;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

#[cfg(test)]
#[path = "tests/network_tests.rs"]
pub mod network_tests;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] Box<bincode::ErrorKind>),
}

/// Delivery class of an outbound message.
///
/// `Control` carries the small messages consensus liveness depends on
/// (pre-prepares, votes, view changes, sync requests/replies): they queue
/// unbounded per peer and are never dropped locally, so a congested link
/// costs latency, not stalled sequences. `Bulk` carries large redundant
/// traffic - sealed payload broadcasts - on a bounded, age-limited queue:
/// under congestion these drop (with a warning) and the mempool
/// synchronizer re-fetches whatever a peer turns out to be missing.
///
/// Rationale (CloudLab run 20260906_130402): with a single shared bounded
/// queue, a network-delay transition briefly congested the leader's links,
/// payload floods filled the per-peer queues, and dropped votes and
/// pre-prepares halved the commit cadence for as long as the backlog fed
/// itself - a degraded state the election timer cannot see, because
/// deliveries keep trickling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageClass {
    Control,
    Bulk,
}

pub struct NetMessage(pub Bytes, pub Vec<SocketAddr>, pub MessageClass);

/// A bulk message older than this is stale by the standards of the mempool
/// intake bound (max_queue_delay defaults to 5s) and is dropped at the
/// queue head instead of wasting bandwidth on it.
const BULK_EXPIRY: std::time::Duration = std::time::Duration::from_secs(5);

/// Parallel TCP connections per peer for the bulk lane. A single TCP
/// connection's usable window self-sizes to rate x RTT of the current
/// path, so an injected delay step makes its throughput collapse by the
/// RTT ratio until the window regrows - seconds during which payload
/// dissemination (and with it the commit rate) is bandwidth-starved even
/// though nothing is wrong with the protocol (CloudLab run
/// 20260906_132436: commits fell 10/s -> 2-3/s for ~8s at delay onset).
/// Striping payloads over several connections multiplies the
/// post-transition floor and lets the windows regrow concurrently.
/// Payload broadcasts are self-contained and stored by digest, so
/// cross-connection reordering is harmless.
const BULK_CONNECTIONS: usize = 4;

/// Per-peer handles: an unbounded lane on a dedicated connection for
/// control traffic (never queues behind a payload frame), and bounded,
/// age-limited lanes striped over BULK_CONNECTIONS connections for bulk.
struct PeerHandle {
    control: UnboundedSender<Bytes>,
    bulk: Vec<Sender<(Instant, Bytes)>>,
    next_bulk: usize,
}

pub struct NetSender {
    transmit: Receiver<NetMessage>,
}

impl NetSender {
    pub fn new(transmit: Receiver<NetMessage>) -> Self {
        Self { transmit }
    }

    // We keep one control TCP connection plus BULK_CONNECTIONS bulk
    // connections per peer, each handled by its own worker task. If a
    // connection dies, the whole peer handle is respawned on the next
    // message to it.
    //
    // This loop must never block on a slow peer: parking here backpressures
    // every task that sends through this NetSender and, under saturation,
    // closes a channel-wait cycle across tasks (and across replicas via TCP)
    // that deadlocks the whole node. Control messages go on an unbounded
    // queue (small, and liveness depends on them); a bulk message is tried
    // round-robin on every bulk lane and dropped with a warning only when
    // all are full - payload sync heals whatever a peer misses.
    pub async fn run(&mut self) {
        let mut senders = HashMap::<SocketAddr, PeerHandle>::new();
        while let Some(NetMessage(bytes, addresses, class)) = self.transmit.recv().await {
            for address in addresses {
                let spawn = match senders.get_mut(&address) {
                    Some(handle) => match class {
                        MessageClass::Control => handle.control.send(bytes.clone()).is_err(),
                        MessageClass::Bulk => Self::try_send_bulk(handle, &address, &bytes),
                    },
                    None => true,
                };
                if spawn {
                    let mut handle = Self::spawn_peer(address).await;
                    let queued = match class {
                        MessageClass::Control => handle.control.send(bytes.clone()).is_ok(),
                        MessageClass::Bulk => !Self::try_send_bulk(&mut handle, &address, &bytes),
                    };
                    if queued {
                        senders.insert(address, handle);
                    }
                }
            }
        }
    }

    /// Queue a bulk message on the next live, non-full bulk lane. Returns
    /// true when the peer handle must be respawned (a lane is closed).
    fn try_send_bulk(handle: &mut PeerHandle, address: &SocketAddr, bytes: &Bytes) -> bool {
        let lanes = handle.bulk.len();
        let mut all_full = true;
        for i in 0..lanes {
            let lane = (handle.next_bulk + i) % lanes;
            match handle.bulk[lane].try_send((Instant::now(), bytes.clone())) {
                Ok(()) => {
                    handle.next_bulk = (lane + 1) % lanes;
                    return false;
                }
                Err(TrySendError::Full(_)) => continue,
                Err(TrySendError::Closed(_)) => {
                    all_full = false;
                    break;
                }
            }
        }
        if all_full {
            warn!("Dropping bulk message to {}: all peer queues full", address);
            false
        } else {
            true
        }
    }

    async fn spawn_peer(address: SocketAddr) -> PeerHandle {
        let control = Self::spawn_control_conn(address);
        let bulk = (0..BULK_CONNECTIONS)
            .map(|_| Self::spawn_bulk_conn(address))
            .collect();
        PeerHandle {
            control,
            bulk,
            next_bulk: 0,
        }
    }

    /// Dedicated connection for control traffic: small frames, never
    /// dropped locally, never stuck behind a bulk frame.
    fn spawn_control_conn(address: SocketAddr) -> UnboundedSender<Bytes> {
        let (tx, mut rx) = unbounded_channel::<Bytes>();
        tokio::spawn(async move {
            let stream = match TcpStream::connect(address).await {
                Ok(stream) => {
                    info!("Outgoing control connection established with {}", address);
                    stream
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", address, e);
                    return;
                }
            };
            let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
            while let Some(message) = rx.recv().await {
                match transport.send(message).await {
                    Ok(_) => debug!("Successfully sent control message to {}", address),
                    Err(e) => {
                        warn!("Failed to send message to {}: {}", address, e);
                        return;
                    }
                }
            }
        });
        tx
    }

    /// One striped bulk connection: bounded queue, stale frames dropped at
    /// the head instead of wasting bandwidth.
    fn spawn_bulk_conn(address: SocketAddr) -> Sender<(Instant, Bytes)> {
        let (tx, mut rx) = channel::<(Instant, Bytes)>(1000);
        tokio::spawn(async move {
            let stream = match TcpStream::connect(address).await {
                Ok(stream) => {
                    info!("Outgoing bulk connection established with {}", address);
                    stream
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", address, e);
                    return;
                }
            };
            let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
            while let Some((queued_at, message)) = rx.recv().await {
                if queued_at.elapsed() > BULK_EXPIRY {
                    warn!("Dropping bulk message to {}: expired in queue", address);
                    continue;
                }
                match transport.send(message).await {
                    Ok(_) => debug!("Successfully sent bulk message to {}", address),
                    Err(e) => {
                        warn!("Failed to send message to {}: {}", address, e);
                        return;
                    }
                }
            }
        });
        tx
    }
}

pub struct NetReceiver<Message> {
    address: SocketAddr,
    deliver: Sender<Message>,
}

impl<Message: 'static + Send + DeserializeOwned + Debug> NetReceiver<Message> {
    pub fn new(address: SocketAddr, deliver: Sender<Message>) -> Self {
        Self { address, deliver }
    }

    // For each incoming request, we spawn a new worker responsible to receive
    // messages and replay them through the provided deliver channel.
    pub async fn run(&self) {
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("Failed to bind to TCP port");

        debug!("Listening on {}", self.address);
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(e) => {
                    warn!("{}", NetworkError::from(e));
                    continue;
                }
            };
            info!("Incoming connection established with {}", peer);
            Self::spawn_worker(socket, peer, self.deliver.clone()).await;
        }
    }

    async fn spawn_worker(socket: TcpStream, peer: SocketAddr, deliver: Sender<Message>) {
        tokio::spawn(async move {
            let mut transport = Framed::new(socket, LengthDelimitedCodec::new());
            while let Some(frame) = transport.next().await {
                match frame
                    .map_err(NetworkError::from)
                    .and_then(|x| bincode::deserialize(&x).map_err(NetworkError::from))
                {
                    Ok(message) => {
                        debug!("Received {:?}", message);
                        deliver
                            .send(message)
                            .await
                            .expect("Failed to deliver message");
                    }
                    Err(e) => {
                        warn!("{}", e);
                        return;
                    }
                }
            }
            warn!("Connection closed by peer {}", peer);
        });
    }
}
