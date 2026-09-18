#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{ConsensusMessage, Header, Proposal, proposal_digest};
use crate::primary::{Height, PrimaryMessage, PrimaryWorkerMessage};
use bytes::Bytes;
use config::{Committee, WorkerId};
use crypto::{Digest, Hash, PublicKey};
use futures::future::try_join_all;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, error};
use network::SimpleSender;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender, UnboundedSender};
use tokio::time::{sleep, Duration, Instant};

/// The resolution of the timer that checks whether we received replies to our sync requests, and triggers
/// new sync requests if we didn't.
const TIMER_RESOLUTION: u64 = 1_000;

/// How many payload waits may be escalated into batch requests at once.
///
/// Escalation repairs an *isolated* batch that dissemination dropped. When
/// many payloads are missing at the same time nothing was dropped: we are
/// simply behind, and the committer's catch-up is what resolves that. Asking
/// for every batch of the gap instead buries our own worker and the peers we
/// ask - measured, a returning replica issued 23894 batch requests and
/// collapsed, while the healthy replicas needed 2 apiece.
const MAX_ESCALATIONS_IN_FLIGHT: usize = 16;

/// A pending sync request is abandoned after this many sync retry delays.
const SYNC_EXPIRY_RETRIES: u128 = 6;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to measure time")
        .as_millis()
}

/// The commands that can be sent to the `Waiter`.
#[derive(Debug)]
pub enum WaiterMessage {
    SyncBatches(HashMap<Digest, WorkerId>, Header, bool),
    SyncProposals(Vec<Proposal>, ConsensusMessage, Header),
    // SyncProposalsC(Vec<Proposal>, ConsensusMessage), //Consensus is independent of header.
    // SyncProposalsCAsync(Vec<Proposal>), //Consensus is independent of header.
    SyncParent(Digest, Header),
    SyncHeader(Digest),
}

/// Waits for missing parent certificates and batches' digests.
pub struct HeaderWaiter {
    /// The name of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// The delay to wait before re-trying sync requests.
    sync_retry_delay: u64,
    /// Pending sync requests older than this (ms) are abandoned. Age based,
    /// not round based: Autobahn lanes are independent, so a header's height
    /// says nothing about how long its sync has been waiting, and a global
    /// round cut off every request for a lane that had fallen behind.
    sync_expiry_ms: u128,
    /// Determine with how many nodes to sync when re-trying to send sync-request.
    sync_retry_nodes: usize,

    /// Receives sync commands from the `Synchronizer`.
    rx_synchronizer: Receiver<WaiterMessage>,
    /// Loops back to the core headers for which we got all parents and batches.
    tx_core: UnboundedSender<Header>,
    /// Loops back commit messages to the committer for reprocessing
    tx_consensus_loopback: UnboundedSender<(ConsensusMessage, Header)>,

    /// Network driver allowing to send messages.
    network: SimpleSender,

    /// Keeps the digests of the all certificates for which we sent a sync request,
    /// along with when the request was first made and when it was last retried.
    /// The two are distinct: the first bounds how long we keep waiting before
    /// abandoning the sync, the second spaces the retries. Using one field for
    /// both means a retried request either never expires or is retried on
    /// every timer tick.
    parent_requests: HashMap<Digest, (Height, u128, u128)>,
    //same, but for special parents
    header_requests: HashMap<Digest, (Height, u128)>,
    /// Keeps the digests of the all tx batches for which we sent a sync request,
    /// similarly to `header_requests`.
    batch_requests: HashMap<Digest, u128>,
    /// List of digests (either certificates, headers or tx batch) that are waiting
    /// to be processed. Their processing will resume when we get all their dependencies.
    pending: HashMap<Digest, (u128, Sender<()>)>,
    /// Headers whose payload we are waiting for without having asked anyone for
    /// it, with the batches still missing, their author, and when the wait
    /// started. Batch dissemination is best effort (`SimpleSender`, no
    /// retransmission), so a batch dropped by a partition or a full queue never
    /// arrives on its own: without an escalation the header can never be voted
    /// on and its lane stalls for good. `escalate_payload_waits` turns these
    /// into real requests once they are older than `sync_retry_delay`.
    payload_waits: HashMap<Digest, (u128, HashMap<Digest, WorkerId>, PublicKey)>,
}

impl HeaderWaiter {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        sync_retry_delay: u64,
        sync_retry_nodes: usize,
        rx_synchronizer: Receiver<WaiterMessage>,
        tx_core: UnboundedSender<Header>,
        tx_consensus_loopback: UnboundedSender<(ConsensusMessage, Header)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                sync_retry_delay,
                sync_expiry_ms: (sync_retry_delay as u128) * SYNC_EXPIRY_RETRIES,
                sync_retry_nodes,
                rx_synchronizer,
                tx_core,
                tx_consensus_loopback,
                network: SimpleSender::new(),
                parent_requests: HashMap::new(),
                header_requests: HashMap::new(),
                batch_requests: HashMap::new(),
                pending: HashMap::new(),
                payload_waits: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for particular data to become available in the storage
    /// and then delivers the specified header.
    /// Ask our own worker to fetch these batches from the author's worker.
    /// `batch_requests` dedupes per digest, so asking twice for the same batch
    /// costs nothing.
    async fn request_batches(&mut self, missing: HashMap<Digest, WorkerId>, author: PublicKey) {
        let mut requires_sync = HashMap::new();
        for (digest, worker_id) in missing.into_iter() {
            self.batch_requests.entry(digest.clone()).or_insert_with(|| {
                requires_sync.entry(worker_id).or_insert_with(Vec::new).push(digest);
                now_ms()
            });
        }
        for (worker_id, digests) in requires_sync {
            let address = self
                .committee
                .worker(&self.name, &worker_id)
                .expect("Author of valid header is not in the committee")
                .primary_to_worker;
            debug!("Sent syncbatches message for {} digests", digests.len());
            let message = PrimaryWorkerMessage::Synchronize(digests, author);
            let bytes = bincode::serialize(&message).expect("Failed to serialize batch sync request");
            self.network.send(address, Bytes::from(bytes)).await;
        }
    }

    /// Turn payload waits older than `sync_retry_delay` into real requests.
    /// A batch that has not arrived by then was not merely slow: dissemination
    /// dropped it, and nothing will resend it unasked.
    async fn escalate_payload_waits(&mut self) {
        let now = now_ms();
        let delay = self.sync_retry_delay as u128;
        let due: Vec<Digest> = self
            .payload_waits
            .iter()
            .filter(|(_, (since, _, _))| since + delay < now)
            .map(|(id, _)| id.clone())
            .collect();
        if due.len() > MAX_ESCALATIONS_IN_FLIGHT {
            // Bulk catch-up, not a dropped batch: leave these to the committer
            // and stop tracking them so they do not pile up.
            debug!("{} payload waits overdue at once; leaving them to catch-up", due.len());
            for id in due {
                let _ = self.payload_waits.remove(&id);
            }
            return;
        }
        for id in due {
            if let Some((_, missing, author)) = self.payload_waits.remove(&id) {
                debug!("Escalating payload wait for header {} to a batch request", id);
                self.request_batches(missing, author).await;
            }
        }
    }

    async fn waiter(
        mut missing: Vec<(Vec<u8>, Store)>,
        deliver: Header,
        mut handler: Receiver<()>,
    ) -> DagResult<Option<Header>> {
        let waiting: Vec<_> = missing
            .iter_mut()
            .map(|(x, y)| y.notify_read(x.to_vec()))
            .collect();
        tokio::select! {
            result = try_join_all(waiting) => {
                result.map(|_| Some(deliver)).map_err(DagError::from)
            }
            _ = handler.recv() => Ok(None),
        }
    }


    async fn proposal_waiter(
        mut missing: Vec<(Vec<u8>, Store)>,
        deliver: (ConsensusMessage, Header),
        mut handler: Receiver<()>,
    ) -> DagResult<Option<(ConsensusMessage, Header)>> {
        let waiting: Vec<_> = missing
            .iter_mut()
            .map(|(x, y)| y.notify_read(x.to_vec()))
            .collect();
        tokio::select! {
            result = try_join_all(waiting) => {
                result.map(|_| Some(deliver)).map_err(DagError::from)
            }
            _ = handler.recv() => Ok(None),
        }
    }

    /// Main loop listening to the `Synchronizer` messages.
    async fn run(&mut self) {
        let mut waiting = FuturesUnordered::new();
        let mut proposal_waiting = FuturesUnordered::new();

        let timer = sleep(Duration::from_millis(TIMER_RESOLUTION));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                Some(message) = self.rx_synchronizer.recv() => {
                    match message {
                        WaiterMessage::SyncBatches(missing, header, force_sync) => {
                            debug!("Synching the payload of {}", header);
                            let header_id = header.id.clone();
                            let header_id_for_wait = header.id.clone();
                            let round = header.height;
                            let author = header.author;

                            // Ensure we sync only once per header.
                            if self.pending.contains_key(&header_id) {
                                continue;
                            }

                            // Add the header to the waiter pool. The waiter will return it to when all
                            // its parents are in the store.
                            let wait_for = missing
                                .iter()
                                .map(|(digest, worker_id)| {
                                    let key = [digest.as_ref(), &worker_id.to_le_bytes()].concat();
                                    (key.to_vec(), self.store.clone())
                                })
                                .collect();
                            let (tx_cancel, rx_cancel) = channel(1);
                            self.pending.insert(header_id, (now_ms(), tx_cancel));
                            let fut = Self::waiter(wait_for, header, rx_cancel);
                            waiting.push(fut);

                            if force_sync {
                                self.request_batches(missing, author).await;
                            } else {
                                // Wait for the batches to arrive on their own,
                                // which is the common case and costs nothing.
                                // If they do not, the timer escalates this to
                                // a real request; see `payload_waits`.
                                self.payload_waits.insert(header_id_for_wait, (now_ms(), missing, author));
                            }
                        }

                        WaiterMessage::SyncHeader(missing) => {
                            debug!("Syncing on header with digest {}", missing);

                            let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Failed to measure time")
                            .as_millis();

                            let mut requires_sync = Vec::new();
                            self.header_requests.entry(missing.clone()).or_insert_with(|| {
                                requires_sync.push(missing);
                                (0, now)
                            });

                            if !requires_sync.is_empty() {
                                let addresses = self.committee
                                .others_primaries(&self.name)
                                .iter()
                                .map(|(_, x)| x.primary_to_primary)
                                .collect();

                                let message = PrimaryMessage::HeadersRequest(requires_sync, self.name);
                                let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                                self.network.lucky_broadcast(addresses, Bytes::from(bytes), self.sync_retry_nodes).await; //after timeout, re-broadcast again (technically not necessary)
                            }
                        }

                        WaiterMessage::SyncParent(missing, header) => {
                            debug!("Synching the parents of {}", header);
                            let header_id = header.id.clone();
                            let height = header.height();
                            let author = header.author;

                            // Ensure we sync only once per header.
                            if self.pending.contains_key(&header_id) {
                                continue;
                            }

                            // Add the header to the waiter pool. The waiter will return it to us
                            // when all its parents are in the store.
                            let mut wait_for = Vec::new();
                            wait_for.push((missing.to_vec(), self.store.clone()));
                            let (tx_cancel, rx_cancel) = channel(1);
                            self.pending.insert(header_id, (now_ms(), tx_cancel));
                            let fut = Self::waiter(wait_for, header, rx_cancel);
                            waiting.push(fut);

                            // Ensure we didn't already sent a sync request for these parents.
                            // Optimistically send the sync request to the node that created the certificate.
                            // If this fails (after a timeout), we broadcast the sync request.
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            let mut requires_sync = Vec::new();
                            self.parent_requests.entry(missing.clone()).or_insert_with(|| {
                                requires_sync.push(missing);
                                (height, now, now)
                            });
                            if !requires_sync.is_empty() {
                                let address = self.committee
                                    .primary(&author)
                                    .expect("Author of valid header not in the committee")
                                    .primary_to_primary;
                                let message = PrimaryMessage::HeadersRequest(requires_sync, self.name);
                                let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                                self.network.send(address, Bytes::from(bytes)).await;
                            }
                        }


                        WaiterMessage::SyncProposals(missing, consensus_message, header) => {
                            //let header_id = header.id.clone();
                            let height = header.height();
                            let author = header.author;
                            let id = proposal_digest(&consensus_message);
                            //println!("syncing proposals in header waiter");

                            // Ensure we sync only once per proposal
                            if self.pending.contains_key(&id) {
                                continue;
                            }

                            // Add the header to the waiter pool. The waiter will return it to us
                            // when all its parents are in the store.
                            let wait_for = missing
                                .iter()
                                .cloned()
                                .map(|x| (x.header_digest.to_vec(), self.store.clone()))
                                .collect();
                            let (tx_cancel, rx_cancel) = channel(1);
                            self.pending.insert(id, (now_ms(), tx_cancel));
                            let fut = Self::proposal_waiter(wait_for, (consensus_message, header), rx_cancel);
                            //println!("created proposal waiter");
                            proposal_waiting.push(fut);

                            // Ensure we didn't already sent a sync request for these parents.
                            // Optimistically send the sync request to the node that created the certificate.
                            // If this fails (after a timeout), we broadcast the sync request.
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            let mut requires_sync = Vec::new();
                            for missing in missing {
                                self.parent_requests.entry(missing.header_digest.clone()).or_insert_with(|| {
                                    requires_sync.push(missing.header_digest);
                                    (missing.height, now, now)
                                });
                            }
                            if !requires_sync.is_empty() {
                                let address = self.committee
                                    .primary(&author)
                                    .expect("Author of valid header not in the committee")
                                    .primary_to_primary;
                                let message = PrimaryMessage::HeadersRequest(requires_sync, self.name);
                                let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                                self.network.send(address, Bytes::from(bytes)).await;
                            }
                        }
                    }
                },

                Some(result) = waiting.next() => match result {
                    Ok(Some(header)) => {
                        debug!("Finished synching {:?}", header);
                        let _ = self.pending.remove(&header.id);
                        let _ = self.payload_waits.remove(&header.id);
                        for x in header.payload.keys() {
                            let _ = self.batch_requests.remove(x);
                        }
                        let _ = self.parent_requests.remove(&header.parent_cert.header_digest);

                        self.tx_core.send(header).expect("Failed to send header");
                    },
                    Ok(None) => {
                        // This request has been canceled.
                    },
                    Err(e) => {
                        error!("{}", e);
                        panic!("Storage failure: killing node.");
                    }
                },

                Some(result) = proposal_waiting.next() => match result {
                    Ok(Some(deliver)) => {
                        //println!("finished syncing");
                        let id = proposal_digest(&deliver.0);
                        let _ = self.pending.remove(&id);
                        for x in deliver.1.payload.keys() {
                            let _ = self.batch_requests.remove(x);
                        }

                        let possibly_missing;
                        match &deliver.0 {
                            ConsensusMessage::Prepare {view: _, slot: _, tc: _, qc_ticket: _, proposals} => {possibly_missing = proposals},
                            ConsensusMessage::Confirm {view: _, slot: _, qc: _, proposals} => {possibly_missing = proposals},
                            ConsensusMessage::Commit {view: _, slot: _, qc: _, proposals} => {possibly_missing = proposals},
                        }
                        for (_, prop) in possibly_missing.iter() {
                            let _ = self.parent_requests.remove(&prop.header_digest);
                        }
                     
                        self.tx_consensus_loopback.send(deliver).expect("Failed to send header");
                    },
                    Ok(None) => {
                        // This request has been canceled.
                    },
                    Err(e) => {
                        error!("{}", e);
                        panic!("Storage failure: killing node.");
                    }
                },

                () = &mut timer => {
                    // We optimistically sent sync requests to a single node. If this timer triggers,
                    // it means we were wrong to trust it. We are done waiting for a reply and we now
                    // broadcast the request to all nodes.
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Failed to measure time")
                        .as_millis();

                    //Retry HeaderRequests  -- We don't use this
                    // let mut retry = Vec::new();
                    // for (digest, (_, timestamp)) in &self.header_requests {
                    //     if timestamp + (self.sync_retry_delay as u128) < now {
                    //         debug!("Requesting sync for header {} (retry)", digest);
                    //         retry.push(digest.clone());
                    //     }
                    // }
                    // let addresses = self.committee.others_primaries(&self.name).iter().map(|(_, x)| x.primary_to_primary).collect();
                    // let message = PrimaryMessage::HeadersRequest(retry, self.name);
                    // let bytes = bincode::serialize(&message).expect("Failed to serialize header request");
                    // self.network.lucky_broadcast(addresses, Bytes::from(bytes), self.sync_retry_nodes).await;

                    //Retry CertificateRequests
                    let mut retry = Vec::new();
                    for (digest, (_, _, last_retry)) in &self.parent_requests {
                        if last_retry + (self.sync_retry_delay as u128) < now {
                            debug!("Requesting retry sync for parent header {} (retry)", digest);
                            retry.push(digest.clone());
                        }
                    }
                    // Record the retry. Without this the timer (which ticks
                    // every TIMER_RESOLUTION) re-broadcasts every overdue
                    // request on every tick instead of once per
                    // sync_retry_delay, so one slow sync turns into a flood.
                    // Only `last_retry` moves: the creation time below still
                    // decides when the sync is abandoned.
                    for digest in &retry {
                        if let Some((_, _, last_retry)) = self.parent_requests.get_mut(digest) {
                            *last_retry = now;
                        }
                    }
                    let addresses = self.committee.others_primaries(&self.name).iter().map(|(_, x)| x.primary_to_primary).collect();
                    let message = PrimaryMessage::HeadersRequest(retry, self.name);
                    let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                    self.network.lucky_broadcast(addresses, Bytes::from(bytes), self.sync_retry_nodes).await;

                    self.escalate_payload_waits().await;

                    // Reschedule the timer.
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_RESOLUTION));
                }
            }

            // Expire pending syncs by age (see `sync_expiry_ms`).
            let now = now_ms();
            let expiry = self.sync_expiry_ms;
            for (since, handler) in self.pending.values() {
                if since + expiry < now {
                    let _ = handler.send(()).await;
                }
            }
            self.pending.retain(|_, (since, _)| *since + expiry >= now);
            self.payload_waits.retain(|_, (since, _, _)| *since + expiry >= now);
            self.batch_requests.retain(|_, since| *since + expiry >= now);
            self.parent_requests.retain(|_, (_, since, _)| *since + expiry >= now);
            self.header_requests.retain(|_, (_, since)| *since + expiry >= now);
        }
    }
}
