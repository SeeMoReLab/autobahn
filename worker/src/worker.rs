#![allow(unused_variables)]
#![allow(unused_imports)]
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::batch_maker::{Batch, BatchMaker, Transaction};
use crate::helper::Helper;
use crate::primary_connector::PrimaryConnector;
use crate::processor::{Processor, SerializedBatchMessage};
use crate::quorum_waiter::QuorumWaiter;
use crate::synchronizer::Synchronizer;
use adaptive::ack::{AckIndex, AckRouter};
use adaptive::front::ClientFront;
use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey};
use futures::sink::SinkExt as _;
use log::{error, info, warn};
use network::{MessageHandler, Receiver, Writer};
use primary::PrimaryWorkerMessage;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{channel, Sender};

/// Bound on batches sealed locally but not yet observed as committed. Beyond
/// this, the oldest pending batches are dropped from the ack index and their
/// transactions surface as client-side timeouts.
const ACK_INDEX_CAPACITY: usize = 100_000;

#[cfg(test)]
#[path = "tests/worker_tests.rs"]
pub mod worker_tests;

/// The default channel capacity for each channel of the worker.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The primary round number.
// TODO: Move to the primary.
pub type Round = u64;

/// Indicates a serialized `WorkerPrimaryMessage` message.
pub type SerializedBatchDigestMessage = Vec<u8>;

/// The message exchanged between workers.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    Batch(Batch),
    BatchRequest(Vec<Digest>, /* origin */ PublicKey),
}

pub struct Worker {
    /// The public key of this authority.
    name: PublicKey,
    /// The id of this worker.
    id: WorkerId,
    /// The committee information.
    committee: Committee,
    /// The configuration parameters.
    parameters: Parameters,
    /// The persistent storage.
    store: Store,
}

impl Worker {
    pub fn spawn(
        name: PublicKey,
        id: WorkerId,
        committee: Committee,
        parameters: Parameters,
        store: Store,
    ) {
        // Define a worker instance.
        let worker = Self {
            name,
            id,
            committee,
            parameters,
            store,
        };

        // Commit-ack plumbing between the client front and the benchmark
        // client: the batch maker registers sealed batches in the index and
        // the ack dispatcher acks them when the primary reports them
        // committed.
        let ack_index = Arc::new(AckIndex::new(ACK_INDEX_CAPACITY));
        let ack_router = Arc::new(AckRouter::new());
        let (tx_committed, mut rx_committed) = channel::<Vec<Digest>>(CHANNEL_CAPACITY);
        {
            let ack_index = Arc::clone(&ack_index);
            let ack_router = Arc::clone(&ack_router);
            tokio::spawn(async move {
                while let Some(digests) = rx_committed.recv().await {
                    for digest in digests {
                        if let Some(txs) = ack_index.take(&digest.0) {
                            ack_router.ack(&txs);
                        }
                    }
                }
            });
        }

        // Spawn all worker tasks.
        let (tx_primary, rx_primary) = channel(CHANNEL_CAPACITY);
        worker.handle_primary_messages(tx_committed);             //spawns async task that listens for network message from Primary
        worker.handle_clients_transactions(tx_primary.clone(), ack_index, ack_router); //spawns async task that listens for network messages from Client
        worker.handle_workers_messages(tx_primary);               //spawns async task that listens for network messages from other Workers

        // The `PrimaryConnector` allows the worker to send messages to its primary.
        PrimaryConnector::spawn(
            worker
                .committee
                .primary(&worker.name)
                .expect("Our public key is not in the committee")
                .worker_to_primary,                              //filter primary associated with current worker based on the committee config.
            rx_primary,                                          //receiver channel to connect to primary channel (i.e. how other listener functions can invoke to PrimaryConnector)
        );

        // NOTE: This log entry is used to compute performance.
        info!(
            "Worker {} successfully booted on {}",
            id,
            worker
                .committee
                .worker(&worker.name, &worker.id)
                .expect("Our public key or worker id is not in the committee")
                .transactions
                .ip()
        );
    }

///////////////////////// TASK INSTANTIATORS ///////////////////////////////////


    /// Spawn all tasks responsible to handle messages from our primary.
    fn handle_primary_messages(&self, tx_committed: Sender<Vec<Digest>>) {
        let (tx_synchronizer, rx_synchronizer) = channel(CHANNEL_CAPACITY); //channel between PrimaryReceiverHandler and Synchronizer

        // Receive incoming messages from our primary.
        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .primary_to_worker;
        address.set_ip("0.0.0.0".parse().unwrap());
        Receiver::spawn(
            address,                                    //socket to receive Primary messages from
            /* handler */
            PrimaryReceiverHandler { tx_synchronizer, tx_committed }, //handler for received Primary messages, forwards them to synchronizer or the ack dispatcher
        );

        // The `Synchronizer` is responsible to keep the worker in sync with the others. It handles the commands
        // it receives from the primary (which are mainly notifications that we are out of sync).
        Synchronizer::spawn(
            self.name,
            self.id,
            self.committee.clone(),
            self.store.clone(),
            self.parameters.gc_depth,
            self.parameters.sync_retry_delay,
            self.parameters.sync_retry_nodes,
            /* rx_message */ rx_synchronizer,   
        );

        info!(
            "Worker {} listening to primary messages on {}",
            self.id, address
        );
    }

    /// Spawn all tasks responsible to handle clients transactions.
    fn handle_clients_transactions(
        &self,
        tx_primary: Sender<SerializedBatchDigestMessage>,  //tx_primary: channel between processor and PrimaryConnector
        ack_index: Arc<AckIndex>,
        ack_router: Arc<AckRouter>,
    ) {
        let (tx_batch_maker, rx_batch_maker) = channel(CHANNEL_CAPACITY);      //channel between ClientFront and batch maker
        //let (tx_quorum_waiter, rx_quorum_waiter) = channel(CHANNEL_CAPACITY);  //channel between batch maker and quorum waiter
        let (tx_processor, rx_processor) = channel(CHANNEL_CAPACITY);          //channel between quorum waiter and processor

        // We first receive clients' transactions from the network. The front
        // tags each transaction with its connection so commit acks can flow
        // back on the same socket.
        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .transactions;
        address.set_ip("0.0.0.0".parse().unwrap());
        ClientFront::new(address, tx_batch_maker, ack_router).spawn();

        // The transactions are sent to the `BatchMaker` that assembles them into batches. It then broadcasts
        // (in a reliable manner) the batches to all other workers that share the same `id` as us. Finally, it
        // gathers the 'cancel handlers' of the messages and send them to the `QuorumWaiter`.
        BatchMaker::spawn(
            self.parameters.batch_size,
            self.parameters.max_batch_delay,
            /* rx_transaction */ rx_batch_maker,  //receiver channel to connect to ClientFront
            // tx_message tx_quorum_waiter,   //sender channel to connect to quorum waiter
           /* tx_batch */ tx_processor,  //sender channel to connect to processor
            /* workers_addresses */
            self.committee
                .others_workers(&self.name, &self.id)
                .iter()
                .map(|(name, addresses)| (*name, addresses.worker_to_worker))
                .collect(),
            ack_index,
        );

        // // The `QuorumWaiter` waits for 2f authorities to acknowledge reception of the batch. It then forwards
        // // the batch to the `Processor`.
        // QuorumWaiter::spawn(
        //     self.committee.clone(),
        //     /* stake */ self.committee.stake(&self.name),
        //     /* rx_message */ rx_quorum_waiter, //receiver channel to connect to batch maker.
        //     /* tx_batch */ tx_processor,  //sender channel to connect to processor
        // );

        // The `Processor` hashes and stores the batch. It then forwards the batch's digest to the `PrimaryConnector`
        // that will send it to our primary machine.
        Processor::spawn(
            self.id,
            self.store.clone(),
            /* rx_batch */ rx_processor,  //receiver channel to connect to quorum waiter
            /* tx_digest */ tx_primary,   //sender channel to connect to PrimaryConnector
            /* own_batch */ true,
        );

        info!(
            "Worker {} listening to client transactions on {}",
            self.id, address
        );
    }

    /// Spawn all tasks responsible to handle messages from other workers.
    fn handle_workers_messages(&self, tx_primary: Sender<SerializedBatchDigestMessage>) {
        let (tx_helper, rx_helper) = channel(CHANNEL_CAPACITY);         //channel between WorkReceiverHandler and Helper
        let (tx_processor, rx_processor) = channel(CHANNEL_CAPACITY);   //channel between WorkReceiverHandler and Processor

        // Receive incoming messages from other workers.
        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .worker_to_worker;
        address.set_ip("0.0.0.0".parse().unwrap());
        Receiver::spawn(
            address,                     //socket to receive Worker messages from
            /* handler */
            WorkerReceiverHandler {      //handler for received Worker messages, forwards them either to helper, or processor -- depending on (?)
                tx_helper,               //sender channel to connect to helper
                tx_processor,            //sender channel to connect to processor
            },
        );

        // The `Helper` is dedicated to reply to batch requests from other workers.
        Helper::spawn(
            self.id,
            self.committee.clone(),
            self.store.clone(),
            /* rx_request */ rx_helper,   //receiver channel to connect to WorkerReceiverHandler
        );

        // This `Processor` hashes and stores the batches we receive from the other workers. It then forwards the
        // batch's digest to the `PrimaryConnector` that will send it to our primary.
        Processor::spawn(
            self.id,
            self.store.clone(),
            /* rx_batch */ rx_processor,   //receiver channel to connect to WorkerReceiverHandler
            /* tx_digest */ tx_primary,    //sender channel to connect to PrimaryConnector
            /* own_batch */ false,
        );

        info!(
            "Worker {} listening to worker messages on {}",
            self.id, address
        );
    }
}

/////////////////////////// Network Handlers ///////////////////////////////


/// Defines how the network receiver handles incoming workers messages.
//Note: Only expect to receive worker messages that are a) proposing batches, or b) acknowledging batches
#[derive(Clone)]
struct WorkerReceiverHandler {
    tx_helper: Sender<(Vec<Digest>, PublicKey)>,   //sender channel to connect to helper
    tx_processor: Sender<SerializedBatchMessage>,  //sender channel to connect to processor
}

#[async_trait]
impl MessageHandler for WorkerReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        //NEW: Do not need to Reply with an ack... Currently simple sender expects it though so we keep it (useful for debugging). Simple sender just sinks the reply.
        // // Reply with an ACK.
        let _ = writer.send(Bytes::from("Ack")).await;     //Question: Where is ack signed? Is authenticated channel assumed? TLS?
        // //Acknowledge Batches received. 
        // //Note: Missing Batch Requests don't expect an ack (they use simple sender) -- seems like it is sent anyways, but origin probably simply ignores it.

        // Deserialize and parse the message.
        match bincode::deserialize(&serialized) {
            Ok(WorkerMessage::Batch(..)) => self     //If receive batch message from another worker. Store the batch, and process.
                .tx_processor
                .send(serialized.to_vec())
                .await
                .expect("Failed to send batch"),
            Ok(WorkerMessage::BatchRequest(missing, requestor)) => self  //If receive message from another worker that is missing a batch. Reply if we have batch ourselves.
                .tx_helper
                .send((missing, requestor))
                .await
                .expect("Failed to send batch request"),
            Err(e) => warn!("Serialization error: {}", e),
        }
        Ok(())
    }
}

/// Defines how the network receiver handles incoming primary messages.  
//Note: Only expect to receive primary messages requesting synchronization.
#[derive(Clone)]
struct PrimaryReceiverHandler {
    tx_synchronizer: Sender<PrimaryWorkerMessage>,  //sender channel to connect to synchronizer.
    tx_committed: Sender<Vec<Digest>>,              //sender channel to connect to the ack dispatcher.
}

#[async_trait]
impl MessageHandler for PrimaryReceiverHandler {
    async fn dispatch(
        &self,
        _writer: &mut Writer,
        serialized: Bytes,
    ) -> Result<(), Box<dyn Error>> {
        // Deserialize the message and send it to the synchronizer, except
        // commit notifications, which go to the ack dispatcher.
        match bincode::deserialize(&serialized) {
            Err(e) => error!("Failed to deserialize primary message: {}", e),
            Ok(PrimaryWorkerMessage::Committed(digests)) => self
                .tx_committed
                .send(digests)
                .await
                .expect("Failed to send committed digests"),
            Ok(message) => self
                .tx_synchronizer
                .send(message)
                .await
                .expect("Failed to send transaction"),
        }
        Ok(())
    }
}
