use crate::core::MempoolMessage;
use crate::messages::{Payload, Transaction};
use adaptive::ack::{tx_seq, AckIndex, ConnId};
use crypto::Hash as _;
use crypto::{PublicKey, SignatureService};
use log::debug;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::Duration;

struct Runner {
    transactions: Vec<Transaction>,
    // (connection, per-connection seq) for each conforming tx in
    // `transactions`; used to ack clients when the payload commits.
    tx_metas: Vec<(ConnId, u64)>,
    size: usize,
    max_size: usize,
    min_block_delay: u64,
    name: PublicKey,
    signature_service: SignatureService,
    ack_index: Arc<AckIndex>,
    client_channel: Receiver<(ConnId, Transaction)>,
    core_channel: Sender<MempoolMessage>,
    request_channel: Receiver<oneshot::Sender<Payload>>,
}

impl Runner {
    fn new(
        name: PublicKey,
        signature_service: SignatureService,
        max_size: usize,
        min_block_delay: u64,
        ack_index: Arc<AckIndex>,
        client_channel: Receiver<(ConnId, Transaction)>,
        core_channel: Sender<MempoolMessage>,
        request_channel: Receiver<oneshot::Sender<Payload>>,
    ) -> Self {
        Self {
            transactions: Vec::with_capacity(max_size),
            tx_metas: Vec::new(),
            size: 0,
            max_size,
            min_block_delay,
            name,
            signature_service,
            ack_index,
            client_channel,
            core_channel,
            request_channel,
        }
    }

    async fn add(&mut self, conn: ConnId, tx: Transaction) -> Option<Payload> {
        let length = tx.len();
        let ret = match self.size + length > self.max_size {
            true => Some(self.make().await),
            false => None,
        };
        match tx_seq(&tx) {
            Some(seq) => self.tx_metas.push((conn, seq)),
            // A tx without the benchmark header cannot be acked; it still
            // goes through consensus.
            None => debug!("transaction without ack header from conn {}", conn),
        }
        self.transactions.push(tx);
        self.size += length;
        ret
    }

    async fn make(&mut self) -> Payload {
        let transactions = self.transactions.drain(..).collect();
        let tx_metas: Vec<_> = self.tx_metas.drain(..).collect();

        // Cleanup state.
        self.size = 0;

        // Make a payload.
        let payload =
            Payload::new(transactions, self.name, self.signature_service.clone()).await;
        if !tx_metas.is_empty() {
            self.ack_index.register(payload.digest().0, tx_metas);
        }
        payload
    }

    async fn run(&mut self) {
        // Periodic sealing bounds how long a transaction can sit unsealed on
        // a replica that is not currently proposing (PBFT followers never
        // pull payloads on demand; they only broadcast sealed ones).
        // min_block_delay == 0 disables the periodic seal, leaving the
        // original pull-only behavior.
        let seal_period = Duration::from_millis(if self.min_block_delay == 0 {
            3_600_000
        } else {
            self.min_block_delay
        });
        let mut seal_tick = tokio::time::interval(seal_period);
        seal_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        seal_tick.tick().await; // The first tick completes immediately.

        loop {
            tokio::select! {
                Some((conn, transaction)) = self.client_channel.recv() => {
                    if let Some(payload) = self.add(conn, transaction).await {
                        let message = MempoolMessage::OwnPayload(payload);
                        if let Err(e) = self.core_channel.send(message).await {
                            panic!("Failed to send payload to the core: {}", e);
                        }
                        // No post-seal sleep here (the upstream artifact
                        // paused for min_block_delay): sealing pauses
                        // ingestion entirely, so any pause caps intake at
                        // one payload per delay (~10k tx/s at the defaults)
                        // and everything beyond backs up into client TCP
                        // buffers. Proposal pacing belongs to the consensus
                        // propose tick, not the payload maker.
                    }
                },
                Some(sender) = self.request_channel.recv() => {
                    let _ = sender.send(self.make().await);
                },
                _ = seal_tick.tick() => {
                    if !self.transactions.is_empty() {
                        let payload = self.make().await;
                        if payload.size() > 0 {
                            let message = MempoolMessage::OwnPayload(payload);
                            if let Err(e) = self.core_channel.send(message).await {
                                panic!("Failed to send payload to the core: {}", e);
                            }
                        }
                    }
                },
                else => break,
            }
        }
    }
}

pub struct PayloadMaker {
    request_channel: Sender<oneshot::Sender<Payload>>,
}

impl PayloadMaker {
    pub fn new(
        name: PublicKey,
        signature_service: SignatureService,
        max_size: usize,
        min_block_delay: u64,
        ack_index: Arc<AckIndex>,
        client_channel: Receiver<(ConnId, Transaction)>,
        core_channel: Sender<MempoolMessage>,
    ) -> Self {
        let (tx_request, rx_request) = channel(1000);
        tokio::spawn(async move {
            Runner::new(
                name,
                signature_service,
                max_size,
                min_block_delay,
                ack_index,
                client_channel,
                core_channel,
                rx_request,
            )
            .run()
            .await;
        });
        Self {
            request_channel: tx_request,
        }
    }

    pub async fn make(&mut self) -> Option<Payload> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.request_channel.send(sender).await {
            panic!("Failed to request payload from the inner runner: {}", e);
        }
        let payload = receiver
            .await
            .expect("Failed to receive payload from the inner runner");
        match payload.size() {
            0 => None,
            _ => Some(payload),
        }
    }
}
