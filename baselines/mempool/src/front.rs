use crate::messages::Transaction;
use adaptive::ack::{AckRouter, ConnId};
use adaptive::front::ClientFront;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

/// TCP front receiving client transactions and streaming commit acks back on
/// the same connection. Thin wrapper over the shared [`ClientFront`].
pub struct Front {
    inner: ClientFront,
}

impl Front {
    pub fn new(
        address: SocketAddr,
        deliver: Sender<(ConnId, Transaction)>,
        ack_router: Arc<AckRouter>,
    ) -> Self {
        Self {
            inner: ClientFront::new(address, deliver, ack_router),
        }
    }

    pub async fn run(&self) {
        self.inner.run().await;
    }
}
