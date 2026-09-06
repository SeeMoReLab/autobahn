//! Shared TCP front for client transactions, used by both workspaces' tx
//! ingestion (the baselines mempool front and the autobahn worker). Each
//! client connection gets a [`ConnId`]; inbound frames are delivered as
//! `(ConnId, Vec<u8>)` transactions, and commit-ack frames registered through
//! the [`AckRouter`] flow back on the same connection.

use crate::ack::{AckRouter, ConnId};
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use log::{debug, warn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, Sender};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct ClientFront {
    address: SocketAddr,
    deliver: Sender<(ConnId, Vec<u8>)>,
    ack_router: Arc<AckRouter>,
}

impl ClientFront {
    pub fn new(
        address: SocketAddr,
        deliver: Sender<(ConnId, Vec<u8>)>,
        ack_router: Arc<AckRouter>,
    ) -> Self {
        Self {
            address,
            deliver,
            ack_router,
        }
    }

    pub fn spawn(self) {
        tokio::spawn(async move {
            self.run().await;
        });
    }

    pub async fn run(&self) {
        let listener = TcpListener::bind(&self.address)
            .await
            .expect("Failed to bind client transactions TCP port");
        let next_conn_id = AtomicU64::new(1);

        debug!("Listening for client transactions on {}", self.address);
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(e) => {
                    warn!("Failed to connect with client: {}", e);
                    continue;
                }
            };
            debug!("Connection established with client {}", peer);
            let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
            Self::spawn_connection(
                socket,
                peer,
                conn_id,
                self.deliver.clone(),
                Arc::clone(&self.ack_router),
            );
        }
    }

    fn spawn_connection(
        socket: TcpStream,
        peer: SocketAddr,
        conn_id: ConnId,
        deliver: Sender<(ConnId, Vec<u8>)>,
        ack_router: Arc<AckRouter>,
    ) {
        let (mut sink, mut stream) = Framed::new(socket, LengthDelimitedCodec::new()).split();
        let (ack_sender, mut ack_receiver) = unbounded_channel();
        ack_router.register(conn_id, ack_sender);

        // Outbound half: pump commit-ack frames back to the client. Exits
        // when the router deregisters this connection (sender dropped) or the
        // socket breaks.
        let writer_router = Arc::clone(&ack_router);
        tokio::spawn(async move {
            while let Some(frame) = ack_receiver.recv().await {
                if let Err(e) = sink.send(frame).await {
                    warn!("Failed to send ack to client {}: {}", peer, e);
                    break;
                }
            }
            writer_router.deregister(conn_id);
        });

        // Inbound half: deliver transactions tagged with this connection.
        tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                match frame {
                    Ok(tx) => {
                        if deliver.send((conn_id, tx.to_vec())).await.is_err() {
                            warn!("Transaction delivery channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to receive client transaction: {}", e);
                        break;
                    }
                }
            }
            ack_router.deregister(conn_id);
            debug!("Connection closed by client {}", peer);
        });
    }
}
