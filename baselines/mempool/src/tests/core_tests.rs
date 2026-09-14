use super::*;
use crate::common::{committee, keys, payload, payload_with};
use crate::common::TestBlock;
use crate::messages::Transaction;
use adaptive::ack::{AckIndex, ConnId};
use crypto::SignatureService;
use std::sync::Arc;
use std::fs;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot;
use tokio::time::sleep;

async fn core(
    store_path: &str,
    max_queued_transactions: usize,
    max_queue_delay: u64,
) -> (
    Receiver<NetMessage>,
    Sender<MempoolMessage>,
    Sender<ConsensusMempoolMessage<TestBlock>>,
    Sender<(ConnId, Transaction)>,
) {
    let (tx_network, rx_network) = channel(1);
    let (tx_consensus, _rx_consensus) = channel::<TestBlock>(1);
    let (tx_core, rx_core) = channel(1);
    let (tx_consensus_mempool, rx_consensus_mempool) = channel(1);
    let (tx_client, rx_client) = channel(1);

    let (name, secret) = keys().pop().unwrap();
    let parameters = Parameters {
        max_queued_transactions,
        max_queue_delay,
        sync_retry_delay: 10_000,
        max_payload_size: 1,
        min_block_delay: 0,
    };
    let signature_service = SignatureService::new(secret);
    let _ = fs::remove_dir_all(store_path);
    let store = Store::new(store_path).unwrap();
    let synchronizer = Synchronizer::new(
        tx_consensus,
        store.clone(),
        name,
        committee(),
        tx_network.clone(),
        parameters.sync_retry_delay,
    );
    let payload_maker = PayloadMaker::new(
        name,
        signature_service,
        parameters.max_payload_size,
        parameters.min_block_delay,
        Arc::new(AckIndex::new(16)),
        Arc::new(adaptive::shadow::ShadowLog::new()),
        rx_client,
        tx_core.clone(),
    );
    let mut core = Core::new(
        name,
        committee(),
        parameters,
        store,
        synchronizer,
        payload_maker,
        /* core_channel */ rx_core,
        /* consensus_channel */ rx_consensus_mempool,
        /* network_channel */ tx_network,
        Arc::new(adaptive::shadow::ShadowLog::new()),
    );
    tokio::spawn(async move {
        core.run().await;
    });

    (rx_network, tx_core, tx_consensus_mempool, tx_client)
}

#[tokio::test]
async fn handle_transaction() {
    // Run the core.
    let path = ".db_test_handle_transaction";
    let (mut rx_network, _tx_core, _tx_consensus, tx_client) = core(path, 100, 60_000).await;

    // Ensure the core transmits the payload to the network.
    tx_client.send((0, vec![1u8])).await.unwrap();
    tx_client.send((0, vec![1u8])).await.unwrap();
    assert!(rx_network.recv().await.is_some());
}

#[tokio::test]
async fn handle_request() {
    // Run the core.
    let path = ".db_test_handle_request";
    let (mut rx_network, tx_core, _tx_consensus, _tx_client) = core(path, 100, 60_000).await;

    // Send a payload to the core.
    let message = MempoolMessage::Payload(payload());
    tx_core.send(message).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    // Send a sync request.
    let (name, _) = keys().pop().unwrap();
    let digest = payload().digest();
    let message = MempoolMessage::PayloadRequest(vec![digest], name);
    tx_core.send(message).await.unwrap();

    // Ensure we transmit a reply.
    assert!(rx_network.recv().await.is_some());
}

#[tokio::test]
async fn get_payload() {
    // Run the core.
    let path = ".db_test_get_payload";
    let (_rx_network, _tx_core, tx_consensus, tx_client) = core(path, 100, 60_000).await;

    // Send enough transactions to generate a payload.
    tx_client.send((0, vec![1u8])).await.unwrap();
    tx_client.send((0, vec![1u8])).await.unwrap();

    // Get the next payload.
    let (sender, receiver) = oneshot::channel();
    let message = ConsensusMempoolMessage::Get(64, sender);
    tx_consensus.send(message).await.unwrap();
    let result = receiver.await.unwrap();
    assert_eq!(result, vec![payload().digest()]);
}

#[tokio::test]
async fn payloads_included_oldest_first() {
    // Run the core.
    let path = ".db_test_fifo_order";
    let (_rx_network, tx_core, tx_consensus, _tx_client) = core(path, 100, 60_000).await;

    // Queue three peer payloads in a known order.
    let tags = [1u8, 2, 3];
    let expected: Vec<_> = tags.iter().map(|t| payload_with(*t).digest()).collect();
    for tag in tags {
        let message = MempoolMessage::Payload(payload_with(tag));
        tx_core.send(message).await.unwrap();
    }
    sleep(Duration::from_millis(50)).await;

    // A Get sized for one digest at a time must return them oldest first.
    for expected_digest in expected {
        let (sender, receiver) = oneshot::channel();
        let message = ConsensusMempoolMessage::Get(32, sender);
        tx_consensus.send(message).await.unwrap();
        assert_eq!(receiver.await.unwrap(), vec![expected_digest]);
    }
}

#[tokio::test]
async fn own_intake_shed_when_backlog_full() {
    // Run the core with a one-transaction backlog bound.
    let path = ".db_test_backlog_shed";
    let (mut rx_network, tx_core, tx_consensus, tx_client) = core(path, 1, 60_000).await;

    // A peer payload fills the bound.
    let message = MempoolMessage::Payload(payload_with(9));
    tx_core.send(message).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    // Client transactions seal an own payload, but the full backlog sheds
    // it: nothing is broadcast...
    tx_client.send((0, vec![1u8])).await.unwrap();
    tx_client.send((0, vec![1u8])).await.unwrap();
    sleep(Duration::from_millis(100)).await;
    assert!(
        rx_network.try_recv().is_err(),
        "shed payload must not be broadcast"
    );

    // ...and only the peer payload is ever proposed.
    let (sender, receiver) = oneshot::channel();
    let message = ConsensusMempoolMessage::Get(1024, sender);
    tx_consensus.send(message).await.unwrap();
    assert_eq!(receiver.await.unwrap(), vec![payload_with(9).digest()]);
}

#[tokio::test]
async fn own_intake_shed_when_backlog_too_old() {
    // Run the core with a zero age bound: any pending payload is "too old".
    let path = ".db_test_age_shed";
    let (mut rx_network, tx_core, tx_consensus, tx_client) = core(path, 1000, 0).await;

    // A peer payload makes the queue non-empty (and instantly over-age).
    let message = MempoolMessage::Payload(payload_with(7));
    tx_core.send(message).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    // Own intake is shed on the age bound even though the transaction-count
    // bound has plenty of room.
    tx_client.send((0, vec![1u8])).await.unwrap();
    tx_client.send((0, vec![1u8])).await.unwrap();
    sleep(Duration::from_millis(100)).await;
    assert!(
        rx_network.try_recv().is_err(),
        "aged-out backlog must shed own intake"
    );

    let (sender, receiver) = oneshot::channel();
    let message = ConsensusMempoolMessage::Get(1024, sender);
    tx_consensus.send(message).await.unwrap();
    assert_eq!(receiver.await.unwrap(), vec![payload_with(7).digest()]);
}
