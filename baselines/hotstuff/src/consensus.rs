use crate::config::{Committee, Parameters};
use crate::core::{CommittedBlock, ConsensusMessage, Core, Instrumentation};
use crate::error::ConsensusResult;
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::Block;
use ::mempool::ConsensusMempoolMessage;
use crate::synchronizer::Synchronizer;
use crypto::{PublicKey, SignatureService};
use log::info;
use network::{NetReceiver, NetSender};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

pub struct Consensus;

impl Consensus {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        store: Store,
        signature_service: SignatureService,
        tx_core: Sender<ConsensusMessage>,
        rx_core: Receiver<ConsensusMessage>,
        tx_consensus_mempool: Sender<ConsensusMempoolMessage<Block>>,
        mut rx_mempool_loopback: Receiver<Block>,
        tx_commit: Sender<CommittedBlock>,
        instrumentation: Instrumentation,
    ) -> ConsensusResult<()> {
        // NOTE: The following log entries are used to compute performance.
        info!(
            "Consensus timeout delay set to {} ms",
            parameters.timeout_delay
        );
        info!(
            "Consensus synchronizer retry delay set to {} ms",
            parameters.sync_retry_delay
        );
        info!(
            "Consensus max payload size set to {} B",
            parameters.max_payload_size
        );
        info!(
            "Consensus min block delay set to {} ms",
            parameters.min_block_delay
        );

        let (tx_network, rx_network) = channel(1000);

        // Forward blocks whose payloads finished syncing back into the core.
        {
            let tx_loopback = tx_core.clone();
            tokio::spawn(async move {
                while let Some(block) = rx_mempool_loopback.recv().await {
                    if tx_loopback
                        .send(ConsensusMessage::LoopBack(block))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        // Make the network sender and receiver.
        let address = committee.address(&name).map(|mut x| {
            x.set_ip("0.0.0.0".parse().unwrap());
            x
        })?;
        let network_receiver = NetReceiver::new(address, tx_core.clone());
        tokio::spawn(async move {
            network_receiver.run().await;
        });

        let mut network_sender = NetSender::new(rx_network);
        tokio::spawn(async move {
            network_sender.run().await;
        });

        // The leader elector algorithm.
        let leader_elector = LeaderElector::new(committee.clone());

        // Make the mempool driver which will mediate our requests to the
        // mempool. Its round trips are waited on by spawned tasks: verified
        // blocks re-enter the core as LoopBack messages and fetched
        // proposal payloads arrive on a core-internal channel.
        let (tx_payload, rx_payload) = channel(100);
        let mempool_driver =
            MempoolDriver::new(tx_consensus_mempool, tx_core.clone(), tx_payload);

        // Make the synchronizer. This instance runs in a background thread
        // and asks other nodes for any block that we may be missing.
        let synchronizer = Synchronizer::new(
            name,
            committee.clone(),
            store.clone(),
            /* network_channel */ tx_network.clone(),
            /* core_channel */ tx_core,
            parameters.sync_retry_delay,
        )
        .await;

        let mut core = Core::new(
            name,
            committee,
            parameters,
            signature_service,
            store,
            leader_elector,
            mempool_driver,
            synchronizer,
            /* core_channel */ rx_core,
            rx_payload,
            /* network_channel */ tx_network,
            /* commit_channel */ tx_commit,
            instrumentation,
        );
        tokio::spawn(async move {
            core.run().await;
        });

        Ok(())
    }
}
