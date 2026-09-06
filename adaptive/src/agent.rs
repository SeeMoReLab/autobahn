//! Thin gRPC client for the learning agent, mirroring the Go
//! `learningAgentClient` (SmartBFT/examples/smallbank/agent_client.go):
//! insecure channel, per-RPC timeout, SendReport + GetTimeout only.

use crate::pb;
use crate::pb::learning_agent_client::LearningAgentClient;
use anyhow::{Context, Result};
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};

#[derive(Clone)]
pub struct AgentClient {
    client: LearningAgentClient<Channel>,
    rpc_timeout: Duration,
    protocol: pb::Protocol,
}

impl AgentClient {
    /// Connect to `target` ("host:port"). Lazy: the TCP connection is
    /// established on first use and re-established as needed, so the agent
    /// process may come up after the replica.
    pub fn connect_lazy(target: &str, rpc_timeout: Duration, protocol: pb::Protocol) -> Result<Self> {
        let endpoint = Endpoint::from_shared(format!("http://{}", target))
            .with_context(|| format!("invalid agent target {}", target))?
            .connect_timeout(rpc_timeout);
        let channel = endpoint.connect_lazy();
        Ok(Self {
            client: LearningAgentClient::new(channel),
            rpc_timeout,
            protocol,
        })
    }

    pub async fn send_report(&self, report: pb::ReportLocal) -> Result<()> {
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(report);
        request.set_timeout(self.rpc_timeout);
        client
            .send_report(request)
            .await
            .context("SendReport failed")?;
        Ok(())
    }

    pub async fn get_timeout(&self, episode: u32) -> Result<pb::TimeoutStatus> {
        let mut client = self.client.clone();
        let mut request = tonic::Request::new(pb::TimeoutRequest {
            episode,
            protocol: self.protocol as i32,
        });
        request.set_timeout(self.rpc_timeout);
        let response = client
            .get_timeout(request)
            .await
            .context("GetTimeout failed")?;
        Ok(response.into_inner())
    }
}
