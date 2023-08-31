use serde::Deserialize;
use std::fmt::Debug;
use std::ops::RangeInclusive;
use std::time::Duration;
use url::Url;

use async_trait::async_trait;
use eyre::Result;
use futures_util::TryFutureExt;
use hyperlane_core::{ChainCommunicationError, ChainResult, HyperlaneMessage, Indexer, LogMeta};
use tendermint_rpc::client::{Client, HttpClient};

/// Retrieves event data for a Cosmos chain that uses the hyperlane modules.
#[derive(Debug)]
pub struct CosmosMailboxIndexer<T: Client + Send + Sync> {
    pub client: T,
}

#[async_trait]
impl<T: Client + Send + Sync + Debug> Indexer<HyperlaneMessage> for CosmosMailboxIndexer<T> {
    async fn fetch_logs(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(HyperlaneMessage, LogMeta)>> {
        todo!()
    }

    /// Fetches the latest finalized block number from Cosmos API (aka LCD). Cosmos chains have fast finality.
    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        let resp = self
            .client
            .latest_block()
            .await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(resp.block.header.height.value() as u32)
    }
}
