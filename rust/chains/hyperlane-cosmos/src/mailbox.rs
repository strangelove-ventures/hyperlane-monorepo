use serde::Deserialize;
use std::fmt::Debug;
use std::time::Duration;
use url::Url;

use crate::client::CosmosClient;
use async_trait::async_trait;
use eyre::Result;
use futures_util::TryFutureExt;
use hyperlane_core::{
    ChainCommunicationError, ChainResult, HyperlaneMessage, IndexRange, Indexer, LogMeta,
    MessageIndexer,
};

/// Retrieves event data for a Cosmos chain that uses the hyperlane modules.
#[derive(Debug)]
pub struct CosmosMailboxIndexer {
    pub client: CosmosClient,
}

#[async_trait]
impl Indexer<HyperlaneMessage> for CosmosMailboxIndexer {
    async fn fetch_logs(&self, range: IndexRange) -> ChainResult<Vec<(HyperlaneMessage, LogMeta)>> {
        todo!()
    }

    /// Fetches the latest finalized block number from Cosmos API (aka LCD). Cosmos chains have fast finality.
    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        self.client
            .finalized_block_height()
            .await
            .map_err(|e| ChainCommunicationError::from_other(e))
    }
}

#[async_trait]
impl MessageIndexer for CosmosMailboxIndexer {
    async fn fetch_count_at_tip(&self) -> ChainResult<(u32, u32)> {
        todo!()
    }
}
