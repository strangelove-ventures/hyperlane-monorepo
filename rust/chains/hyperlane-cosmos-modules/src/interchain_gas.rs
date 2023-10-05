use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, Indexer,
    InterchainGasPaymaster, SequenceIndexer, U256,
};
use hyperlane_core::{HyperlaneDomain, HyperlaneProvider, InterchainGasPayment, LogMeta, H256};
use std::ops::RangeInclusive;
use tracing::info;

use crate::{Signer, ConnectionConf, CosmosProvider};

#[derive(Debug)]
pub struct CosmosInterchainGasPaymaster {
    conf: ConnectionConf,
    domain: HyperlaneDomain,
    address: H256,
    signer: Signer,
    provider: Box<CosmosProvider>,
}

impl CosmosInterchainGasPaymaster {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer.clone());

        Self {
            conf: conf.clone(),
            domain: locator.domain.clone(),
            address: locator.address,
            signer,
            provider: Box::new(provider),
        }
    }
}

impl HyperlaneContract for CosmosInterchainGasPaymaster {
    fn address(&self) -> H256 {
        self.address.clone()
    }
}

impl HyperlaneChain for CosmosInterchainGasPaymaster {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(CosmosProvider::new(
            self.conf.clone(),
            self.domain.clone(),
            self.address(),
            self.signer.clone(),
        ))
    }
}

impl InterchainGasPaymaster for CosmosInterchainGasPaymaster {}

#[derive(Debug)]
pub struct CosmosInterchainGasPaymasterIndexer {
    provider: Box<CosmosProvider>,
}

impl CosmosInterchainGasPaymasterIndexer {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer);
        Self {
            provider: Box::new(provider),
        }
    }
}

#[async_trait]
impl Indexer<InterchainGasPayment> for CosmosInterchainGasPaymasterIndexer {
    async fn fetch_logs(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(InterchainGasPayment, LogMeta)>> {
        let mut result: Vec<(InterchainGasPayment, LogMeta)> = vec![];
        Ok(result)
    }

    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        let result = self.provider.query_latest_block().await?;
        Ok(result.block.header.height.value() as u32)
    }
}

#[async_trait]
impl Indexer<H256> for CosmosInterchainGasPaymasterIndexer {
    async fn fetch_logs(&self, range: RangeInclusive<u32>) -> ChainResult<Vec<(H256, LogMeta)>> {
        let mut result: Vec<(InterchainGasPayment, LogMeta)> = vec![];
        
        Ok(result
            .into_iter()
            .map(|(msg, meta)| (msg.message_id, meta))
            .collect())
    }

    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        let result = self.provider.query_latest_block().await?;
        Ok(result.block.header.height.value() as u32)
    }
}

#[async_trait]
impl SequenceIndexer<InterchainGasPayment> for CosmosInterchainGasPaymasterIndexer {
    async fn sequence_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        info!("Message delivery indexing not implemented");
        Ok((Some(1), 1))
    }
}

#[async_trait]
impl SequenceIndexer<H256> for CosmosInterchainGasPaymasterIndexer {
    async fn sequence_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        info!("Message delivery indexing not implemented");
        Ok((Some(1), 1))
    }
}
