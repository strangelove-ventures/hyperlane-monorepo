use async_trait::async_trait;

use hyperlane_core::{
    BlockInfo, ChainResult, HyperlaneChain, HyperlaneDomain, HyperlaneProvider, TxnInfo, H256,
};

/// A wrapper around a cosmos provider to get generic blockchain information.
#[derive(Debug)]
pub struct CosmosProvider {
    domain: HyperlaneDomain,
}

impl CosmosProvider {
    pub fn new(domain: HyperlaneDomain) -> Self {
        Self { domain }
    }
}

impl HyperlaneChain for CosmosProvider {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(CosmosProvider {
            domain: self.domain.clone(),
        })
    }
}

#[async_trait]
impl HyperlaneProvider for CosmosProvider {
    async fn get_block_by_hash(&self, hash: &H256) -> ChainResult<BlockInfo> {
        todo!()
    }

    async fn get_txn_by_hash(&self, hash: &H256) -> ChainResult<TxnInfo> {
        todo!()
    }

    async fn is_contract(&self, address: &H256) -> ChainResult<bool> {
        Ok(true) // Non-contracts will be supported, so this is a nop
    }
}
