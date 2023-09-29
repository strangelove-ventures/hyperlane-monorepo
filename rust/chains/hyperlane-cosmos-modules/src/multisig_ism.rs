use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, HyperlaneDomain, HyperlaneMessage,
    HyperlaneProvider, MultisigIsm, H256,
};

/// A reference to a MultisigIsm contract on some Cosmos chain
#[derive(Debug)]
pub struct CosmosMultisigIsm {
    domain: HyperlaneDomain,
    address: H256,
}

impl CosmosMultisigIsm {
    pub fn new(locator: ContractLocator) -> Self {
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
        }
    }
}

impl HyperlaneContract for CosmosMultisigIsm {
    fn address(&self) -> H256 {
        self.address
    }
}

impl HyperlaneChain for CosmosMultisigIsm {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        todo!()
    }
}

#[async_trait]
impl MultisigIsm for CosmosMultisigIsm {
    /// Returns the validator and threshold needed to verify message
    async fn validators_and_threshold(
        &self,
        message: &HyperlaneMessage,
    ) -> ChainResult<(Vec<H256>, u8)> {
        todo!()
    }
}
