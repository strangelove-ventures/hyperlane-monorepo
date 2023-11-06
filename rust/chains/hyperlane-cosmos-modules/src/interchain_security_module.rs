use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneMessage, HyperlaneProvider, InterchainSecurityModule, ModuleType, H256, U256,
};

use crate::{
    ConnectionConf, CosmosProvider, Signer,
};

pub const LEGACY_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.LegacyMultiSig";
pub const MERKLE_ROOT_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.MerkleRootMultiSig";
pub const MESSAGE_ID_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.MessageIdMultiSig";

#[derive(Debug)]
pub struct CosmosInterchainSecurityModule {
    domain: HyperlaneDomain,
    address: H256,
    conf: ConnectionConf,
    provider: Box<CosmosProvider>,
    signer: Signer,
}

impl CosmosInterchainSecurityModule {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer.clone());
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
            conf: conf.clone(),
            provider: Box::new(provider),
            signer,
        }
    }

    pub fn is_default_ism(&self) -> bool {
        if self.address.is_zero() {
            return true
        }
        false
    }
}

impl HyperlaneContract for CosmosInterchainSecurityModule {
    fn address(&self) -> H256 {
        self.address.clone()
    }
}

impl HyperlaneChain for CosmosInterchainSecurityModule {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(CosmosProvider::new(
            self.conf.clone(),
            self.domain.clone(),
            self.address().clone(),
            self.signer.clone(),
        ))
    }
}

fn proto_type_to_module_type(ism: prost_types::Any) -> ModuleType {
    match &*ism.type_url {
        LEGACY_MULTISIG_TYPE_URL => ModuleType::LegacyMultisig,
        MERKLE_ROOT_MULTISIG_TYPE_URL => ModuleType::MerkleRootMultisig,
        MESSAGE_ID_MULTISIG_TYPE_URL => ModuleType::MessageIdMultisig,
        _ => ModuleType::Null,
    }
}

#[async_trait]
impl InterchainSecurityModule for CosmosInterchainSecurityModule {
    async fn module_type(&self, origin: u32) -> ChainResult<ModuleType> {
        let ism = match self.is_default_ism() {
            true => {
                let response = self.provider.query_origins_default_ism(origin).await?;
                response.default_ism.unwrap()
            }
            _ => {
                let response = self.provider.query_custom_ism(self.address()).await?;
                response.custom_ism.unwrap()
            }
        };
        Ok(proto_type_to_module_type(ism))
    }

    async fn dry_run_verify(
        &self,
        _message: &HyperlaneMessage,
        _metadata: &[u8],
    ) -> ChainResult<Option<U256>> {
        Ok(Some(U256::zero()))
    }
}
