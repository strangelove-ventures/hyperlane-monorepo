use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client;
use hyperlane_core::{
    ChainCommunicationError, ChainResult, ContractLocator, Encode, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneMessage, HyperlaneProvider, InterchainSecurityModule, ModuleType, H256, U256,
};

use crate::{
    ConnectionConf, CosmosProvider,
};

pub const LEGACY_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.LegacyMultiSig";
pub const MERKLE_ROOT_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.MerkleRootMultiSig";
pub const MESSAGE_ID_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.MessageIdMultiSig";

#[derive(Debug)]
pub struct CosmosInterchainSecurityModule {
    domain: HyperlaneDomain,
    address: H256,
    provider: Box<CosmosProvider>,
}

impl CosmosInterchainSecurityModule {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address);
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
            provider: Box::new(provider),
        }
    }
}

impl HyperlaneContract for CosmosInterchainSecurityModule {
    fn address(&self) -> H256 {
        self.address
    }
}

impl HyperlaneChain for CosmosInterchainSecurityModule {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        todo!()
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
        let response = self.provider.query_origins_default_ism(origin).await?;
        Ok(proto_type_to_module_type(response.default_ism.unwrap()))
    }

    async fn dry_run_verify(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
    ) -> ChainResult<Option<U256>> {
        Ok(Some(U256::zero())) // TODO
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hyperlane_core::{HyperlaneDomainType, HyperlaneDomainProtocol};

    #[tokio::test]
    async fn test_module_type() {
        let ism = CosmosInterchainSecurityModule::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:45897".to_string(),
                rpc_url: "".to_string(),
            },
            ContractLocator { 
                domain: &HyperlaneDomain::Unknown {
                    domain_id: 0,
                    domain_name: "CosmosTest".to_string(),
                    domain_type: HyperlaneDomainType::LocalTestChain,
                    domain_protocol: HyperlaneDomainProtocol::Ethereum,
                },
                address: H256::default(),
            },
        );
        let module_type = ism.module_type(1).await.unwrap();
        assert_eq!(module_type, ModuleType::LegacyMultisig);
    }
}