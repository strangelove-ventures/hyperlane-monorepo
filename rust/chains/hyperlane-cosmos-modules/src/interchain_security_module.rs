use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client;
use hyperlane_core::{
    ChainCommunicationError, ChainResult, ContractLocator, Encode, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneMessage, HyperlaneProvider, InterchainSecurityModule, ModuleType, H256, U256,
};

use crate::{
    ConnectionConf, CosmosProvider,
};

use grpc_client::{
    query_client::QueryClient,
    QueryOriginsDefaultIsmRequest, QueryOriginsDefaultIsmResponse,
    LegacyMultiSig, MerkleRootMultiSig, MessageIdMultiSig,
};

pub mod grpc_client {
    tonic::include_proto!("hyperlane.ism.v1");
}

pub const LEGACY_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.LegacyMultiSig";
pub const MERKLE_ROOT_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.MerkleRootMultiSig";
pub const MESSAGE_ID_MULTISIG_TYPE_URL: &str = "/hyperlane.ism.v1.MessageIdMultiSig";

#[derive(Debug)]
pub struct CosmosInterchainSecurityModule {
    domain: HyperlaneDomain,
    address: H256,
    grpc_url: String,
}

impl CosmosInterchainSecurityModule {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator) -> Self {
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
            grpc_url: conf.get_grpc_url(),
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
        let mut client = QueryClient::connect(self.grpc_url.clone()).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryOriginsDefaultIsmRequest { origin });
        let response = client.origins_default_ism(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        
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
