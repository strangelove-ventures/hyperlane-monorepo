use async_trait::async_trait;

use hyperlane_core::{
    BlockInfo, ChainCommunicationError, ChainResult, ContractLocator,
    HyperlaneChain, HyperlaneDomain, HyperlaneProvider, TxnInfo, H256,
};

use crate::ConnectionConf;

use mailbox_grpc_client::query_client::QueryClient as MailboxQueryClient;
use mailbox_grpc_client::{QueryCurrentTreeMetadataRequest, QueryCurrentTreeMetadataResponse, QueryCurrentTreeRequest, QueryCurrentTreeResponse};
use ism_grpc_client::{
    query_client::QueryClient as IsmQueryClient,
    QueryOriginsDefaultIsmRequest, QueryOriginsDefaultIsmResponse,
    LegacyMultiSig, MerkleRootMultiSig, MessageIdMultiSig,
};
use cosmrs::rpc::{
    client::{Client, CompatMode, HttpClient, HttpClientUrl},
    endpoint::{
        block::Response as BlockResponse,
        block_results::Response as BlockResultsResponse,
    },
};
use cosmrs::tendermint::{
    abci::EventAttribute,
    hash::Algorithm,
    Hash,
};
pub mod mailbox_grpc_client {
    tonic::include_proto!("hyperlane.mailbox.v1");
}
pub mod ism_grpc_client {
    tonic::include_proto!("hyperlane.ism.v1");
}
/// A wrapper around a cosmos provider to get generic blockchain information.
#[derive(Debug)]
pub struct CosmosProvider {
    conf: ConnectionConf,
    domain: HyperlaneDomain,
    address: H256,
}

impl CosmosProvider {
    pub fn new(conf: ConnectionConf, domain: HyperlaneDomain, address: H256) -> Self {
        Self {
            conf,
            domain,
            address,
        }
    }

    fn get_rpc_url(&self) -> ChainResult<String> {
        Ok(self.conf.get_rpc_url())
    }
    
    fn get_grpc_url(&self) -> ChainResult<String> {
        Ok(self.conf.get_grpc_url())
    }

    fn get_rpc_client(&self) -> ChainResult<HttpClient> {
        let client = HttpClient::builder(self.get_rpc_url()?.parse().unwrap())
            .compat_mode(CompatMode::V0_37)
            .build()
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(client)
    }

    pub async fn query_current_tree(&self) -> ChainResult<QueryCurrentTreeResponse> {
        let mut client = MailboxQueryClient::connect(self.get_grpc_url()?).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryCurrentTreeRequest {});
        let response = client.current_tree(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        Ok(response)
    }

    pub async fn query_current_tree_metadata(&self) -> ChainResult<QueryCurrentTreeMetadataResponse> {
        let mut client = MailboxQueryClient::connect(self.get_grpc_url()?).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryCurrentTreeMetadataRequest {});
        let response = client.current_tree_metadata(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        Ok(response)
    }

    pub async fn query_origins_default_ism(&self, origin: u32) -> ChainResult<QueryOriginsDefaultIsmResponse> {
        let mut client = IsmQueryClient::connect(self.get_grpc_url()?).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryOriginsDefaultIsmRequest { origin });
        let response = client.origins_default_ism(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        Ok(response)
    }

    pub async fn query_latest_block(&self) -> ChainResult<BlockResponse> {
        let client = self.get_rpc_client()?;
        let result = client
            .latest_block()
            .await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(result)
    }

    pub async fn query_block(&self, block_num: u32) -> ChainResult<BlockResponse> {
        let client = self.get_rpc_client()?;
        let block = client.block(block_num).await.map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(block)
    }

    pub async fn query_block_results(&self, block_num: u32) -> ChainResult<BlockResultsResponse> {
        let client = self.get_rpc_client()?;
        let block_results = client.block_results(block_num).await.map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(block_results)
    }

}

impl HyperlaneChain for CosmosProvider {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(CosmosProvider {
            conf: self.conf.clone(),
            domain: self.domain.clone(),
            address: self.address.clone(),
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
