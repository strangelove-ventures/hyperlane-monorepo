use async_trait::async_trait;

use hyperlane_core::{
    BlockInfo, ChainCommunicationError, ChainResult, ContractLocator,
    HyperlaneChain, HyperlaneDomain, HyperlaneMessage, HyperlaneProvider, 
    RawHyperlaneMessage, TxnInfo, H256, U256,
};

use crate::{
    ConnectionConf,
    signers::Signer,
};

use mailbox_grpc_client::{
    query_client::QueryClient as MailboxQueryClient,
    QueryCurrentTreeMetadataRequest, QueryCurrentTreeMetadataResponse, 
    QueryCurrentTreeRequest, QueryCurrentTreeResponse,
    QueryMsgDeliveredRequest, QueryMsgDeliveredResponse,
    MsgProcess,
};
use ism_grpc_client::{
    query_client::QueryClient as IsmQueryClient,
    QueryOriginsDefaultIsmRequest, QueryOriginsDefaultIsmResponse,
    LegacyMultiSig, MerkleRootMultiSig, MessageIdMultiSig,
};
use cosmrs::{
    Amount, Coin,
    crypto::secp256k1::SigningKey,
    proto::{
        cosmos::{
            auth::v1beta1::{
                BaseAccount,
                query_client::QueryClient as QueryAccountClient, QueryAccountRequest,
            },
            base::abci::v1beta1::TxResponse,
            tx::v1beta1::{
                service_client::ServiceClient as TxServiceClient,
                BroadcastMode, BroadcastTxRequest, SimulateRequest, SimulateResponse,
            },
        },
        traits::Message as CosmrsMessage,
        Any as CosmrsAny, ibc::core::client,
    },
    rpc::{
        client::{Client, CompatMode, HttpClient, HttpClientUrl},
        endpoint::{
            block::Response as BlockResponse,
            block_results::Response as BlockResultsResponse,
        },
    },
    tendermint::{
        abci::EventAttribute,
        hash::Algorithm,
        Hash,
    },
    tx::{
        Body, Fee, MessageExt, SignDoc, SignerInfo,
    }
};
use prost::Message;
use prost_types::Any;
use std::str::FromStr;

pub mod mailbox_grpc_client {
    tonic::include_proto!("hyperlane.mailbox.v1");
}
pub mod ism_grpc_client {
    tonic::include_proto!("hyperlane.ism.v1");
}

const DEFAULT_GAS_PRICE: f32 = 0.05;
const DEFAULT_GAS_ADJUSTMENT: f32 = 1.25;

/// A wrapper around a cosmos provider to get generic blockchain information.
#[derive(Debug)]
pub struct CosmosProvider {
    conf: ConnectionConf,
    domain: HyperlaneDomain,
    address: H256,
    signer: Signer,
}

impl CosmosProvider {
    pub fn new(conf: ConnectionConf, domain: HyperlaneDomain, address: H256, signer: Signer) -> Self {
        Self {
            conf,
            domain,
            address,
            signer,
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

    pub async fn query_delivered(&self, id: H256) -> ChainResult<bool> {
        let mut client = MailboxQueryClient::connect(self.get_grpc_url()?).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryMsgDeliveredRequest {
            message_id: id.as_bytes().to_vec(),
        });
        let response = client.msg_delivered(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        Ok(response.delivered)
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

    async fn account_query(&self, account: String) -> ChainResult<BaseAccount> {
        let mut client = QueryAccountClient::connect(self.get_grpc_url()?).await.unwrap();

        let request = QueryAccountRequest { address: account };
        let response = client.account(request).await.unwrap().into_inner();

        let account = BaseAccount::decode(response.account.unwrap().value.as_slice()).unwrap();
        Ok(account)
    }

    async fn simulate_raw_tx(&self, msgs: Vec<CosmrsAny>, gas_limit: Option<U256>) -> ChainResult<SimulateResponse> {
        let mut client = TxServiceClient::connect(self.get_grpc_url()?).await.unwrap();

        let tx_bytes = self.generate_raw_tx(msgs, gas_limit).await?;
        let sim_req = SimulateRequest { tx: None, tx_bytes };
        let mut sim_res = client.simulate(sim_req).await.unwrap().into_inner();

        // apply gas adjustment
        sim_res.gas_info.as_mut().map(|v| {
            v.gas_used = (v.gas_used as f32 * DEFAULT_GAS_ADJUSTMENT) as u64;
            v
        });

        Ok(sim_res)
    }

    async fn generate_raw_tx(&self, msgs: Vec<CosmrsAny>, gas_limit: Option<U256>) -> ChainResult<Vec<u8>> {
        let account_info = self.account_query(self.signer.bech32_address().clone()).await?;

        let private_key = SigningKey::from_slice(&self.signer.private_key()).unwrap();
        let public_key = private_key.public_key();

        let tx_body = Body::new(msgs, "", 900u16);
        let signer_info = SignerInfo::single_direct(Some(public_key), account_info.sequence);

        let gas_limit: u64 = gas_limit
            .unwrap_or(U256::from_str("300000").unwrap())
            .as_u64();

        let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(
            Coin::new(
                Amount::from((gas_limit as f32 * DEFAULT_GAS_PRICE) as u64),
                format!("{}", self.signer.base_denom().clone()).as_str(),
            )
            .unwrap(),
            gas_limit,
        ));

        // signing
        let sign_doc = SignDoc::new(
            &tx_body,
            &auth_info,
            &self.conf.get_chain_id().parse().unwrap(),
            account_info.account_number,
        )
        .unwrap();

        let tx_signed = sign_doc.sign(&private_key).unwrap();

        Ok(tx_signed.to_bytes().unwrap())
    }

    pub async fn send_tx(&self, msg: CosmrsAny, gas_limit: Option<U256>) -> ChainResult<TxResponse> {
        let msgs = vec![msg];

        let tx_req = BroadcastTxRequest {
            tx_bytes: self.generate_raw_tx(msgs, gas_limit).await?,
            mode: BroadcastMode::Sync as i32,
        };
        
        let mut client = TxServiceClient::connect(self.get_grpc_url()?).await.unwrap();
        let tx_res = client
            .broadcast_tx(tx_req)
            .await.unwrap()
            .into_inner()
            .tx_response
            .unwrap();
        if tx_res.code != 0 {
            println!("TX_ERROR: {}", tx_res.raw_log)
        }

        Ok(tx_res)
    }

    pub async fn simulate_tx(&self, msg: CosmrsAny) -> ChainResult<SimulateResponse> {
        let msgs = vec![msg];

        let response = self.simulate_raw_tx(msgs, None).await?;
        Ok(response)
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
            signer: self.signer.clone(),
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
