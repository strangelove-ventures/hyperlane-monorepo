use async_trait::async_trait;
use hyperlane_core::{
    ChainCommunicationError,
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, HyperlaneDomain, HyperlaneMessage,
    HyperlaneProvider, MultisigIsm, H256,
};

use crate::{
    ConnectionConf,
    interchain_security_module::{
        LEGACY_MULTISIG_TYPE_URL,
        MERKLE_ROOT_MULTISIG_TYPE_URL,
        MESSAGE_ID_MULTISIG_TYPE_URL,
    }
};

use grpc_client::{
    query_client::QueryClient,
    QueryOriginsDefaultIsmRequest, QueryOriginsDefaultIsmResponse,
    LegacyMultiSig, MerkleRootMultiSig, MessageIdMultiSig,
};

pub mod grpc_client {
    tonic::include_proto!("hyperlane.ism.v1");
}

/// A reference to a MultisigIsm contract on some Cosmos chain
#[derive(Debug)]
pub struct CosmosMultisigIsm {
    domain: HyperlaneDomain,
    address: H256,
    grpc_url: String,
}

impl CosmosMultisigIsm {
    pub fn new(
        conf: &ConnectionConf,
        locator: ContractLocator
    ) -> Self {
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
            grpc_url: conf.get_grpc_url(),
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

fn unpack_from_any<M>(msg: &prost_types::Any) -> ChainResult<M>
where M: prost::Message + Default,
{
    M::decode(&msg.value[..])
        .map_err(|e| ChainCommunicationError::from_other(e))
}

fn return_vals_and_threshold(vals: Vec<String>, threshold: u32) -> ChainResult<(Vec<H256>, u8)> {
    let vals_h256 = vals
        .into_iter()
        .map(|val| {
            H256::from_slice(
                hex::decode(val.trim_start_matches("0x"))
                    .map_err(|e| ChainCommunicationError::from_other(e))
                    .unwrap()
                    .as_slice()
            )
        })
        .collect();
    Ok((vals_h256, threshold as u8))
}

fn proto_to_module_type(ism: prost_types::Any) -> ChainResult<(Vec<H256>, u8)> {
    match &*ism.type_url {
        LEGACY_MULTISIG_TYPE_URL => {
            let lm = unpack_from_any::<LegacyMultiSig>(&ism)?;
            return_vals_and_threshold(lm.validator_pub_keys, lm.threshold)
        }
        MERKLE_ROOT_MULTISIG_TYPE_URL => {
            let mrm = unpack_from_any::<MerkleRootMultiSig>(&ism)?;
            return_vals_and_threshold(mrm.validator_pub_keys, mrm.threshold)
        }
        MESSAGE_ID_MULTISIG_TYPE_URL => {
            let mim = unpack_from_any::<MessageIdMultiSig>(&ism)?;
            return_vals_and_threshold(mim.validator_pub_keys, mim.threshold)
        }
        _ => Err(ChainCommunicationError::from_other_str("Unknown multisig type")),
    }
}

#[async_trait]
impl MultisigIsm for CosmosMultisigIsm {
    /// Returns the validator and threshold needed to verify message
    async fn validators_and_threshold(
        &self,
        message: &HyperlaneMessage,
    ) -> ChainResult<(Vec<H256>, u8)> {
        let mut client = QueryClient::connect(self.grpc_url.clone()).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryOriginsDefaultIsmRequest { origin: message.origin });
        let response = client.origins_default_ism(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        
        proto_to_module_type(response.default_ism.unwrap())
    }
}
