use async_trait::async_trait;
use hyperlane_core::{
    ChainCommunicationError,
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, HyperlaneDomain, HyperlaneMessage,
    HyperlaneProvider, MultisigIsm, H160, H256,
};

use crate::{
    ConnectionConf,
    CosmosProvider,
    interchain_security_module::{
        LEGACY_MULTISIG_TYPE_URL,
        MERKLE_ROOT_MULTISIG_TYPE_URL,
        MESSAGE_ID_MULTISIG_TYPE_URL,
    },
    Signer,
};

use grpc_client::{LegacyMultiSig, MerkleRootMultiSig, MessageIdMultiSig};

pub mod grpc_client {
    tonic::include_proto!("hyperlane.ism.v1");
}

/// A reference to a MultisigIsm contract on some Cosmos chain
#[derive(Debug)]
pub struct CosmosMultisigIsm {
    domain: HyperlaneDomain,
    address: H256,
    provider: Box<CosmosProvider>,
}

impl CosmosMultisigIsm {
    pub fn new(
        conf: &ConnectionConf,
        locator: ContractLocator,
        signer: Signer,
    ) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer);
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
            provider: Box::new(provider),
        }
    }

    pub fn is_default_ism(&self) -> bool {
        if self.address.is_zero() {
            return true
        }
        false
    }
}

impl HyperlaneContract for CosmosMultisigIsm {
    fn address(&self) -> H256 {
        self.address.clone()
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

// Unpack any type
fn unpack_from_any<M>(msg: &prost_types::Any) -> ChainResult<M>
where M: prost::Message + Default,
{
    M::decode(&msg.value[..])
        .map_err(|e| ChainCommunicationError::from_other(e))
}

// Returns the multisig's val list and threshold
fn return_vals_and_threshold(vals: Vec<String>, threshold: u32) -> ChainResult<(Vec<H256>, u8)> {
    let vals_h256 = vals
        .into_iter()
        .map(|val| {
            H256::from(
                H160::from_slice(
                    hex::decode(val.trim_start_matches("0x"))
                        .map_err(|e| ChainCommunicationError::from_other(e))
                        .unwrap()
                        .as_slice()
                )
            )
        })
        .collect();
    Ok((vals_h256, threshold as u8))
}

// Unpack multisig any type and returns the val list and threshold
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
        let ism = match self.is_default_ism() {
            true => {
                let response = self.provider.query_origins_default_ism(message.origin).await?;
                response.default_ism.unwrap()
            }
            _ => {
                let response = self.provider.query_custom_ism(self.address()).await?;
                response.custom_ism.unwrap()
            }
        };
        proto_to_module_type(ism)
    }
}
