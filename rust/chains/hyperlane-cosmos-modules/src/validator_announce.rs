use async_trait::async_trait;

use hyperlane_core::{
    Announcement, ChainResult, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneProvider, SignedType, TxOutcome, ValidatorAnnounce, H256, H512, U256, ContractLocator,
};

use crate::{ConnectionConf, CosmosProvider, Signer};
use cosmrs::proto::Any as CosmrsAny;
use announce_grpc_client::MsgAnnouncement;
use prost::Message;
pub mod announce_grpc_client {
    tonic::include_proto!("hyperlane.announce.v1");
}

const MSG_ANNOUNCEMENT_TYPE_URL: &str = "/hyperlane.announce.v1.MsgAnnouncement";

/// A reference to a ValidatorAnnounce contract on some Cosmos chain
#[derive(Debug)]
pub struct CosmosValidatorAnnounce {
    domain: HyperlaneDomain,
    address: H256,
    conf: ConnectionConf,
    provider: Box<CosmosProvider>,
    signer: Signer,
}

impl CosmosValidatorAnnounce {
    /// create a new instance of CosmosValidatorAnnounce
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer.clone());
        Self {
            domain: locator.domain.clone(),
            address: locator.address,
            conf: conf.clone(),
            signer,
            provider: Box::new(provider),
        }
    }
}

impl HyperlaneContract for CosmosValidatorAnnounce {
    fn address(&self) -> H256 {
        self.address.clone()
    }
}

impl HyperlaneChain for CosmosValidatorAnnounce {
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

#[async_trait]
impl ValidatorAnnounce for CosmosValidatorAnnounce {
    // Query the storage locations given a set of validators
    async fn get_announced_storage_locations(
        &self,
        validators: &[H256],
    ) -> ChainResult<Vec<Vec<String>>> {
        let response = self.provider.query_announced_storage_locations(validators).await?;
        Ok(response)
    }

    // Announce this validator
    async fn announce(
        &self,
        announcement: SignedType<Announcement>,
        tx_gas_limit: Option<U256>,
    ) -> ChainResult<TxOutcome> {
        let msg = CosmrsAny {
            type_url: MSG_ANNOUNCEMENT_TYPE_URL.to_string(),
            value: MsgAnnouncement {
                sender: self.signer.bech32_address().clone(),
                validator: announcement.value.validator.as_bytes().to_vec(),
                storage_location: announcement.value.storage_location,
                signature: announcement.signature.to_vec(),
            }.encode_to_vec(),
        };


        let response = self.provider.send_tx(msg, tx_gas_limit).await?;
        Ok(TxOutcome {
            transaction_id: H512::from(H256::from_slice(hex::decode(response.txhash).unwrap().as_slice())),
            executed: response.code == 0,
            gas_used: U256::from(response.gas_used),
            gas_price: U256::from(response.gas_wanted),
        })
    }

    async fn announce_tokens_needed(&self, _announcement: SignedType<Announcement>) -> Option<U256> {
        None
    }
}
