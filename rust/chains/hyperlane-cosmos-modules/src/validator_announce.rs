use async_trait::async_trait;

use hyperlane_core::{
    Announcement, ChainResult, HyperlaneChain, HyperlaneContract, HyperlaneDomain,
    HyperlaneProvider, SignedType, TxOutcome, ValidatorAnnounce, H256, H512, U256, ContractLocator,
};

use crate::{ConnectionConf, CosmosProvider, Signer};
use cosmrs::proto::{
    traits::Message as CosmrsMessage,
    Any as CosmrsAny,
};
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
    async fn get_announced_storage_locations(
        &self,
        validators: &[H256],
    ) -> ChainResult<Vec<Vec<String>>> {
        let response = self.provider.query_announced_storage_locations(validators).await?;
        Ok(response)
    }

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

    async fn announce_tokens_needed(&self, announcement: SignedType<Announcement>) -> Option<U256> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperlane_core::{H160, Signature, HyperlaneDomainType, HyperlaneDomainProtocol, Signable};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_announce() {
        let announce = CosmosValidatorAnnounce::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:36343".to_string(),
                rpc_url: "http://127.0.0.1:38325".to_string(),
                chain_id: "simd1".to_string(),
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
            Signer::new(
                hex::decode("a011942e70462913d8e2f26a36d487c221dc0b4ca7fc502bd3490c84f98aa0cd").unwrap(), 
                "cosmos".to_string(),
                "stake".to_string(),
            ),
        );

        let announcement = Announcement {
            validator: H160::from_str("0x13DFDeB827D4D7fACE707fAdbfd4D651438B4aB3").unwrap(),
            mailbox_address: H256::from_slice(hex::decode("000000000000000000000000cc2a110c8df654a38749178a04402e88f65091d3").unwrap().as_slice()),
            mailbox_domain: 23456,
            storage_location: "file:///tmp/TestAnnounce1945637263/001/signatures-simd1".to_string(),
        };

        assert_eq!(hex::encode(announcement.eth_signed_message_hash()), "");
        let signed_announcement = SignedType {
            value: announcement,
            signature: Signature{
                r: U256::from(hex::decode("da623ce25c6603cdc254061c7217905c820f59d336c440c1c75b04223d71afac").unwrap().as_slice()),
                s: U256::from(hex::decode("63953f87e366b097849212e549bcc61262d016daedd4224cafb115d0ffab1af0").unwrap().as_slice()),
                v: 0,
            },
        };

        let response = announce.announce(signed_announcement, None).await.unwrap();
        assert_eq!(response.executed, true);

    }


    #[tokio::test]
    async fn test_get_announced_storage_locations() {
        let announce = CosmosValidatorAnnounce::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:36343".to_string(),
                rpc_url: "http://127.0.0.1:38325".to_string(),
                chain_id: "hsimd-1".to_string(),
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
            Signer::new(
                hex::decode("a011942e70462913d8e2f26a36d487c221dc0b4ca7fc502bd3490c84f98aa0cd").unwrap(), 
                "cosmos".to_string(),
                "stake".to_string(),
            ),
        );

        let validators = vec![H256::from(H160::from_str("0x13DFDeB827D4D7fACE707fAdbfd4D651438B4aB3").unwrap())];
       let locations = announce.get_announced_storage_locations(validators.as_ref()).await.unwrap();
       assert_eq!(locations[0][0], "s3://test-storage-location-foo/us-east-1".to_string())

    }

}