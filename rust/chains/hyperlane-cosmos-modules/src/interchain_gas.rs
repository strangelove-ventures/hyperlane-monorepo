use async_trait::async_trait;
use hyperlane_core::{
    ChainResult, ContractLocator, HyperlaneChain, HyperlaneContract, Indexer,
    InterchainGasPaymaster, SequenceIndexer, U256,
};
use hyperlane_core::{ChainCommunicationError, HyperlaneDomain, HyperlaneProvider, InterchainGasPayment, LogMeta, H256, H512};
use std::ops::RangeInclusive;
use tracing::info;
use cosmrs::tendermint::{
    abci::EventAttribute,
    hash::Algorithm,
    Hash,
};
use sha256::digest;

use crate::{Signer, ConnectionConf, CosmosProvider};

#[derive(Debug)]
pub struct CosmosInterchainGasPaymaster {
    conf: ConnectionConf,
    domain: HyperlaneDomain,
    address: H256,
    signer: Signer,
    _provider: Box<CosmosProvider>,
}

impl CosmosInterchainGasPaymaster {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer.clone());

        Self {
            conf: conf.clone(),
            domain: locator.domain.clone(),
            address: locator.address,
            signer,
            _provider: Box::new(provider),
        }
    }
}

impl HyperlaneContract for CosmosInterchainGasPaymaster {
    fn address(&self) -> H256 {
        self.address.clone()
    }
}

impl HyperlaneChain for CosmosInterchainGasPaymaster {
    fn domain(&self) -> &HyperlaneDomain {
        &self.domain
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        Box::new(CosmosProvider::new(
            self.conf.clone(),
            self.domain.clone(),
            self.address(),
            self.signer.clone(),
        ))
    }
}

impl InterchainGasPaymaster for CosmosInterchainGasPaymaster {}

#[derive(Debug)]
pub struct CosmosInterchainGasPaymasterIndexer {
    provider: Box<CosmosProvider>,
}

impl CosmosInterchainGasPaymasterIndexer {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer);
        Self {
            provider: Box::new(provider),
        }
    }

    // Parse IGP events
    fn parse_event(&self, attrs: Vec<EventAttribute>) -> ChainResult<InterchainGasPayment> {
        let mut res = InterchainGasPayment {
            message_id: H256::default(),
            payment: U256::default(),
            gas_amount: U256::default(),
        };
        for attr in attrs {
            let key = attr.key.as_str();
            let value = attr.value.as_str();

            info!("Attr: {:?}", key);
            match key {
                "messageid" => {
                    res.message_id = H256::from_slice(hex::decode(value.trim_start_matches("0x")).unwrap().as_slice())
                }
                "payment" => res.payment = U256::from_dec_str(value).unwrap(),
                "amount" => res.gas_amount = U256::from_dec_str(value).unwrap(),
                "igpid" => {
                    let id = H256::from_low_u64_be(value.parse().unwrap());
                    if id != self.provider.get_address() {
                        info!("Ignoring gas payment");
                        return Err(ChainCommunicationError::from_other_str("ignore gas payment"));
                    }
                }
                _ => {}
            }
        }
        Ok(res)
    }

    // Get block and parse IGP events
    async fn get_and_parse_block(&self, block_num: u32) -> ChainResult<Vec<(InterchainGasPayment, LogMeta)>> {
        let block = self.provider.query_block(block_num).await?;
        let block_results = self.provider.query_block_results(block_num).await?;
        let tx_results = block_results.txs_results;

        let tx_hash_vec: Vec<H256> = block
            .block
            .data
            .into_iter()
            .map(|tx| {
                H256::from_slice(
                    Hash::from_bytes(
                        Algorithm::Sha256,
                        hex::decode(digest(tx.as_slice())).unwrap().as_slice(),
                    )
                    .unwrap()
                    .as_bytes(),
                )
            })
            .collect();
        
        let mut result: Vec<(InterchainGasPayment, LogMeta)> = vec![];
        if let Some(tx_results) = tx_results {
            for (tx_idx, tx) in tx_results.iter().enumerate() {
                let tx_hash = tx_hash_vec[tx_idx];
                for (event_idx, event) in tx.events.clone().iter().enumerate() {
                    if event.kind.as_str() != "payforgas" {
                        continue;
                    }
                    let wrapped_msg = self.parse_event(event.attributes.clone());
                    if let Ok(msg) = wrapped_msg {
                        let meta = LogMeta {
                            address: self.provider.get_address(),
                            block_number: block_num as u64,
                            block_hash: H256::from_slice(block.block_id.hash.as_bytes()),
                            transaction_id: H512::from(tx_hash),
                            transaction_index: tx_idx as u64,
                            log_index: U256::from(event_idx),
                        };
                        result.push((msg, meta));
                    }
                }
            }
        }   
        Ok(result)
    }

}

#[async_trait]
impl Indexer<InterchainGasPayment> for CosmosInterchainGasPaymasterIndexer {
    // Iterate through a range of blocks for parsing IGP events
    async fn fetch_logs(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(InterchainGasPayment, LogMeta)>> {
        let mut result: Vec<(InterchainGasPayment, LogMeta)> = vec![];
        for block_number in range {
            let logs = self.get_and_parse_block(block_number).await?;
            result.extend(logs);
        }
        Ok(result)
    }

    // Query the latest block
    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        let result = self.provider.query_latest_block().await?;
        Ok(result.block.header.height.value() as u32)
    }
}

#[async_trait]
impl SequenceIndexer<InterchainGasPayment> for CosmosInterchainGasPaymasterIndexer {
    // Query the latest block
    async fn sequence_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        let tip = self.get_finalized_block_number().await?;
        Ok((Some(0), tip))
    }
}
