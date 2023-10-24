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
    provider: Box<CosmosProvider>,
}

impl CosmosInterchainGasPaymaster {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer.clone());

        Self {
            conf: conf.clone(),
            domain: locator.domain.clone(),
            address: locator.address,
            signer,
            provider: Box::new(provider),
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
                "payment" => res.payment = value.parse().unwrap(),
                "amount" => res.gas_amount = value.parse().unwrap(),
                _ => {}
            }
        }
        Ok(res)
    }

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
                    // TODO: filter out IGP number/index
                    let msg = self.parse_event(event.attributes.clone())?;
                    let meta = LogMeta {
                        address: H256::from_slice(hex::decode("000000000000000000000000cc2a110c8df654a38749178a04402e88f65091d3").unwrap().as_ref()),
                        block_number: block_num as u64,
                        block_hash: H256::from_slice(block.block_id.hash.as_bytes()),
                        transaction_id: H512::from(tx_hash),
                        transaction_index: tx_idx as u64,
                        log_index: U256::from(event_idx),
                    };
                    println!("meta: block_num: {:?}, transaction_idx: {:?}", block_num, tx_idx);
                    println!("tx_hash: {:?}", hex::encode(tx_hash.0));
                    result.push((msg, meta));
                }
            }
        }   
        Ok(result)
    }

}

#[async_trait]
impl Indexer<InterchainGasPayment> for CosmosInterchainGasPaymasterIndexer {
    async fn fetch_logs(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(InterchainGasPayment, LogMeta)>> {
        let mut result: Vec<(InterchainGasPayment, LogMeta)> = vec![];
        info!("Indexer<InterchainGasPayment>: fetch_logs {:?}2", range);
        for block_number in range {
            let logs = self.get_and_parse_block(block_number).await?;
            result.extend(logs);
        }
        Ok(result)
    }

    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        info!("Indexer<InterchainGasPayment>: get_finalized_block_number");
        let result = self.provider.query_latest_block().await?;
        Ok(result.block.header.height.value() as u32)
    }
}

#[async_trait]
impl SequenceIndexer<InterchainGasPayment> for CosmosInterchainGasPaymasterIndexer {
    async fn sequence_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        let tip = self.get_finalized_block_number().await?;
        println!("CosmosInterchainGasPaymasterIndexer: sequence_and_tip: count: 0, tip: {:?}", tip);
        Ok((Some(0), tip))
    }
}
