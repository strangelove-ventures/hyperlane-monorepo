use std::fmt::{Debug, Formatter};
use std::num::NonZeroU64;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use url::Url;

use async_trait::async_trait;
use eyre::Result;
use hyperlane_core::{
    accumulator::{
        TREE_DEPTH,
        incremental::IncrementalMerkle, 
    },
    utils::fmt_bytes, ChainCommunicationError,
    ChainResult, Checkpoint, ContractLocator, HyperlaneChain, HyperlaneContract, HyperlaneDomain, HyperlaneMessage,
    HyperlaneProvider, Indexer, LogMeta, Mailbox, SequenceIndexer, TxCostEstimate, TxOutcome, H256, H512, U256,
    RawHyperlaneMessage,
};

use cosmrs::{
    tendermint::{
        abci::EventAttribute,
        hash::Algorithm,
        Hash,
    },
    proto::{
        traits::Message as CosmrsMessage,
        Any as CosmrsAny,
    },
};
use sha256::digest;

use crate::{ConnectionConf, CosmosProvider, Signer, };

use mailbox_grpc_client::MsgProcess;
use prost::Message;

pub mod mailbox_grpc_client {
    tonic::include_proto!("hyperlane.mailbox.v1");
}

const MSG_PROCESS_TYPE_URL: &str = "/hyperlane.mailbox.v1.MsgProcess";

/// A reference to a Mailbox contract on some Cosmos chain
pub struct CosmosMailbox {
    domain: HyperlaneDomain,
    mailbox_address: H256,
    conf: ConnectionConf,
    provider: Box<CosmosProvider>,
    signer: Signer,
}

impl CosmosMailbox {
    pub fn new(
        conf: &ConnectionConf,
        locator: ContractLocator,
        signer: Signer,
    ) -> ChainResult<Self> {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer.clone());
        Ok(Self {
            domain: locator.domain.clone(),
            mailbox_address: provider.get_address(),
            conf: conf.clone(),
            provider: Box::new(provider),
            signer,
        })
    }
}

impl HyperlaneContract for CosmosMailbox {
    fn address(&self) -> H256 {
        self.mailbox_address.clone()
    }
}

impl HyperlaneChain for CosmosMailbox {
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

impl Debug for CosmosMailbox {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self as &dyn HyperlaneContract)
    }
}

#[async_trait]
impl Mailbox for CosmosMailbox {
    #[instrument(level = "debug", err, ret, skip(self))]
    async fn tree(&self, lag: Option<NonZeroU64>) -> ChainResult<IncrementalMerkle> {
        let response = self.provider.query_current_tree().await?;
        let mut branches: [H256; TREE_DEPTH] = Default::default();
        response.branches
            .iter()
            .enumerate()
            .for_each(|(i, elem)| {
                let elem_copy = elem.clone();
                if(!elem_copy.is_empty()) {
                    let branch: [u8; 32] = elem_copy.try_into().unwrap();
                    branches[i] = H256::from(branch);
                }
                else {
                    branches[i] = H256::zero();
                }
            });
        println!("tree: count: {:?}", response.count);
        Ok(IncrementalMerkle::new(
            branches,
            response.count.try_into().unwrap(),
        ))
    }

    #[instrument(level = "debug", err, ret, skip(self))]
    async fn count(&self, lag: Option<NonZeroU64>) -> ChainResult<u32> {
        let response = self.provider.query_current_tree_metadata().await?;
        let count = response.count;
        println!("count: {:?}", count);
        Ok(count)
    }

    #[instrument(level = "debug", err, ret, skip(self))]
    async fn delivered(&self, id: H256) -> ChainResult<bool> {
        let delivered = self.provider.query_delivered(id).await?;
        Ok(delivered)
    }

    #[instrument(level = "debug", err, ret, skip(self))]
    async fn latest_checkpoint(&self, lag: Option<NonZeroU64>) -> ChainResult<Checkpoint> {
        let response = self.provider.query_current_tree_metadata().await?;
        let root: [u8; 32] = response.root.try_into().unwrap();
        println!("latest_checkpoint: index: {:?}", response.count);
        Ok(Checkpoint { 
            mailbox_address: self.mailbox_address,
            mailbox_domain: self.domain.id(),
            root: H256::from(root),
            index: response.count-1
        })
    }

    #[instrument(err, ret, skip(self))]
    async fn default_ism(&self) -> ChainResult<H256> {
        Ok(H256::default()) // Change this to the acc addr of "hyperlane-ism" module
    }

    #[instrument(err, ret, skip(self))]
    async fn recipient_ism(&self, recipient: H256) -> ChainResult<H256> {
        self.provider.query_recipients_ism_id(recipient).await
    }

    // relayer only
    #[instrument(err, ret, skip(self))]
    async fn process(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
        tx_gas_limit: Option<U256>,
    ) -> ChainResult<TxOutcome> {
        let msg_hex = "0x".to_string() + &hex::encode(RawHyperlaneMessage::from(message));
        let metadata_hex = "0x".to_string() + &hex::encode(metadata);

        let msg = CosmrsAny {
            type_url: MSG_PROCESS_TYPE_URL.to_string(),
            value: MsgProcess {
                    sender: self.signer.bech32_address().clone(),
                    metadata: metadata_hex,
                    message: msg_hex,
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

    //relayer only
    #[instrument(err, ret, skip(self), fields(msg=%message, metadata=%fmt_bytes(metadata)))]
    async fn process_estimate_costs(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
    ) -> ChainResult<TxCostEstimate> {
        let msg_hex = "0x".to_string() + &hex::encode(RawHyperlaneMessage::from(message));
        let metadata_hex = "0x".to_string() + &hex::encode(metadata);

        let msg = CosmrsAny {
            type_url: MSG_PROCESS_TYPE_URL.to_string(),
            value: MsgProcess {
                    sender: self.signer.bech32_address().clone(),
                    metadata: metadata_hex,
                    message: msg_hex,
                }.encode_to_vec(),
        };

        let response = self.provider.simulate_tx(msg).await?;
        let result = TxCostEstimate {
            gas_limit: U256::from(response.gas_info.unwrap().gas_used),
            gas_price: U256::from(2500),
            l2_gas_limit: None,
        };
        Ok(result)
    }

    // not required
    fn process_calldata(&self, message: &HyperlaneMessage, metadata: &[u8]) -> Vec<u8> {
        todo!()
    }
}

/// Retrieves event data for a Cosmos chain that uses the hyperlane modules.
#[derive(Debug)]
pub struct CosmosMailboxIndexer {
    provider: Box<CosmosProvider>,
}

impl CosmosMailboxIndexer {
    pub fn new(conf: &ConnectionConf, locator: ContractLocator, signer: Signer) -> Self {
        let provider = CosmosProvider::new(conf.clone(), locator.domain.clone(), locator.address, signer);
        Self {
            provider: Box::new(provider),
        }
    }

    fn parse_event(&self, attrs: Vec<EventAttribute>) -> ChainResult<HyperlaneMessage> {
        let mut res = HyperlaneMessage::default();
        for attr in attrs {
            let key = attr.key.as_str();
            let value = attr.value.as_str();

            match key {
                "destination" => res.destination = value.parse().map_err(|e| ChainCommunicationError::from_other(e))?,
                "message" => res.body = hex::decode(value.trim_start_matches("0x"))
                    .map_err(|e| ChainCommunicationError::from_other(e))?,
                "nonce" => res.nonce = value.parse().map_err(|e| ChainCommunicationError::from_other(e))?,
                "origin" => res.origin = value.parse().map_err(|e| ChainCommunicationError::from_other(e))?,
                "recipient" => {
                    let mut recipient = hex::decode(value.trim_start_matches("0x"))
                        .map_err(|e| ChainCommunicationError::from_other(e))?;
                    if recipient.len() == 20 {
                        let tmp = vec![0u8; 12];
                        recipient = [tmp, recipient].concat();
                    }
                    res.recipient = 
                        H256::from_slice(recipient.as_slice());
                }
                "sender" => res.sender = 
                    H256::from_slice(hex::decode(value.trim_start_matches("0x"))
                        .map_err(|e| ChainCommunicationError::from_other(e))?.as_slice()),
                "version" => res.version = value.parse().map_err(|e| ChainCommunicationError::from_other(e))?,
                _ => {}
            }
        }
        Ok(res)
    }

    async fn get_and_parse_block(&self, block_num: u32) -> ChainResult<Vec<(HyperlaneMessage, LogMeta)>> {
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
        
        let mut result: Vec<(HyperlaneMessage, LogMeta)> = vec![];
        if let Some(tx_results) = tx_results {
            for (tx_idx, tx) in tx_results.iter().enumerate() {
                let tx_hash = tx_hash_vec[tx_idx];
                for (event_idx, event) in tx.events.clone().iter().enumerate() {
                    if event.kind.as_str() != "dispatch" {
                        continue;
                    }
                    let msg = self.parse_event(event.attributes.clone())?;
                    let meta = LogMeta {
                        address: self.provider.get_address(),
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
impl Indexer<HyperlaneMessage> for CosmosMailboxIndexer {
    async fn fetch_logs(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(HyperlaneMessage, LogMeta)>> {
        let mut result: Vec<(HyperlaneMessage, LogMeta)> = vec![];
        for block_number in range {
            let logs = self.get_and_parse_block(block_number).await?;
            result.extend(logs);
        }
        Ok(result)
    }

    /// Fetches the latest finalized block number from Cosmos API (aka LCD). Cosmos chains have fast finality.
    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        let result = self.provider.query_latest_block().await?;
        println!("get_finalized_block_number: {:?}", result.block.header.height.value() as u32);
        Ok(result.block.header.height.value() as u32)
    }
}

#[async_trait]
impl SequenceIndexer<HyperlaneMessage> for CosmosMailboxIndexer {
    async fn sequence_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        let tip = self.get_finalized_block_number().await?;
        let response = self.provider.query_current_tree_metadata().await?;
        println!("CosmosMailboxIndexer: sequence_and_tip: count: {:?}, tip: {:?}", response.count, tip);
        Ok((Some(response.count), tip))
    }
}
