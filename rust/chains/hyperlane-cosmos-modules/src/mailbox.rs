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
            // TODO: pass in on mailbox creation
            mailbox_address: H256::from_slice(hex::decode("000000000000000000000000cc2a110c8df654a38749178a04402e88f65091d3").unwrap().as_ref()),
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
        self.default_ism().await // Return default ism until non-default ISMs are supported
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyperlane_core::{HyperlaneDomainType, HyperlaneDomainProtocol};

    #[tokio::test]
    async fn test_mailbox_count() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:1234".to_string(),
                rpc_url: "".to_string(),
                chain_id: "".to_string(),
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
        ).unwrap();

        let count = mailbox.count(None).await.unwrap();
        println!("Count: {:?}", count);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_mailbox_tree() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:1234".to_string(),
                rpc_url: "".to_string(),
                chain_id: "".to_string(),
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
        ).unwrap();

        let im = mailbox.tree(None).await.unwrap();
        assert_eq!(im.count(), 1);
    }

    #[tokio::test]
    async fn test_mailbox_latest_checkpoint() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:1234".to_string(),
                rpc_url: "".to_string(),
                chain_id: "".to_string(),
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
        ).unwrap();

        let cp = mailbox.latest_checkpoint(None).await.unwrap();
        assert_eq!(cp.index, 1);
    }

    #[tokio::test]
    async fn test_mailbox_process() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "http://127.0.0.1:40971".to_string(),
                rpc_url: "http://127.0.0.1:36487".to_string(),
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
        ).unwrap();

        let msg = HyperlaneMessage{
                version: 0,
                nonce: 0,
                origin: 1,
                sender: H256::from_slice(&hex::decode("000000000000000000000000bcb815f38D481a5EBA4D7ac4c9E74D9D0FC2A7e7").unwrap()),
                destination: 12345,
                recipient: H256::from_slice(&hex::decode("ade4a5f5803a439835c636395a8d648dee57b2fc90d98dc17fa887159b69638b").unwrap()),
                body: "TestRelayer".as_bytes().to_vec(),
            };

        let delivered = mailbox.delivered(msg.id()).await.unwrap();
        assert_eq!(delivered, false);

        let response = mailbox.process(
            &msg,
            hex::decode("9d602d36f4ae1cdcb3a86af8b1627ad7836385ad8a0dd3666b21aae5dc4f760e0000000031323334353637383930313233343536373839303132333435363738393031320000000000000000000000000000000000000000000000000000000000000000ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d3021ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85e58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a193440eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968ffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f839867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756afcefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0f9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5f8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf8923490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99cc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8beccda7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d22733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981fe1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0b46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0c65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2f4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd95a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e3774df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652cdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618db8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea32293237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d7358448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a902055007fe9cf7f779d562f223a4311d16976129ac4580499cf72f2802acfb7e750509de7280b6e077ea46bc225e4afdafaff738e231e7fed38abc821b5eec44170053c74b0caf2d562137135bac4a14f08fe96e5988365eccbe3e8a78aac6802f57442256dacebca270cbde433bd0056b6a433f05f7682e5d661bf673359317b4cc00").unwrap().as_slice(), 
            None,
        ).await.unwrap();
        assert_eq!(response.executed, true); 

        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        let delivered = mailbox.delivered(msg.id()).await.unwrap();
        assert_eq!(delivered, true);

    }

    #[tokio::test]
    async fn test_mailbox_indexer_fetch_logs() {
        let indexer = CosmosMailboxIndexer::new(
            &ConnectionConf{
                grpc_url: "".to_string(),
                rpc_url: "http://127.0.0.1:1234".to_string(),
                chain_id: "".to_string(),
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
        let logs = indexer.fetch_logs(RangeInclusive::new(45, 48)).await.unwrap();
        assert_eq!(logs[0].0.origin, 12345);
    }

    #[tokio::test]
    async fn test_mailbox_indexer_get_finalized_block_number() {
        let indexer = CosmosMailboxIndexer::new(
            &ConnectionConf{
                grpc_url: "".to_string(),
                rpc_url: "http://127.0.0.1:1234".to_string(),
                chain_id: "".to_string(),
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
        let block_num = indexer.get_finalized_block_number().await.unwrap();
        assert_eq!(block_num, 10);
    }
}
