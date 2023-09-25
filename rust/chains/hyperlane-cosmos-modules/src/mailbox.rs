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
    ChainResult, Checkpoint, HyperlaneChain, HyperlaneContract, HyperlaneDomain, HyperlaneMessage,
    HyperlaneProvider, Indexer, LogMeta, Mailbox, SequenceIndexer, TxCostEstimate, TxOutcome, H256, H512, U256,
};

use grpc_client::query_client::QueryClient;
use grpc_client::{QueryCurrentTreeMetadataRequest, QueryCurrentTreeMetadataResponse, QueryCurrentTreeRequest, QueryCurrentTreeResponse};
use cosmrs::rpc::client::{Client, CompatMode, HttpClient, HttpClientUrl};
use cosmrs::tendermint::abci::EventAttribute;

use crate::ConnectionConf;

pub mod grpc_client {
    tonic::include_proto!("hyperlane.mailbox.v1");
}

/// A reference to a Mailbox contract on some Cosmos chain
pub struct CosmosMailbox {
    domain: HyperlaneDomain,
    grpc_url: String,
    mailbox_address: H256,
}

impl CosmosMailbox {
    pub fn new(
        conf: &ConnectionConf,
        domain: HyperlaneDomain,
        //grpc_address: String,
    ) -> ChainResult<Self> {
        Ok(Self {
            domain,
            grpc_url: conf.get_grpc_url(),
            mailbox_address: H256::default(),
        })
    }
}

impl HyperlaneContract for CosmosMailbox {
    fn address(&self) -> H256 {
        todo!()
    }
}

impl HyperlaneChain for CosmosMailbox {
    fn domain(&self) -> &HyperlaneDomain {
        todo!()
    }

    fn provider(&self) -> Box<dyn HyperlaneProvider> {
        todo!()
    }
}

impl Debug for CosmosMailbox {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self as &dyn HyperlaneContract)
    }
}

#[async_trait]
impl Mailbox for CosmosMailbox {
    // Val requirement
    #[instrument(level = "debug", err, ret, skip(self))]
    async fn tree(&self, lag: Option<NonZeroU64>) -> ChainResult<IncrementalMerkle> {
        let mut client = QueryClient::connect(self.grpc_url.clone()).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryCurrentTreeRequest {});
        let response = client.current_tree(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
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
        Ok(IncrementalMerkle::new(
            branches,
            response.count.try_into().unwrap(),
        ))
    }

    // Val requirement
    #[instrument(level = "debug", err, ret, skip(self))]
    async fn count(&self, lag: Option<NonZeroU64>) -> ChainResult<u32> {
        let mut client = QueryClient::connect(self.grpc_url.clone()).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryCurrentTreeMetadataRequest {});
        let response = client.current_tree_metadata(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(response.into_inner().count)
    }

    // Relayer only
    #[instrument(level = "debug", err, ret, skip(self))]
    async fn delivered(&self, id: H256) -> ChainResult<bool> {
        todo!()
    }

    // Val requirement
    #[instrument(level = "debug", err, ret, skip(self))]
    async fn latest_checkpoint(&self, lag: Option<NonZeroU64>) -> ChainResult<Checkpoint> {
        let mut client = QueryClient::connect(self.grpc_url.clone()).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryCurrentTreeMetadataRequest {});
        let response = client.current_tree_metadata(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?.into_inner();
        let root: [u8; 32] = response.root.try_into().unwrap();
        Ok(Checkpoint { 
            mailbox_address: self.mailbox_address,
            mailbox_domain: self.domain.id(),
            root: H256::from(root),
            index: response.count
        })
    }

    // not required
    #[instrument(err, ret, skip(self))]
    async fn default_ism(&self) -> ChainResult<H256> {
        todo!()
    }

    // relayer only
    #[instrument(err, ret, skip(self))]
    async fn recipient_ism(&self, recipient: H256) -> ChainResult<H256> {
        todo!()
    }

    // relayer only
    #[instrument(err, ret, skip(self))]
    async fn process(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
        tx_gas_limit: Option<U256>,
    ) -> ChainResult<TxOutcome> {
        todo!()
    }

    //relayer only
    #[instrument(err, ret, skip(self), fields(msg=%message, metadata=%fmt_bytes(metadata)))]
    async fn process_estimate_costs(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
    ) -> ChainResult<TxCostEstimate> {
        todo!()
    }

    // not required
    fn process_calldata(&self, message: &HyperlaneMessage, metadata: &[u8]) -> Vec<u8> {
        todo!()
    }
}

/// Retrieves event data for a Cosmos chain that uses the hyperlane modules.
#[derive(Debug)]
pub struct CosmosMailboxIndexer {
    pub grpc_url: String,
    pub rpc_url: HttpClientUrl,
}

impl CosmosMailboxIndexer {
    pub fn new(conf: &ConnectionConf) -> Self {
        Self {
            grpc_url: conf.get_grpc_url(),
            rpc_url: conf.get_rpc_url().parse().unwrap(),
        }
    }

    fn get_client(&self) -> ChainResult<HttpClient> {
        let client = HttpClient::builder(self.rpc_url.clone())
            .compat_mode(CompatMode::V0_37)
            .build()
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(client)
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
        let client = self.get_client()?;

        let block = client.block(block_num).await.map_err(|e| ChainCommunicationError::from_other(e))?;
        let block_result = client.block_results(block_num).await.map_err(|e| ChainCommunicationError::from_other(e))?;
        let tx_results = block_result.txs_results;
        
        let mut result: Vec<(HyperlaneMessage, LogMeta)> = vec![];
        if let Some(tx_results) = tx_results {
            for (tx_idx, tx) in tx_results.iter().enumerate() {
                for (event_idx, event) in tx.events.clone().iter().enumerate() {
                    if event.kind.as_str() != "dispatch" {
                        continue;
                    }
                    let msg = self.parse_event(event.attributes.clone())?;
                    let meta = LogMeta {
                        address: H256::default(),
                        block_number: block_num as u64,
                        block_hash: H256::from_slice(block.block_id.hash.as_bytes()),
                        transaction_id: H512::from_slice(tx.data.as_ref()),
                        transaction_index: tx_idx as u64,
                        log_index: U256::from(event_idx),
                    };
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
        let client = self.get_client()?;
        let result = client
            .latest_block()
            .await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(result.block.header.height.value() as u32)
    }
}

#[async_trait]
impl SequenceIndexer<HyperlaneMessage> for CosmosMailboxIndexer {
    async fn sequence_and_tip(&self) -> ChainResult<(Option<u32>, u32)> {
        let tip = self.get_finalized_block_number().await?;
        let mut client = QueryClient::connect(self.grpc_url.clone()).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let request = tonic::Request::new(QueryCurrentTreeMetadataRequest {});
        let response = client.current_tree_metadata(request).await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        let resp_count = response.into_inner().count;
        let count = match resp_count {
            0 => None,
            _ => Some(resp_count)
        };
        Ok((count, tip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperlane_core::{HyperlaneDomainType, HyperlaneDomainProtocol};

    const BLOCK_RESPONSE: &str = r#"{
  "jsonrpc": "2.0",
  "id": -1,
  "result": {
    "block_id": {
      "hash": "C6067781514B5307E7E70C28B9B049E202F93346921A4B746C1181BFCE1D97D6",
      "parts": {
        "total": 1,
        "hash": "1D3CA467096FF5FEC8C39DF44208E49E4AA79D911306ABF8FA24B840FC55625F"
      }
    },
    "block": {
      "header": {
        "version": {
          "block": "11"
        },
        "chain_id": "cosmoshub-4",
        "height": "16808683",
        "time": "2023-08-31T22:26:06.95121174Z",
        "last_block_id": {
          "hash": "111A94AB0F78C2AAE900A8D911F5CEC0C850D822E55BDDA3B29A24D385DF53D3",
          "parts": {
            "total": 1,
            "hash": "BA1B4CD143DCAB5B3DB5C573B7064B19303715818E19BAA7A8721F5861599056"
          }
        },
        "last_commit_hash": "806299D91A7DD69981ADCC7F5C8A840F41C8485C8A9B5460FBDF6F38B1828DA2",
        "data_hash": "ADB2F266E3794DF129B1BA6E5810C016D9C099661AF02DF614999CC70FAAC2F5",
        "validators_hash": "780CB40142BF151AE506A8556DC4CB17B544EA4EF3A77B36B0587252879BD1E0",
        "next_validators_hash": "E429260F924033AD0CD8221CF38644EDFBB85432C806B1D4C1060732B1397B68",
        "consensus_hash": "80364965B7C2CC9DE961C0998B47A7F93F1970077EB882E0ED1C3822408888C7",
        "app_hash": "71900A059F90A85056F533DEADDD4102953BA236F8E71EC7AFA6C22717368516",
        "last_results_hash": "84E04CD2AFE089E09CB6D1B71DE70BFEBC52FD581157727E55608C53D3E281DD",
        "evidence_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "proposer_address": "CC05882978FC5FDD6A7721687E14C0299AE004B8"
      },
      "data": {
        "txs": []
      },
      "evidence": {
        "evidence": []
      },
      "last_commit": {
        "height": "16808682",
        "round": 0,
        "block_id": {
          "hash": "111A94AB0F78C2AAE900A8D911F5CEC0C850D822E55BDDA3B29A24D385DF53D3",
          "parts": {
            "total": 1,
            "hash": "BA1B4CD143DCAB5B3DB5C573B7064B19303715818E19BAA7A8721F5861599056"
          }
        },
        "signatures": []
      }
    }
  }
}
"#;

    /*#[tokio::test]
    async fn test_get_finalized_block_number() {
        let matcher =
            MockRequestMethodMatcher::default().map(Method::Block, Ok(BLOCK_RESPONSE.to_string()));
        let (client, driver) = MockClient::new(matcher);
        let driver_hdl = tokio::spawn(async move { driver.run().await });
        let client = Arc::new(client);
        let indexer = CosmosMailboxIndexer { client };

        let block_number = indexer.get_finalized_block_number().await.unwrap();
        assert_eq!(block_number, 16808683);

        Arc::try_unwrap(indexer.client).unwrap().close();
        driver_hdl.await.unwrap();
    }*/

    #[tokio::test]
    async fn test_mailbox_count() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "127.0.0.1:1234".to_string(),
                rpc_url: "".to_string(),
            },
            HyperlaneDomain::Unknown {
                domain_id: 0,
                domain_name: "CosmosTest".to_string(),
                domain_type: HyperlaneDomainType::LocalTestChain,
                domain_protocol: HyperlaneDomainProtocol::Ethereum,
            },
        ).unwrap();

        let count = mailbox.count(None).await.unwrap();
        println!("Count: {:?}", count);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_mailbox_tree() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "127.0.0.1:1234".to_string(),
                rpc_url: "".to_string(),
            },
            HyperlaneDomain::Unknown {
                domain_id: 0,
                domain_name: "CosmosTest".to_string(),
                domain_type: HyperlaneDomainType::LocalTestChain,
                domain_protocol: HyperlaneDomainProtocol::Ethereum,
            },
        ).unwrap();

        let im = mailbox.tree(None).await.unwrap();
        assert_eq!(im.count(), 1);
    }

    #[tokio::test]
    async fn test_mailbox_latest_checkpoint() {
        let mailbox = CosmosMailbox::new(
            &ConnectionConf{
                grpc_url: "127.0.0.1:1234".to_string(),
                rpc_url: "".to_string(),
            },
            HyperlaneDomain::Unknown {
                domain_id: 0,
                domain_name: "CosmosTest".to_string(),
                domain_type: HyperlaneDomainType::LocalTestChain,
                domain_protocol: HyperlaneDomainProtocol::Ethereum,
            },
        ).unwrap();

        let cp = mailbox.latest_checkpoint(None).await.unwrap();
        assert_eq!(cp.index, 1);
    }

    #[tokio::test]
    async fn test_mailbox_indexer_fetch_logs() {
        let indexer = CosmosMailboxIndexer::new(
            &ConnectionConf{
                grpc_url: "".to_string(),
                rpc_url: "127.0.0.1:1234".to_string(),
            },);
        let logs = indexer.fetch_logs(RangeInclusive::new(45, 48)).await.unwrap();
        assert_eq!(logs[0].0.origin, 12345);
    }

    #[tokio::test]
    async fn test_mailbox_indexer_get_finalized_block_number() {
        let indexer = CosmosMailboxIndexer::new(
            &ConnectionConf{
                grpc_url: "".to_string(),
                rpc_url: "127.0.0.1:1234".to_string(),
            },
        );
        let block_num = indexer.get_finalized_block_number().await.unwrap();
        assert_eq!(block_num, 10);
    }

}
