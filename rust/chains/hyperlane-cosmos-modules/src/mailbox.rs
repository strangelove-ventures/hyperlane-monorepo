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
    accumulator::incremental::IncrementalMerkle, utils::fmt_bytes, ChainCommunicationError,
    ChainResult, Checkpoint, HyperlaneChain, HyperlaneContract, HyperlaneDomain, HyperlaneMessage,
    HyperlaneProvider, Indexer, LogMeta, Mailbox, TxCostEstimate, TxOutcome, H256, U256,
};
use tendermint_rpc::client::Client;

/// A reference to a Mailbox contract on some Cosmos chain
pub struct CosmosMailbox {
    domain: HyperlaneDomain,
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
    #[instrument(level = "debug", err, ret, skip(self))]
    async fn tree(&self, lag: Option<NonZeroU64>) -> ChainResult<IncrementalMerkle> {
        todo!()
    }

    #[instrument(level = "debug", err, ret, skip(self))]
    async fn count(&self, lag: Option<NonZeroU64>) -> ChainResult<u32> {
        todo!()
    }

    #[instrument(level = "debug", err, ret, skip(self))]
    async fn delivered(&self, id: H256) -> ChainResult<bool> {
        todo!()
    }

    #[instrument(level = "debug", err, ret, skip(self))]
    async fn latest_checkpoint(&self, lag: Option<NonZeroU64>) -> ChainResult<Checkpoint> {
        todo!()
    }

    #[instrument(err, ret, skip(self))]
    async fn default_ism(&self) -> ChainResult<H256> {
        todo!()
    }

    #[instrument(err, ret, skip(self))]
    async fn recipient_ism(&self, recipient: H256) -> ChainResult<H256> {
        todo!()
    }

    #[instrument(err, ret, skip(self))]
    async fn process(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
        tx_gas_limit: Option<U256>,
    ) -> ChainResult<TxOutcome> {
        todo!()
    }

    #[instrument(err, ret, skip(self), fields(msg=%message, metadata=%fmt_bytes(metadata)))]
    async fn process_estimate_costs(
        &self,
        message: &HyperlaneMessage,
        metadata: &[u8],
    ) -> ChainResult<TxCostEstimate> {
        todo!()
    }

    fn process_calldata(&self, message: &HyperlaneMessage, metadata: &[u8]) -> Vec<u8> {
        todo!()
    }
}

/// Retrieves event data for a Cosmos chain that uses the hyperlane modules.
#[derive(Debug)]
pub struct CosmosMailboxIndexer<T: Client + Send + Sync> {
    pub client: Arc<T>,
}

#[async_trait]
impl<T: Client + Send + Sync + Debug> Indexer<HyperlaneMessage> for CosmosMailboxIndexer<T> {
    async fn fetch_logs(
        &self,
        range: RangeInclusive<u32>,
    ) -> ChainResult<Vec<(HyperlaneMessage, LogMeta)>> {
        todo!()
    }

    /// Fetches the latest finalized block number from Cosmos API (aka LCD). Cosmos chains have fast finality.
    async fn get_finalized_block_number(&self) -> ChainResult<u32> {
        let resp = self
            .client
            .latest_block()
            .await
            .map_err(|e| ChainCommunicationError::from_other(e))?;
        Ok(resp.block.header.height.value() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint_rpc::{Method, MockClient, MockRequestMethodMatcher};

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

    #[tokio::test]
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
    }
}
