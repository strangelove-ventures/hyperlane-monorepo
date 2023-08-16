use serde::Deserialize;
use std::fmt::Debug;
use std::num::ParseIntError;
use std::ops::RangeInclusive;
use std::time::Duration;
use url::Url;

use async_trait::async_trait;
use eyre::eyre;
use futures_util::TryStreamExt;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error(transparent)]
    Other(#[from] eyre::ErrReport),
}

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug)]
pub struct CosmosClient {
    base_url: Url,
    client: reqwest::Client,
}

impl CosmosClient {
    pub fn new(api_base_url: String, timeout: Duration) -> Result<Self> {
        let base_url = Url::parse(&api_base_url)?;
        let client = reqwest::Client::builder()
            .connect_timeout(timeout)
            .user_agent("hyperlane-cosmos-client")
            .build()?;
        Ok(Self { base_url, client })
    }

    pub async fn finalized_block_height(&self) -> Result<u32> {
        let url = self
            .base_url
            .clone()
            .join("cosmos/base/tendermint/v1beta1/blocks/latest")?;

        let latest = self
            .client
            .get(url)
            .send()
            .await?
            .json::<LatestBlock>()
            .await?;

        latest
            .block
            .header
            .height
            .parse()
            .map_err(|e: ParseIntError| {
                ClientError::Other(eyre!("Failed to parse block height: {}", e))
            })
    }
}

#[derive(Deserialize)]
struct LatestBlock {
    block: Block,
}

#[derive(Deserialize)]
struct Block {
    header: BlockHeader,
}

#[derive(Deserialize)]
struct BlockHeader {
    height: String,
}
