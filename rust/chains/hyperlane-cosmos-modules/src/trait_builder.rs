use hyperlane_core::config::{ConfigErrResultExt, ConfigPath, ConfigResult, FromRawConf};
use url::Url;

/// Cosmos connection configuration
#[derive(Debug, Clone)]
pub struct ConnectionConf {
    // TODO: remove pub after unit testing complete
    pub grpc_url: String,
    pub rpc_url: String,
}

/// Raw Cosmos connection configuration used for better deserialization errors.
#[derive(Debug, serde::Deserialize)]
pub struct DeprecatedRawConnectionConf {
    pub grpc_url: Option<String>,
    pub rpc_url: Option<String>,
}

/// An error type when parsing a connection configuration.
#[derive(thiserror::Error, Debug)]
pub enum ConnectionConfError {
    /// Missing `url` for connection configuration
    #[error("Missing `url` for connection configuration")]
    MissingConnectionUrl,
    /// Invalid `url` for connection configuration
    #[error("Invalid `url` for connection configuration: `{0}` ({1})")]
    InvalidConnectionUrl(String, url::ParseError),
}

impl FromRawConf<DeprecatedRawConnectionConf> for ConnectionConf {
    fn from_config_filtered(
        raw: DeprecatedRawConnectionConf,
        cwp: &ConfigPath,
        _filter: (),
    ) -> ConfigResult<Self> {
        use ConnectionConfError::*;

        let grpc_url = raw
            .grpc_url
            .ok_or(MissingConnectionUrl)
            .into_config_result(|| cwp.join("grpc_url"))?;
        let rpc_url = raw
            .rpc_url
            .ok_or(MissingConnectionUrl)
            .into_config_result(|| cwp.join("rpc_url"))?;
        println!("cosmos modules settings: from_config_filtered");
        println!("grpc_url: {grpc_url}, rpc_url: {rpc_url}");
        Ok(ConnectionConf { grpc_url, rpc_url })
    }
}

impl ConnectionConf {
    pub fn get_grpc_url(&self) -> String {
        self.grpc_url.clone()
    }
    pub fn get_rpc_url(&self) -> String {
        self.rpc_url.clone()
    }
}