use cosmrs::crypto::secp256k1::SigningKey;
use hyperlane_core::{ChainCommunicationError, ChainResult};
use digest::Digest;
use ripemd::Ripemd160;
use bech32::ToBase32;

#[derive(Clone, Debug)]
/// Signer for cosmos chain
pub struct Signer {
    /// prefix for signer address
    prefix: String,
    private_key: Vec<u8>,
    bech32_address: String,
}

impl Signer {
    /// create new signer
    pub fn new(private_key: Vec<u8>, prefix: String) -> Self {
        let bech32_address = derive_bech32_address(private_key.clone(), prefix.clone());

        Self {
            prefix,
            private_key,
            bech32_address,
        }
    }

    pub fn bech32_address(&self) -> String {
        self.bech32_address.clone()
    }
}

fn derive_bech32_address(private_key: Vec<u8>, prefix: String) -> String {
    let pub_key = SigningKey::from_slice(private_key.as_slice())
        .unwrap()
        .public_key()
        .to_bytes();

    let pub_key_sha256 = sha2::Sha256::digest(pub_key);
    let pub_key_hash: [u8; 20] = Ripemd160::digest(pub_key_sha256).into();
    bech32::encode(
        &prefix,
        pub_key_hash.to_base32(),
        bech32::Variant::Bech32,
    ).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer() {
        let private_key = hex::decode("984e39bb0d8974432114adcfcbe99d5984e8ac052fa3bb6059f5a77a88ef9912").unwrap();
        let prefix = "osmo".to_string();
        let signer = Signer::new(private_key, prefix);
        assert_eq!(signer.bech32_address(), "osmo109ns4u04l44kqdkvp876hukd3hxz8zzm7809el".to_string());
    }
}