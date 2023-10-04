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
    base_denom: String,
}

impl Signer {
    /// create new signer
    pub fn new(private_key: Vec<u8>, prefix: String, base_denom: String) -> Self {
        let bech32_address = derive_bech32_address(private_key.clone(), prefix.clone());

        Self {
            prefix,
            private_key,
            bech32_address,
            base_denom,
        }
    }

    pub fn bech32_address(&self) -> String {
        self.bech32_address.clone()
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }

    pub fn prefix(&self) -> String {
        self.prefix.clone()
    }

    pub fn base_denom(&self) -> String {
        self.base_denom.clone()
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
        let private_key = hex::decode("a011942e70462913d8e2f26a36d487c221dc0b4ca7fc502bd3490c84f98aa0cd").unwrap();
        let prefix = "cosmos".to_string();
        let signer = Signer::new(private_key, prefix, "stake".to_string());
        assert_eq!(signer.bech32_address(), "cosmos1h2r25vnegrp3j6qpqglrcuw54flcuwxlry8tnj".to_string());
    }
}