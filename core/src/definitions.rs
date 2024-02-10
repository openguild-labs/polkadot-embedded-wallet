use codec::{Decode, Encode};
use sp_core::H256;

/// Encryption algorithm
/// Lists all encryption algorithms supported by Substrate
#[derive(Copy, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub enum Encryption {
    Ed25519,
    Sr25519,
    Ecdsa,
    Ethereum,
}

/// Event content for address generation or removal.
#[derive(Debug, Decode, Encode, PartialEq, Eq, Clone)]
pub struct IdentityRecord {
    /// The name of the seed.
    pub seed_name: String,
    /// [`Encryption`] scheme of the seed.
    pub encryption: Encryption,
    /// Public key.
    pub public_key: Vec<u8>,
    /// - path with soft (`/`) and hard (`//`) derivations only, **without** password  
    pub path: String,
    /// - genesis hash of the network within which the address is  
    pub network_genesis_hash: H256,
}

impl IdentityRecord {
    pub fn new(
        seed_name: String,
        encryption: Encryption,
        public_key: Vec<u8>,
        path: String,
        network_genesis_hash: H256,
    ) -> Self {
        Self {
            seed_name,
            encryption,
            public_key,
            path,
            network_genesis_hash,
        }
    }

    /// Generate [`IdentityHistory`] from parts  
    pub fn get(
        seed_name: &str,
        encryption: &Encryption,
        public_key: &[u8],
        path: &str,
        network_genesis_hash: H256,
    ) -> Self {
        Self {
            seed_name: seed_name.to_string(),
            encryption: encryption.to_owned(),
            public_key: public_key.to_vec(),
            path: path.to_string(),
            network_genesis_hash,
        }
    }
}
