use codec::{Decode, Encode};
use sp_core::H256;

use crate::{error::DefinitionResult, helpers::unhex};

/// Encryption algorithm
/// Lists all encryption algorithms supported by Substrate
#[derive(Copy, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub enum Encryption {
    Ed25519,
    Sr25519,
    Ecdsa,
    Ethereum,
}

/// These network parameters are sufficient to add network into Vault database.
#[derive(Decode, Encode, PartialEq, Eq, Debug, Clone)]
pub struct NetworkSpecs {
    /// Network-specific prefix for address representation in
    /// [base58 format](https://docs.rs/sp-core/6.0.0/sp_core/crypto/trait.Ss58Codec.html#method.to_ss58check_with_version)  
    pub base58prefix: u16,

    /// Order of magnitude, by which the token unit exceeds the balance integer unit.  
    /// Is used to display balance-related values properly.  
    pub decimals: u8,

    /// Encryption algorithm the network uses  
    pub encryption: Encryption,

    /// Network genesis hash  
    pub genesis_hash: H256,

    /// Network associated logo  
    pub logo: String,

    /// Network name, as it appears in network metadata  
    pub name: String,

    /// Default derivation path for addresses in this network  
    pub path_id: String,

    /// Network-associated secondary color.  
    /// Historically is there, not doing much at the moment.  
    pub secondary_color: String,

    /// Network title, as it appears in Vault menus.
    pub title: String,

    /// Token name, to display balance-related values properly.  
    pub unit: String,

    pub color: String,

    pub address: String,
}

/// Key in `SPECSTREE` tree (cold database) and in `SPECSPREPTREE` (hot database)  
///
/// [`NetworkSpecsKey`] is used to retrieve the
/// [`OrderedNetworkSpecs`](crate::network_specs::OrderedNetworkSpecs) in cold database and
/// [`NetworkSpecs`](crate::network_specs::NetworkSpecs) in hot
/// database.  
///
/// Key is derived from network genesis hash and encryption algorithm.  
///
/// Network could support more than one encryption algorithm. In this case
/// there would be more than one database entry with different
/// [`NetworkSpecsKey`] values. Such entries do not conflict.  
#[derive(Decode, Hash, Encode, PartialEq, Eq, Debug, Clone)]
pub struct NetworkSpecsKey(Vec<u8>);

/// Decoded `NetworkSpecsKey` content, encryption-based variants with vector
/// genesis hash inside
#[derive(Decode, Encode)]
enum NetworkSpecsKeyContent {
    Ed25519(H256),
    Sr25519(H256),
    Ecdsa(H256),
    Ethereum(H256),
}

impl NetworkSpecsKey {
    /// Generate [`NetworkSpecsKey`] from parts: network genesis hash and
    /// [`Encryption`]
    pub fn from_parts(genesis_hash: &H256, encryption: &Encryption) -> Self {
        let network_key_content = match encryption {
            Encryption::Ed25519 => NetworkSpecsKeyContent::Ed25519(*genesis_hash),
            Encryption::Sr25519 => NetworkSpecsKeyContent::Sr25519(*genesis_hash),
            Encryption::Ecdsa => NetworkSpecsKeyContent::Ecdsa(*genesis_hash),
            Encryption::Ethereum => NetworkSpecsKeyContent::Ethereum(*genesis_hash),
        };
        Self(network_key_content.encode())
    }

    /// Transform hexadecimal `String` into [`NetworkSpecsKey`]  
    ///
    /// Vault receives hexadecimal strings from user interface.
    ///
    /// This function checks only that hexadecimal format is valid, no check
    /// of encryption validity is done here.  
    pub fn from_hex(hex_line: &str) -> DefinitionResult<Self> {
        Ok(Self(unhex(hex_line)?))
    }

    /// Get genesis hash as `H256` and [`Encryption`] from [`NetworkSpecsKey`]
    pub fn genesis_hash_encryption(&self) -> DefinitionResult<(H256, Encryption)> {
        match <NetworkSpecsKeyContent>::decode(&mut &self.0[..])? {
            NetworkSpecsKeyContent::Ed25519(b) => Ok((b, Encryption::Ed25519)),
            NetworkSpecsKeyContent::Sr25519(b) => Ok((b, Encryption::Sr25519)),
            NetworkSpecsKeyContent::Ecdsa(b) => Ok((b, Encryption::Ecdsa)),
            NetworkSpecsKeyContent::Ethereum(b) => Ok((b, Encryption::Ethereum)),
        }
    }

    /// Transform [`NetworkSpecsKey`] into `Vec<u8>` database key  
    pub fn key(&self) -> Vec<u8> {
        self.0.to_vec()
    }
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
