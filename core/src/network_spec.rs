use std::str::FromStr;

use codec::{Decode, Encode};
use sp_core::H256;

use crate::{definitions::Encryption, error::DefinitionResult, helpers::unhex};

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

pub fn default_network_specs() -> [NetworkSpecs; 3] {
    [
        NetworkSpecs {
            address: String::from("wss://kusama-rpc.polkadot.io"),
            base58prefix: 2,
            color: String::from("#000"),
            decimals: 12,
            encryption: Encryption::Sr25519,
            genesis_hash: H256::from_str(
                "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
            )
            .expect("known value"),
            logo: String::from("kusama"),
            name: String::from("kusama"),
            path_id: String::from("//kusama"),
            secondary_color: String::from("#262626"),
            title: String::from("Kusama"),
            unit: String::from("KSM"),
        },
        NetworkSpecs {
            address: String::from("wss://rpc.polkadot.io"),
            base58prefix: 0,
            color: String::from("#E6027A"),
            decimals: 10,
            encryption: Encryption::Sr25519,
            genesis_hash: H256::from_str(
                "91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
            )
            .expect("known value"),
            logo: String::from("polkadot"),
            name: String::from("polkadot"),
            path_id: String::from("//polkadot"),
            secondary_color: String::from("#262626"),
            title: String::from("Polkadot"),
            unit: String::from("DOT"),
        },
        NetworkSpecs {
            address: String::from("wss://westend-rpc.polkadot.io"),
            base58prefix: 42,
            color: String::from("#660D35"),
            decimals: 12,
            encryption: Encryption::Sr25519,
            genesis_hash: H256::from_str(
                "e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e",
            )
            .expect("known value"),
            logo: String::from("westend"),
            name: String::from("westend"),
            path_id: String::from("//westend"),
            secondary_color: String::from("#262626"),
            title: String::from("Westend"),
            unit: String::from("WND"),
        },
    ]
}
