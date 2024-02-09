//! Common helper functions

use hex;
use sp_core::{
    crypto::{Ss58AddressFormat, Ss58Codec},
    hexdisplay::HexDisplay,
    Hasher, KeccakHasher, H160, H256,
};
use sp_core::{ecdsa, ed25519, sr25519};
use sp_runtime::MultiSigner;
use std::convert::TryInto;

use crate::error::DefinitionError;
use crate::{crypto::Encryption, error::DefinitionResult};

/// Decode hexadecimal `&str` into `Vec<u8>`, with descriptive error  
///
/// Function could be used both on hot and cold side.  
///
/// In addition to encoded `&str` required is input of `T::NotHex`, to produce
/// error with details on what exactly turned out to be invalid hexadecimal
/// string.  
pub fn unhex(hex_entry: &str) -> DefinitionResult<Vec<u8>> {
    let hex_entry = {
        if let Some(a) = hex_entry.strip_prefix("0x") {
            a
        } else {
            hex_entry
        }
    };
    Ok(hex::decode(hex_entry)?)
}

/// Get `Vec<u8>` public key from
/// [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html)  
pub fn multisigner_to_public(m: &MultiSigner) -> Vec<u8> {
    match m {
        MultiSigner::Ed25519(a) => a.to_vec(),
        MultiSigner::Sr25519(a) => a.to_vec(),
        MultiSigner::Ecdsa(a) => a.0.to_vec(),
    }
}

/// Get [`Encryption`](crate::crypto::Encryption) from
/// [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html)  
pub fn multisigner_to_encryption(m: &MultiSigner) -> Encryption {
    match m {
        MultiSigner::Ed25519(_) => Encryption::Ed25519,
        MultiSigner::Sr25519(_) => Encryption::Sr25519,
        MultiSigner::Ecdsa(_) => Encryption::Ecdsa,
    }
}

/// Get [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html)
/// from public key and [`Encryption`](crate::crypto::Encryption)
pub fn get_multisigner(public: &[u8], encryption: &Encryption) -> DefinitionResult<MultiSigner> {
    match encryption {
        Encryption::Ed25519 => {
            let into_pubkey: [u8; 32] = public
                .to_vec()
                .try_into()
                .map_err(|_| DefinitionError::WrongPublicKeyLength)?;
            Ok(MultiSigner::Ed25519(ed25519::Public::from_raw(into_pubkey)))
        }
        Encryption::Sr25519 => {
            let into_pubkey: [u8; 32] = public
                .to_vec()
                .try_into()
                .map_err(|_| DefinitionError::WrongPublicKeyLength)?;
            Ok(MultiSigner::Sr25519(sr25519::Public::from_raw(into_pubkey)))
        }
        Encryption::Ecdsa | Encryption::Ethereum => {
            let into_pubkey: [u8; 33] = public
                .to_vec()
                .try_into()
                .map_err(|_| DefinitionError::WrongPublicKeyLength)?;
            Ok(MultiSigner::Ecdsa(ecdsa::Public::from_raw(into_pubkey)))
        }
    }
}

/// Print [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html)
/// in base58 format
///
/// Could be done for both
/// [custom](https://docs.rs/sp-core/6.0.0/sp_core/crypto/trait.Ss58Codec.html#method.to_ss58check_with_version)
/// network-specific base58 prefix by providing `Some(value)` as `optional_prefix` or with
/// [default](https://docs.rs/sp-core/6.0.0/sp_core/crypto/trait.Ss58Codec.html#method.to_ss58check)
/// one by leaving it `None`.
pub fn print_multisigner_as_base58_or_eth(
    multi_signer: &MultiSigner,
    optional_prefix: Option<u16>,
    encryption: Encryption,
) -> String {
    match optional_prefix {
        Some(base58prefix) => {
            let version_for_base58 = Ss58AddressFormat::custom(base58prefix);
            match multi_signer {
                MultiSigner::Ed25519(pubkey) => {
                    pubkey.to_ss58check_with_version(version_for_base58)
                }
                MultiSigner::Sr25519(pubkey) => {
                    pubkey.to_ss58check_with_version(version_for_base58)
                }
                MultiSigner::Ecdsa(pubkey) => {
                    if encryption == Encryption::Ethereum {
                        print_ethereum_address(pubkey)
                    } else {
                        pubkey.to_ss58check_with_version(version_for_base58)
                    }
                }
            }
        }
        None => match multi_signer {
            MultiSigner::Ed25519(pubkey) => {
                let version = Ss58AddressFormat::try_from("BareEd25519")
                    .expect("unable to make Ss58AddressFormat from `BareEd25519`");
                pubkey.to_ss58check_with_version(version)
            }
            MultiSigner::Sr25519(pubkey) => {
                let version = Ss58AddressFormat::try_from("BareSr25519")
                    .expect("unable to make Ss58AddressFormat from `BareSr25519`");
                pubkey.to_ss58check_with_version(version)
            }
            MultiSigner::Ecdsa(pubkey) => {
                if encryption == Encryption::Ethereum {
                    print_ethereum_address(pubkey)
                } else {
                    pubkey.to_ss58check()
                }
            }
        },
    }
}

/// Turn a `ecdsa::Public` addr into an Ethereum address.
pub fn ecdsa_public_to_eth_address(public: &ecdsa::Public) -> DefinitionResult<H160> {
    let decompressed = libsecp256k1::PublicKey::parse_compressed(&public.0)?.serialize();
    let mut m = [0u8; 64];
    m.copy_from_slice(&decompressed[1..65]);
    Ok(H160::from(H256::from_slice(
        KeccakHasher::hash(&m).as_bytes(),
    )))
}

/// Print a `ecdsa::Public` into `String`.
///
/// Panics if provided ecdsa public key is in wrong format.
fn print_ethereum_address(public: &ecdsa::Public) -> String {
    let account = ecdsa_public_to_eth_address(public).expect("Wrong ecdsa public key provided");

    format!("0x{:?}", HexDisplay::from(&account.as_bytes()))
}

pub fn base58_or_eth_to_multisigner(
    base58_or_eth: &str,
    encryption: &Encryption,
) -> DefinitionResult<MultiSigner> {
    match encryption {
        Encryption::Ed25519 => {
            let pubkey = ed25519::Public::from_ss58check(base58_or_eth)?;
            Ok(MultiSigner::Ed25519(pubkey))
        }
        Encryption::Sr25519 => {
            let pubkey = sr25519::Public::from_ss58check(base58_or_eth)?;
            Ok(MultiSigner::Sr25519(pubkey))
        }
        Encryption::Ethereum | Encryption::Ecdsa => {
            let pubkey = ecdsa::Public::from_ss58check(base58_or_eth)?;
            Ok(MultiSigner::Ecdsa(pubkey))
        }
    }
}
