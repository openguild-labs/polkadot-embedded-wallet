mod crypto;
mod definitions;
mod error;
mod helpers;
mod keyring;
mod network_spec;
mod users;

use bip39::{Language, Mnemonic, MnemonicType};
use definitions::{Encryption, IdentityRecord, NetworkSpecs, NetworkSpecsKey};
use error::{IdentityError, IdentityResult};
use helpers::multisigner_to_public;
use keyring::AddressKey;
use lazy_static::lazy_static;
use regex::Regex;
use sp_core::{crypto::Zeroize, ecdsa, ed25519, sr25519, Pair};
use sp_runtime::MultiSigner;
use users::AddressDetails;

use crate::network_spec::default_network_specs;

lazy_static! {
    static ref REG_PATH: Regex =
        Regex::new(r"^(?P<path>(//?[^/]+)*)(///(?P<password>.+))?$").expect("known value");
}

enum CreateAddressPayload {
    SocialProvider,
    EmailAndPassword,
    SeedPhrase {
        derivation_path: &'static str,
        seed_phrase: String,
        seed_name: &'static str,
    },
}

/// Generate random phrase with given number of words.
///
/// The output is a **secret seed phrase**.
///
/// Its zeroization and safe handling are delegated to hardware.
pub fn generate_random_phrase(words_number: u32) -> IdentityResult<String> {
    let mnemonic_type = MnemonicType::for_word_count(words_number as usize).unwrap();
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
    Ok(mnemonic.into_phrase())
}

/// Get public key from seed phrase and derivation path
fn full_address_to_multisigner(
    mut full_address: String,
    encryption: Encryption,
) -> Result<MultiSigner, IdentityError> {
    let multisigner_result = match encryption {
        Encryption::Ed25519 => match ed25519::Pair::from_string(&full_address, None) {
            Ok(a) => Ok(MultiSigner::Ed25519(a.public())),
            Err(e) => Err(IdentityError::SecretStringError(e)),
        },
        Encryption::Sr25519 => match sr25519::Pair::from_string(&full_address, None) {
            Ok(a) => Ok(MultiSigner::Sr25519(a.public())),
            Err(e) => Err(IdentityError::SecretStringError(e)),
        },
        Encryption::Ecdsa | Encryption::Ethereum => {
            match ecdsa::Pair::from_string(&full_address, None) {
                Ok(a) => Ok(MultiSigner::Ecdsa(a.public())),
                Err(e) => Err(IdentityError::SecretStringError(e)),
            }
        }
    };
    full_address.zeroize();
    multisigner_result
}

fn do_create_address_with_seed_phrase(
    cropped_path: &str,
    network_specs: Option<&NetworkSpecs>,
    seed_name: &str,
    multisigner: MultiSigner,
    has_pwd: bool,
) -> IdentityResult<(Option<AddressDetails>, Option<IdentityRecord>)> {
    // Check that the seed name is not empty.
    if seed_name.is_empty() {
        return Err(IdentityError::EmptySeedName);
    }
    let mut identity_record: Option<IdentityRecord> = None;
    let mut address_details: Option<AddressDetails> = None;
    let mut address_key: Option<AddressKey> = None;
    let mut network_specs_key: Option<NetworkSpecsKey> = None;
    if let Some(network_specs) = network_specs {
        network_specs_key = Some(NetworkSpecsKey::from_parts(
            &network_specs.genesis_hash,
            &network_specs.encryption,
        ));

        let public_key = multisigner_to_public(&multisigner);
        address_key = Some(AddressKey::new(
            multisigner.clone(),
            Some(network_specs.genesis_hash),
        ));
        identity_record = Some(IdentityRecord::get(
            seed_name,
            &network_specs.encryption,
            &public_key,
            cropped_path,
            network_specs.genesis_hash,
        ));
    }
    if address_key.is_none() {
        address_key = Some(AddressKey::new(multisigner.clone(), None))
    }

    address_details = Some(AddressDetails {
        seed_name: seed_name.to_string(),
        path: cropped_path.to_string(),
        has_pwd,
        network_id: network_specs_key,
        encryption: network_specs
            .map(|ns| ns.encryption)
            .unwrap_or(Encryption::Sr25519),
        secret_exposed: false,
    });

    Ok((address_details, identity_record))
}

fn create_address_with_seed_phrase(
    network_specs: Option<&NetworkSpecs>,
    derivation_path: &'static str,
    seed_phrase: String,
    seed_name: &'static str,
) -> IdentityResult<(Option<AddressDetails>, Option<IdentityRecord>)> {
    // Check that the seed name is not empty.
    if seed_phrase.is_empty() {
        return Err(IdentityError::EmptySeed);
    }
    // create fixed-length string to avoid reallocations
    let full_address_size = seed_phrase.len() + derivation_path.len();
    let mut full_address = String::with_capacity(full_address_size);
    full_address.push_str(seed_phrase.as_str());
    full_address.push_str(derivation_path);

    let encryption = network_specs
        .map(|ns| ns.encryption)
        .unwrap_or(Encryption::Sr25519);

    let multisigner = full_address_to_multisigner(full_address, encryption)?;

    let (cropped_path, has_pwd) = match REG_PATH.captures(derivation_path) {
        Some(caps) => match caps.name("path") {
            Some(a) => (a.as_str(), caps.name("password").is_some()),
            None => ("", caps.name("password").is_some()),
        },
        None => ("", false),
    };

    let res = do_create_address_with_seed_phrase(
        cropped_path,
        network_specs,
        seed_name,
        multisigner,
        has_pwd,
    )?;
    Ok(res)
}

fn create_address(
    network_specs: Option<&NetworkSpecs>,
    payload: CreateAddressPayload,
) -> IdentityResult<(Option<AddressDetails>, Option<IdentityRecord>)> {
    match payload {
        CreateAddressPayload::SeedPhrase {
            seed_name,
            seed_phrase,
            derivation_path,
        } => {
            create_address_with_seed_phrase(network_specs, derivation_path, seed_phrase, seed_name)
        }
        _ => unimplemented!(),
    }
}

fn main() {
    let seed_phrase = generate_random_phrase(24).unwrap();
    println!("{:?}", seed_phrase.clone());

    let sr25519_pair = sr25519::Pair::from_string(&seed_phrase, None)
        .map_err(IdentityError::SecretStringError)
        .unwrap();
    println!("{:?}", sr25519_pair.public());
    for network_spec in default_network_specs().to_vec() {
        let (address_details, identity_record) = create_address(
            Some(&network_spec),
            CreateAddressPayload::SeedPhrase {
                derivation_path: "//Alice",
                seed_phrase: seed_phrase.clone(),
                seed_name: "Alice",
            },
        )
        .unwrap();

        println!("{:?}", address_details);
        println!("{:?}", identity_record);
    }
}
