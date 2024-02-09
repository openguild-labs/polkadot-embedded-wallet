use codec::{Decode, Encode};
use sp_core::H256;
use sp_runtime::MultiSigner;

use crate::{
    crypto::Encryption,
    error::IdentityResult,
    helpers::{get_multisigner, unhex},
};

#[derive(Decode, Encode, Debug, PartialEq, Eq, Clone)]
pub struct AddressKey {
    multisigner: MultiSigner,
    /// the root address is not used on any network and hence has no genesis hash.
    genesis_hash: Option<H256>,
}

impl AddressKey {
    /// Generate [`AddressKey`] from corresponding
    /// [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html) value  
    /// and a network prefix.
    pub fn new(multisigner: MultiSigner, genesis_hash: Option<H256>) -> Self {
        Self {
            multisigner,
            genesis_hash,
        }
    }

    /// Generate [`AddressKey`] from parts: raw public key and [`Encryption`]  
    ///
    /// Could result in error if public key length does not match the
    /// expected length for chosen encryption algorithm.  
    pub fn from_parts(
        public: &[u8],
        encryption: &Encryption,
        genesis_hash: Option<H256>,
    ) -> IdentityResult<Self> {
        let multisigner = get_multisigner(public, encryption)?;
        Ok(Self::new(multisigner, genesis_hash))
    }

    /// Transform hexadecimal `String` into [`AddressKey`]  
    ///
    /// Vault receives hexadecimal strings from user interface.
    ///
    /// This function checks only that hexadecimal format is valid, no length
    /// check happens here.  
    pub fn from_hex(hex_address_key: &str) -> IdentityResult<Self> {
        Ok(Self::decode(&mut &unhex(hex_address_key)?[..])?)
    }

    /// Get public key and [`Encryption`] from the [`AddressKey`]  
    pub fn public_key_encryption(&self) -> IdentityResult<(Vec<u8>, Encryption)> {
        match &self.multisigner {
            MultiSigner::Ed25519(b) => Ok((b.to_vec(), Encryption::Ed25519)),
            MultiSigner::Sr25519(b) => Ok((b.to_vec(), Encryption::Sr25519)),
            MultiSigner::Ecdsa(b) => Ok((b.0.to_vec(), Encryption::Ecdsa)),
        }
    }

    /// Get [`MultiSigner`](https://docs.rs/sp-runtime/6.0.0/sp_runtime/enum.MultiSigner.html)
    /// from the [`AddressKey`]  
    pub fn multi_signer(&self) -> &MultiSigner {
        &self.multisigner
    }

    /// Transform [`AddressKey`] into `Vec<u8>` database key  
    pub fn key(&self) -> Vec<u8> {
        self.encode()
    }
}
