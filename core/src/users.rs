//! Address key associated non-secret information stored in Vault database
//!
//! Vault database has a tree `ADDRTREE` with [`AddressKey`] in key form
//! as a key and encoded [`AddressDetails`] as a value.
//! [`AddressDetails`] contains non-secret information associated with address key.
//!
//! `ADDRTREE` is operated mainly from within the Vault.
//!
//! Release and test versions of the cold database are generated on the Active side.

use codec::{Decode, Encode};

use crate::{definitions::Encryption, network_spec::NetworkSpecsKey};

/// Address key associated non-secret information stored in Vault database
///
/// Info that should be available for any address key.
/// No secrets are stored there.
#[derive(Decode, PartialEq, Eq, Encode, Debug, Clone)]
pub struct AddressDetails {
    /// seed name (as it is known to the Vault device)
    pub seed_name: String,

    /// derivation path, only with soft (`/`) and hard (`//`) junctions (i.e. no password)
    pub path: String,

    /// whether the address key has an associated password
    pub has_pwd: bool,

    /// set of networks, identified through [`NetworkSpecsKey`], that are available
    /// to work with this address key
    pub network_id: Option<NetworkSpecsKey>,

    /// encryption algorithm associated with the address key and all its associated networks
    pub encryption: Encryption,

    /// address, or its parent address, had or could have secret exposed
    pub secret_exposed: bool,
}
