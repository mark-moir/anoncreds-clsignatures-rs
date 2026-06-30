#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]
#![deny(unsafe_code)]

#[macro_use]
extern crate log;

#[macro_use]
mod error;
#[macro_use]
mod macros;
#[macro_use]
mod helpers;
#[cfg(feature = "serde")]
#[macro_use]
mod serialization;

mod amcl;
mod constants;
mod hash;
mod issuer;
mod prover;
mod verifier;

pub mod bn;
mod types;

pub use {
    self::error::{Error, ErrorKind, Result as ClResult},
    self::helpers::{hash_credential_attribute, new_nonce},
    self::issuer::Issuer,
    self::verifier::{ProofVerifier, Verifier},
    self::types::*
};

pub use version_specific_imports::*;
#[cfg(not(feature = "vca"))]
mod version_specific_imports {
    use super::*;
    pub use self::prover::{ProofBuilder, Prover};
}

#[cfg(feature = "vca")]
mod version_specific_imports {
    use super::*;
    pub use helpers::vca_schema_from_attr_names;
    pub use self::prover::blind_credential_secrets;
}

#[cfg(feature = "vca")]
pub use credx::vca::{
    api::VcaApi,
    api::Accumulator as CryptoAccumulator,
    zkp_backends::{dnc::crypto_interface::CRYPTO_INTERFACE_DNC,
                   ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_BBS,
                   ac2c::crypto_interface::CRYPTO_INTERFACE_AC2C_PS},
};

#[cfg(feature = "vca")]
use once_cell::sync::Lazy;

#[cfg(feature = "vca")]
static DEFAULT_BACKEND_ARG: &str = "ac2c-bbs";

/// Build a VCA API for a specific backend label (`dnc` | `ac2c-bbs` | `ac2c-ps`).
#[cfg(feature = "vca")]
pub fn vca_api_for_backend() -> VcaApi {
    let backend = std::env::var("VCA_BACKEND")
        .unwrap_or_else(|_| DEFAULT_BACKEND_ARG.to_string());
    println!("VCA_BACKEND={backend}");
    match backend.as_str() {
        "dnc" => credx::vca::api_utils::implement_vca_api_using(&CRYPTO_INTERFACE_DNC),
        "ac2c-bbs" => credx::vca::api_utils::implement_vca_api_using(&CRYPTO_INTERFACE_AC2C_BBS),
        "ac2c-ps" => credx::vca::api_utils::implement_vca_api_using(&CRYPTO_INTERFACE_AC2C_PS),
        x => {
            println!("VCA_BACKEND={x} not supported, defaulting to {DEFAULT_BACKEND_ARG}");
            credx::vca::api_utils::implement_vca_api_using(&CRYPTO_INTERFACE_DNC)
        }
    }
}

/// Select VCA backend at runtime via `VCA_BACKEND` env var (`dnc` | `ac2c-bbs` | `ac2c-ps`).
#[cfg(feature = "vca")]
pub static VCA_API: Lazy<VcaApi> = Lazy::new(vca_api_for_backend);

pub fn validate_issuance_by_default(issuance_by_default: bool) -> ClResult<()> {
    let _ = issuance_by_default;
    #[cfg(feature="vca")]
    if !issuance_by_default {
        return Err(err_msg!("VCA does not support issuance_by_default=false"))
    };
    Ok(())
}

#[cfg(feature="vca")]
pub fn vca_nonce_from_cl_nonce(nonce: &Nonce) -> String {
    format!("nonce-from-big-number-{nonce:?}")
}
