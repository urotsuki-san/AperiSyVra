#![forbid(unsafe_code)]

//! AperiSyVra P1 public-key research core.

mod error;
#[cfg_attr(not(feature = "research-tools"), allow(dead_code))]
mod kem;
#[cfg_attr(not(any(test, feature = "research-tools")), allow(dead_code))]
mod matrix;
mod message;
pub mod parameters;
pub mod structure;
mod syndrome;
mod xof;

pub use error::{Error, Result};
pub use kem::{
    decapsulate, encapsulate, generate_keypair, keypair_from_seed, Ciphertext, PublicKey,
    SecretKey, SharedSecret,
};
pub use message::{open, seal, SealedMessage};
pub use syndrome::Syndrome;

#[cfg(feature = "research-tools")]
pub use kem::research;
