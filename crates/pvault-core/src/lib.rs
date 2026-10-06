//! Core library for `pvault`, an offline encrypted file vault.
//!
//! The format and behavior are defined in `PVAULT_BUILD_SPEC.md`.

pub mod card;
pub mod cbor;
pub mod crypto;
pub mod errors;
pub mod estimator;
pub mod header;
#[macro_use]
mod failpoints;
pub mod input;
pub mod journal;
pub mod keytable;
pub mod lock;
mod normalize;
pub mod passphrase;
pub mod paths;
pub mod platform;
pub mod records;
pub mod render;
pub mod resources;
pub mod secrets;
pub mod shamir;
pub mod store;
pub mod tpmid;
mod ucd17;
pub mod vault;

#[cfg(test)]
mod format_vectors;
#[cfg(test)]
mod fuzz_seeds;
#[cfg(test)]
mod testvec;

pub use errors::Error;
