//! Core library for `pvault`, an offline encrypted file vault.
//!
//! The format and behavior are defined in `PVAULT_BUILD_SPEC.md`.

pub mod crypto;
pub mod errors;
pub mod platform;
pub mod secrets;

#[cfg(test)]
mod testvec;

pub use errors::Error;
