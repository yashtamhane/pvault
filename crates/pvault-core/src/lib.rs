//! Core library for `pvault`, an offline encrypted file vault.
//!
//! The format and behavior are defined in `PVAULT_BUILD_SPEC.md`.

pub mod errors;
pub mod secrets;

pub use errors::Error;
