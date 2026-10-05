//! `pvault` command-line interface.

use clap::Parser;
use pvault_core::secrets::disable_core_dumps;

/// Offline encrypted file vault.
#[derive(Debug, Parser)]
#[command(name = "pvault", version, arg_required_else_help = true)]
struct Cli {}

fn main() {
    // Before anything else, so no later crash can write secrets to disk
    // (spec Section 10.3).
    if let Err(err) = disable_core_dumps() {
        eprintln!("warning: {err}. A crash could write this process's memory to disk.");
    }

    let _cli = Cli::parse();
}
