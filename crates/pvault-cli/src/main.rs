//! `pvault` command-line interface.

use clap::Parser;
use pvault_core::estimator;
use pvault_core::platform::disable_core_dumps;

/// Offline encrypted file vault.
#[derive(Debug, Parser)]
#[command(name = "pvault", version, arg_required_else_help = true)]
struct Cli {}

fn main() {
    // The custom-passphrase estimator child (SI-51). It hardens itself and
    // never reaches the argument parser.
    let mut args = std::env::args_os().skip(1);
    if let (Some(first), None) = (args.next(), args.next())
        && first == estimator::CHILD_ARG
    {
        std::process::exit(estimator::run_child());
    }

    // Before anything else, so no later crash can write secrets to disk
    // (spec Section 10.3).
    if let Err(err) = disable_core_dumps() {
        eprintln!("warning: {err}. A crash could write this process's memory to disk.");
    }

    let _cli = Cli::parse();
}
