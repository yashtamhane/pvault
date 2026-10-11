//! `pvault` command-line interface (`docs/CLI.md`, approved for Milestone 4).
//!
//! The binary is a one-line wrapper around [`main`], so the crash tests in
//! `pvault-tests` can run the same CLI built with `fault-injection`.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use pvault_core::card::{CardTextProgress, CardTextReader, PAYLOAD_LEN};
use pvault_core::crypto::kdf::Argon2Params;
use pvault_core::errors::Error;
use pvault_core::estimator;
use pvault_core::header::Mode;
use pvault_core::input::{InputError, SecretLine, StdinSecrets, read_line};
use pvault_core::passphrase::WordCount;
use pvault_core::platform::terminal;
use pvault_core::platform::{CoreDumpProtection, disable_core_dumps};
use pvault_core::records::{Delivery, Settings};
use pvault_core::render;
use pvault_core::secrets::SecretBytes;
use pvault_core::tpm::{TpmOptions, TpmTarget};
use pvault_core::vault::export::GetError;
use pvault_core::vault::init::{InitOptions, InitOutcome, PassphraseChoice};
use pvault_core::vault::{self, Access, Prompter, Session};

/// Offline encrypted file vault.
#[derive(Debug, Parser)]
#[command(name = "pvault", version, arg_required_else_help = true)]
struct Cli {
    /// Read secrets from standard input, one per line, in the documented
    /// order.
    #[arg(long, global = true)]
    secrets_stdin: bool,
    /// The TPM for bound vaults: `device` (default, /dev/tpmrm0) or
    /// `swtpm:PORT` (a local emulator). Not a secret.
    #[arg(long, global = true, value_parser = parse_tpm)]
    tpm: Option<TpmTarget>,
    /// The TPM owner authorization will be supplied (hidden prompt, or the
    /// documented --secrets-stdin line).
    #[arg(long, global = true)]
    tpm_owner_auth: bool,
    #[command(subcommand)]
    command: Command,
}

fn parse_tpm(s: &str) -> Result<TpmTarget, String> {
    TpmTarget::parse(s).ok_or_else(|| "expected device or swtpm:PORT".to_owned())
}

#[derive(Debug, Subcommand)]
enum DuressAction {
    /// Create a duress passphrase (inactive in this version).
    Set {
        /// The vault folder.
        vault_dir: PathBuf,
    },
    /// Remove the duress passphrase.
    Disable {
        /// The vault folder.
        vault_dir: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CardsArg {
    /// Printed cards; the card files are temporary.
    Paper,
    /// The card files are the recovery cards.
    Digital,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RiskArg {
    /// Digital recovery cards (SI-52).
    DigitalCards,
    /// Both digital cards on one volume.
    SameVolume,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Portable,
    Bound,
}

// Parsed once per process; boxing `init`'s options would add an allocation
// for nothing (the variant is largest on Windows, where `PathBuf` is bigger).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Create a vault (or resume an interrupted setup).
    Init {
        /// The vault folder.
        vault_dir: PathBuf,
        /// Vault mode (required for a new vault). Bound needs Linux with a
        /// TPM.
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
        /// Recovery cards: printed (paper) or kept as files (digital).
        /// Required for a new vault.
        #[arg(long, value_enum)]
        cards: Option<CardsArg>,
        /// Paper: an existing folder outside the vault for the two card
        /// files to print.
        #[arg(long)]
        cards_dir: Option<PathBuf>,
        /// Digital: the folder for Card A (a supported local drive).
        #[arg(long)]
        card_a_dir: Option<PathBuf>,
        /// Digital: the folder for Card B (another drive and place).
        #[arg(long)]
        card_b_dir: Option<PathBuf>,
        /// Digital: acknowledge a risk without a typed phrase
        /// (digital-cards, same-volume). Repeatable. Not a secret.
        #[arg(long, value_enum)]
        accept_risk: Vec<RiskArg>,
        /// Generated passphrase of this many words (10 to 16).
        #[arg(long, value_parser = clap::value_parser!(u8).range(10..=16), conflicts_with = "custom")]
        words: Option<u8>,
        /// Write your own passphrase.
        #[arg(long)]
        custom: bool,
        /// Argon2id memory in MiB (256 to 4096).
        #[arg(long, value_parser = clap::value_parser!(u32).range(256..=4096), default_value_t = 1024)]
        kdf_memory: u32,
        /// Argon2id passes (3 to 16).
        #[arg(long, value_parser = clap::value_parser!(u32).range(3..=16), default_value_t = 4)]
        kdf_iterations: u32,
        /// Argon2id lanes (1 to 8).
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=8), default_value_t = 4)]
        kdf_parallelism: u32,
        /// Verify Card A from a PNG photo, read after the printing
        /// acknowledgment. Needs a terminal (also with --secrets-stdin).
        #[arg(long)]
        card_a_png: Option<PathBuf>,
        /// Verify Card B from a PNG photo, read after the printing
        /// acknowledgment. Needs a terminal (also with --secrets-stdin).
        #[arg(long)]
        card_b_png: Option<PathBuf>,
        /// Bound, digital: the folder for the bound card file.
        #[arg(long)]
        card_dir: Option<PathBuf>,
        /// Bound, paper: verify the bound card from a PNG photo.
        #[arg(long)]
        card_png: Option<PathBuf>,
    },
    /// Set up or remove a duress passphrase.
    Duress {
        #[command(subcommand)]
        action: DuressAction,
    },
    /// Add a file.
    Add {
        /// The vault folder.
        vault_dir: PathBuf,
        /// The file to add.
        source: PathBuf,
        /// Its path in the vault.
        vault_path: String,
        /// Replace exactly this file entry.
        #[arg(long)]
        replace: bool,
    },
    /// List entries.
    List {
        /// The vault folder.
        vault_dir: PathBuf,
        /// Only this entry and its descendants.
        vault_path: Option<String>,
    },
    /// Export one file.
    Get {
        /// The vault folder.
        vault_dir: PathBuf,
        /// The file in the vault.
        vault_path: String,
        /// Where to write it (must not exist).
        destination: PathBuf,
        /// Not available in this version.
        #[arg(long)]
        force: bool,
    },
    /// Remove a file or folder entry.
    Rm {
        /// The vault folder.
        vault_dir: PathBuf,
        /// The entry.
        vault_path: String,
        /// Remove a folder and its contents.
        #[arg(long)]
        recursive: bool,
    },
    /// Show the vault's public state.
    Status {
        /// The vault folder.
        vault_dir: PathBuf,
    },
    /// Remove files left by interrupted exports and setups.
    CleanPartials,
    /// Delete one recovery card file you name (asks on the terminal).
    DiscardCard {
        /// The card file.
        card_file: PathBuf,
        /// Compare with this vault's public header (not verified).
        #[arg(long)]
        vault: Option<PathBuf>,
    },
}

/// Exit codes (`docs/CLI.md` 3).
fn code(e: &Error) -> u8 {
    match e {
        Error::VaultInUse => 3,
        Error::PendingJournal(_)
        | Error::UnownedLeftovers(_)
        | Error::RecordFull(_)
        | Error::InitPending
        | Error::Blocked(_)
        | Error::AckRequired(_)
        | Error::NotConfirmed(_) => 4,
        Error::OutcomeUnknown
        | Error::DurabilityUnknown
        | Error::Indeterminate
        | Error::UnresolvedCleanup
        | Error::ExportUnconfirmed
        | Error::ExportOutcomeUnknown => 5,
        Error::UnsupportedFileSystem(_)
        | Error::MemoryPolicy { .. }
        | Error::MemoryResource { .. }
        | Error::NeedsTerminal(_)
        | Error::SettingsUnavailable(_)
        | Error::SettingsNotPrivate(_)
        | Error::RegistrationUnsupported(_)
        | Error::RecordDamaged(_)
        | Error::NoReplaceUnsupported
        | Error::DestinationNotPrivate(_)
        | Error::Unsupported(_)
        | Error::BoundVault
        | Error::TpmUnavailable(_)
        | Error::TpmIdentity
        | Error::TpmHierarchyDisabled
        | Error::TpmLockout
        | Error::TpmNoFreeHandle
        | Error::TpmSession
        | Error::DuressUnavailable(_) => 6,
        Error::TpmOwnerAuthRequired | Error::DuressConfigured | Error::TpmIndexElsewhere(_) => 4,
        Error::TpmDefineUnknown => 5,
        Error::Input(
            InputError::NoTerminal | InputError::StdinIsTerminal | InputError::StdinNotTerminal,
        ) => 6,
        Error::ForceRefused | Error::SameCardFolder => 2,
        Error::Cancelled => 7,
        _ => 1,
    }
}

/// The owner's typed path, normalized when possible, rendered (1.1, 1.2).
fn shown_path(typed: &str) -> String {
    match pvault_core::paths::normalize_input(typed) {
        Ok(p) => render::text(&p.stored),
        Err(_) => render::text(typed),
    }
}

/// Messages that name the owner's typed path (`docs/CLI.md` 7).
fn message(e: &Error, typed: Option<&str>) -> String {
    let Some(t) = typed else { return e.to_string() };
    let p = shown_path(t);
    match e {
        Error::PathExists => {
            format!("{p} already exists in the vault. Use --replace to replace it.")
        }
        Error::PathCollision => format!(
            "{p} collides with an existing entry that differs only by letter case or Unicode form. Use pvault list to see it."
        ),
        Error::PathUnsupported => {
            format!("{p} contains a character this version of pvault does not support.")
        }
        Error::PathNotFound => format!("{p} is not in the vault."),
        _ => e.to_string(),
    }
}

fn fail(e: &Error, typed: Option<&str>) -> ExitCode {
    eprintln!("{}", message(e, typed));
    ExitCode::from(code(e))
}

/// The wait after a shown secret (`docs/CLI.md` 2).
const DISMISS: &str = "Press Enter when you have written it down (nothing needs to be typed): ";
/// Shown after any input other than an empty line.
const DISMISS_AGAIN: &str = "Nothing needs to be typed here; that input was discarded. Press Enter when you have written it down: ";

/// Terminal and `--secrets-stdin` interaction (`docs/CLI.md` 2).
struct Owner {
    stdin: Option<StdinSecrets>,
    tty: bool,
    /// Whether standard input is a terminal. Without `--secrets-stdin`, a
    /// secret prompt on a non-terminal standard input is refused (spec 10
    /// item 6), even when a terminal device exists.
    stdin_terminal: bool,
}

impl Owner {
    fn stdin_line(&mut self) -> Result<SecretLine, Error> {
        let s = self
            .stdin
            .as_mut()
            .ok_or(Error::Input(InputError::NoTerminal))?;
        match s.next_secret() {
            Ok(l) if l.terminated() => Ok(l),
            Ok(_) | Err(InputError::Cancelled) => Err(Error::InputEnded),
            Err(e) => Err(Error::Input(e)),
        }
    }
}

impl Prompter for Owner {
    fn secret(&mut self, prompt: &str) -> Result<SecretLine, Error> {
        if self.stdin.is_some() {
            return self.stdin_line();
        }
        if !self.tty {
            return Err(Error::Input(InputError::NoTerminal));
        }
        if !self.stdin_terminal {
            return Err(Error::Input(InputError::StdinNotTerminal));
        }
        terminal::read_secret(prompt).map_err(|e| match e {
            InputError::Cancelled => Error::Cancelled,
            e => Error::Input(e),
        })
    }

    fn card_text(&mut self, label: &str) -> Result<SecretBytes<PAYLOAD_LEN>, Error> {
        if self.stdin.is_some() {
            // One whole line holding exactly 216 symbols.
            let line = self.stdin_line()?;
            let mut reader = CardTextReader::new();
            return match reader.push_line(&line).map_err(Error::CardText)? {
                CardTextProgress::Complete => reader.payload().map_err(Error::CardText),
                CardTextProgress::NeedMore => Err(Error::CardText(reader.ended())),
            };
        }
        if !self.tty {
            return Err(Error::Input(InputError::NoTerminal));
        }
        if !self.stdin_terminal {
            return Err(Error::Input(InputError::StdinNotTerminal));
        }
        let prompt = format!("{label}: type the card text (hidden; it may span lines): ");
        let result = terminal::read_hidden(&prompt, |src| {
            let mut reader = CardTextReader::new();
            loop {
                let line = match read_line(src) {
                    Ok(l) => l,
                    Err(InputError::Cancelled) => return Ok(Err(reader.ended())),
                    Err(e) => return Err(e),
                };
                match reader.push_line(&line) {
                    Ok(CardTextProgress::Complete) => return Ok(reader.payload()),
                    Ok(CardTextProgress::NeedMore) => {}
                    Err(e) => return Ok(Err(e)),
                }
            }
        })
        .map_err(Error::Input)?;
        result.map_err(Error::CardText)
    }

    fn card_png_path(&mut self, label: &str) -> Result<Option<PathBuf>, Error> {
        if !self.tty || self.stdin.is_some() {
            return Ok(None);
        }
        let line = terminal::read_visible(&format!(
            "{label}: enter the path of a PNG photo of the printed card, or press Enter to type its text: "
        ))
        .map_err(Error::Input)?;
        let line = line.trim();
        Ok((!line.is_empty()).then(|| PathBuf::from(line)))
    }

    fn confirm(&mut self, prompt: &str, phrase: &str) -> Result<bool, Error> {
        if !self.tty {
            return Ok(false);
        }
        let line = terminal::read_visible(prompt).map_err(Error::Input)?;
        Ok(line.trim_end_matches(['\r', '\n']) == phrase)
    }

    fn acknowledge(&mut self, prompt: &str) -> Result<(), Error> {
        if self.tty {
            terminal::read_visible(prompt).map_err(Error::Input)?;
        }
        Ok(())
    }

    fn show_secret(&mut self, text: &str) -> Result<(), Error> {
        if !self.tty {
            return Err(Error::NeedsTerminal(
                "No terminal is available to show the passphrase.",
            ));
        }
        terminal::show(&format!("\n{text}\n")).map_err(Error::Input)?;
        // Approved 2026-10-11: a labelled wait, with echo off, that only an
        // empty line ends. Anything typed is discarded unseen, the secret
        // stays on screen, and the instruction is repeated.
        terminal::wait_for_dismissal(DISMISS, DISMISS_AGAIN).map_err(|e| match e {
            InputError::Cancelled => Error::Cancelled,
            e => Error::Input(e),
        })?;
        // Best effort: clear the screen and scrollback (7.4b remnants).
        terminal::clear_screen();
        Ok(())
    }

    fn notice(&mut self, text: &str) {
        eprintln!("{text}");
    }

    fn interactive(&self) -> bool {
        self.tty && self.stdin.is_none()
    }

    fn has_terminal(&self) -> bool {
        self.tty
    }
}

fn settings_optional(ui: &mut Owner) -> Option<Settings> {
    match Settings::open() {
        Ok(s) => Some(s),
        Err(e) => {
            ui.notice(&format!("Warning: {e}"));
            None
        }
    }
}

fn unlock(
    vault: &Path,
    ui: &mut Owner,
    settings: Option<&Settings>,
    access: Access,
    tpm: &TpmOptions,
) -> Result<Session, Error> {
    vault::unlock_with(vault, ui, settings, access, tpm)
}

fn estimate(
    p: &pvault_core::passphrase::CustomPassphrase,
    context: &str,
) -> Result<(estimator::Band, Vec<String>), Error> {
    let e = estimator::estimate(p, context)?;
    let mut feedback = Vec::new();
    if let Some(w) = e.warning() {
        feedback.push(w.to_string());
    }
    feedback.extend(e.suggestions().iter().map(ToString::to_string));
    Ok((e.band(), feedback))
}

/// Whether the command reads a secret (a passphrase, card text or the TPM
/// owner authorization) in some branch.
fn reads_secrets(command: &Command) -> bool {
    matches!(
        command,
        Command::Init { .. }
            | Command::Duress { .. }
            | Command::Add { .. }
            | Command::List { .. }
            | Command::Get { .. }
            | Command::Rm { .. }
    )
}

fn run(cli: Cli, dumps: Option<CoreDumpProtection>) -> ExitCode {
    let tty = terminal::has_terminal() && !test_without_terminal();
    let stdin_terminal = std::io::stdin().is_terminal();
    // Spec 10 item 6 (`docs/CLI.md` 2): without --secrets-stdin, a secret is
    // never read while standard input is redirected, even when a terminal
    // device exists; refused before anything is read or created.
    if !cli.secrets_stdin && tty && !stdin_terminal && reads_secrets(&cli.command) {
        return fail(&Error::Input(InputError::StdinNotTerminal), None);
    }
    let stdin = if cli.secrets_stdin {
        match StdinSecrets::open() {
            Ok(s) => Some(s),
            Err(e) => return fail(&Error::Input(e), None),
        }
    } else {
        None
    };
    let mut ui = Owner {
        stdin,
        tty,
        stdin_terminal,
    };
    let tpm_opts = TpmOptions {
        target: cli.tpm.clone().unwrap_or(TpmTarget::Device),
        owner_auth_declared: cli.tpm_owner_auth,
    };
    match cli.command {
        Command::Init {
            vault_dir,
            mode,
            cards,
            cards_dir,
            card_a_dir,
            card_b_dir,
            accept_risk,
            words,
            custom,
            kdf_memory,
            kdf_iterations,
            kdf_parallelism,
            card_a_png,
            card_b_png,
            card_dir,
            card_png,
        } => {
            // A resume (`pvault init <vault>`) takes no card options.
            let resume_only = mode.is_none()
                && cards.is_none()
                && cards_dir.is_none()
                && card_a_dir.is_none()
                && card_b_dir.is_none()
                && accept_risk.is_empty()
                && card_a_png.is_none()
                && card_b_png.is_none()
                && card_dir.is_none()
                && card_png.is_none();
            match mode {
                // D10: refused before anything is created.
                Some(ModeArg::Bound) if !pvault_core::tpm::supported() => {
                    return fail(&Error::BoundVault, None);
                }
                None if !resume_only => {
                    eprintln!("--mode portable or --mode bound is required.");
                    return ExitCode::from(2);
                }
                _ => {}
            }
            let bound = matches!(mode, Some(ModeArg::Bound));
            let digital = cards == Some(CardsArg::Digital);
            if !resume_only {
                let usage = |m: &str| {
                    eprintln!("{m}");
                    ExitCode::from(2)
                };
                match cards {
                    None => return usage("--cards paper or --cards digital is required."),
                    Some(CardsArg::Paper) => {
                        if card_a_dir.is_some()
                            || card_b_dir.is_some()
                            || card_dir.is_some()
                            || !accept_risk.is_empty()
                        {
                            return usage(
                                "--card-a-dir, --card-b-dir, --card-dir and --accept-risk belong to --cards digital.",
                            );
                        }
                        if cards_dir.is_none() {
                            return usage("--cards-dir is required with --cards paper.");
                        }
                    }
                    Some(CardsArg::Digital) => {
                        if cards_dir.is_some()
                            || card_a_png.is_some()
                            || card_b_png.is_some()
                            || card_png.is_some()
                        {
                            return usage(
                                "--cards-dir, --card-a-png, --card-b-png and --card-png belong to --cards paper.",
                            );
                        }
                        if bound && card_dir.is_none() {
                            return usage(
                                "--card-dir is required with --mode bound --cards digital.",
                            );
                        }
                        if !bound && (card_a_dir.is_none() || card_b_dir.is_none()) {
                            return usage(
                                "--card-a-dir and --card-b-dir are required with --cards digital.",
                            );
                        }
                    }
                }
                // One bound card; two portable cards (D8).
                if bound
                    && (card_a_dir.is_some()
                        || card_b_dir.is_some()
                        || card_a_png.is_some()
                        || card_b_png.is_some())
                {
                    return usage(
                        "--card-a-dir, --card-b-dir, --card-a-png and --card-b-png belong to --mode portable.",
                    );
                }
                if !bound && (card_dir.is_some() || card_png.is_some()) {
                    return usage("--card-dir and --card-png belong to --mode bound.");
                }
            }
            // O1 (2026-10-06): PNG verification waits for the printing
            // acknowledgment on the terminal; refused before anything exists.
            if (card_a_png.is_some() || card_b_png.is_some() || card_png.is_some()) && !ui.tty {
                return fail(
                    &Error::NeedsTerminal(
                        "Verifying a card from a PNG photo needs a terminal for the printing acknowledgment, also with --secrets-stdin. Nothing was written.",
                    ),
                    None,
                );
            }
            // SI-52 5: without the option and without a terminal the
            // acknowledgment cannot be given; refused before anything exists
            // (the settings folder included).
            if digital && !accept_risk.contains(&RiskArg::DigitalCards) && !ui.tty {
                eprintln!(
                    "{}",
                    if bound {
                        vault::init::DIGITAL_RISKS_BOUND
                    } else {
                        vault::init::DIGITAL_RISKS
                    }
                );
                return fail(
                    &Error::AckRequired(
                        "Digital recovery cards need your acknowledgment: give --accept-risk digital-cards, or type STORE CARDS DIGITALLY on a terminal. Nothing was written.",
                    ),
                    None,
                );
            }
            if kdf_memory < 1024 {
                eprintln!("Lower memory makes passphrase guessing cheaper.");
            }
            let passphrase = if custom {
                PassphraseChoice::Custom
            } else {
                match WordCount::new(words.unwrap_or(12)) {
                    Ok(c) => PassphraseChoice::Generated(c),
                    Err(e) => return fail(&Error::Passphrase(e), None),
                }
            };
            let settings = match Settings::open() {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            let opts = InitOptions {
                vault: vault_dir.clone(),
                delivery: if digital {
                    Delivery::Digital
                } else {
                    Delivery::Paper
                },
                cards_dir: cards_dir.unwrap_or_default(),
                card_a_dir,
                card_b_dir,
                accept_digital_cards: accept_risk.contains(&RiskArg::DigitalCards),
                accept_same_volume: accept_risk.contains(&RiskArg::SameVolume),
                passphrase,
                argon2: Argon2Params {
                    m_kib: kdf_memory * 1024,
                    t: kdf_iterations,
                    p: kdf_parallelism,
                },
                card_a_png,
                card_b_png,
                estimate: &estimate,
                mode: if bound { Mode::Bound } else { Mode::Portable },
                card_dir,
                card_png,
                tpm: tpm_opts.clone(),
            };
            if resume_only {
                // Only an existing folder can be resumed; a new vault needs
                // the options.
                if !vault_dir.exists() {
                    eprintln!("--mode portable and --cards are required to create a vault.");
                    return ExitCode::from(2);
                }
            }
            match vault::init::init(&opts, &settings, &mut ui) {
                Ok(InitOutcome::Created {
                    vault_id,
                    card_files,
                }) => {
                    eprintln!(
                        "Vault created: {} (portable, vault ID {}). Keep Card A and Card B apart; together they can recover the vault without the passphrase.",
                        render::path(&vault_dir),
                        pvault_core::records::hex(&vault_id)
                    );
                    // SI-52 R5: optional, interactive only, after every
                    // handle and lock of `init` is released.
                    match card_files.map(|files| {
                        vault::init::card_check_after_commit(&vault_dir, &files, &mut ui)
                    }) {
                        Some(Err(e)) => fail(&e, None),
                        _ => ExitCode::SUCCESS,
                    }
                }
                Ok(InitOutcome::Finished { vault_id }) => {
                    eprintln!(
                        "The interrupted setup was finished: {} (vault ID {}).",
                        render::path(&vault_dir),
                        pvault_core::records::hex(&vault_id)
                    );
                    ExitCode::SUCCESS
                }
                Ok(InitOutcome::RolledBack) => {
                    eprintln!("The interrupted setup was removed. Run pvault init again.");
                    ExitCode::SUCCESS
                }
                Err(Error::TargetNotEmpty) if resume_only => {
                    eprintln!("--mode portable and --cards are required to create a vault.");
                    ExitCode::from(2)
                }
                Err(e) => fail(&e, None),
            }
        }
        Command::Add {
            vault_dir,
            source,
            vault_path,
            replace,
        } => {
            let settings = settings_optional(&mut ui);
            let mut s = match unlock(
                &vault_dir,
                &mut ui,
                settings.as_ref(),
                Access::Write,
                &tpm_opts,
            ) {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            match vault::edit::add(
                &mut s,
                &source,
                &vault_path,
                replace,
                settings.as_ref(),
                &mut ui,
            ) {
                Ok(o) => {
                    let p = render::text(&o.stored);
                    if o.changed {
                        eprintln!("Stored as: {p}");
                    }
                    if o.created_dirs > 0 {
                        eprintln!("Created {} folders.", o.created_dirs);
                    }
                    eprintln!("Added {p} ({} bytes).", o.size);
                    report_kept(&o.kept);
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e, Some(&vault_path)),
            }
        }
        Command::List {
            vault_dir,
            vault_path,
        } => {
            let settings = settings_optional(&mut ui);
            let s = match unlock(
                &vault_dir,
                &mut ui,
                settings.as_ref(),
                Access::Read,
                &tpm_opts,
            ) {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            match vault::export::list(&s, vault_path.as_deref(), &mut out) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => fail(&e, vault_path.as_deref()),
            }
        }
        Command::Get {
            vault_dir,
            vault_path,
            destination,
            force,
        } => {
            if force {
                return fail(&Error::ForceRefused, None);
            }
            // O3: refused before the passphrase is read and before anything
            // is created (the settings folder included).
            if let Err(e) = vault::export::check_destination(&destination) {
                return fail(&e, None);
            }
            let settings = match Settings::open() {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            let s = match unlock(
                &vault_dir,
                &mut ui,
                Some(&settings),
                Access::Read,
                &tpm_opts,
            ) {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            let dest = render::path(&destination);
            match vault::export::get(&s, &vault_path, &destination, &settings, &mut ui) {
                Ok(o) => {
                    eprintln!(
                        "Exported {} to {dest} ({} bytes).",
                        render::text(&o.stored),
                        o.size
                    );
                    ExitCode::SUCCESS
                }
                Err(GetError::Unconfirmed(o)) => {
                    eprintln!(
                        "Exported {} to {dest}, but the export could not be confirmed as durable.",
                        render::text(&o.stored)
                    );
                    ExitCode::from(5)
                }
                Err(GetError::Unknown) => {
                    eprintln!("The export's outcome could not be determined; check {dest}.");
                    ExitCode::from(5)
                }
                Err(GetError::Failed(Error::DestinationExists)) => {
                    eprintln!("{dest} already exists; nothing was written.");
                    ExitCode::from(1)
                }
                Err(GetError::Failed(Error::NameExists(p))) => {
                    eprintln!("{p} already exists; nothing was written.");
                    ExitCode::from(1)
                }
                Err(GetError::Failed(e)) => fail(&e, Some(&vault_path)),
            }
        }
        Command::Rm {
            vault_dir,
            vault_path,
            recursive,
        } => {
            let settings = settings_optional(&mut ui);
            let mut s = match unlock(
                &vault_dir,
                &mut ui,
                settings.as_ref(),
                Access::Write,
                &tpm_opts,
            ) {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            match vault::edit::rm(&mut s, &vault_path, recursive, settings.as_ref(), &mut ui) {
                Ok((n, kept)) => {
                    eprintln!("Removed {n} entries.");
                    report_kept(&kept);
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e, Some(&vault_path)),
            }
        }
        Command::Status { vault_dir } => {
            let settings = Settings::open().ok();
            match vault::status::status(&vault_dir, settings.as_ref(), dumps, &tpm_opts) {
                Ok((report, warning)) => {
                    if let Some(w) = warning {
                        eprintln!("{w}");
                    }
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(report.as_bytes());
                    ExitCode::SUCCESS
                }
                Err(Error::HeaderInvalid) => {
                    eprintln!("The header does not parse.");
                    ExitCode::from(1)
                }
                Err(e) => fail(&e, None),
            }
        }
        Command::Duress { action } => {
            let (vault_dir, set) = match action {
                DuressAction::Set { vault_dir } => (vault_dir, true),
                DuressAction::Disable { vault_dir } => (vault_dir, false),
            };
            let settings = settings_optional(&mut ui);
            let mut s = match unlock(
                &vault_dir,
                &mut ui,
                settings.as_ref(),
                Access::Write,
                &tpm_opts,
            ) {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            let r = if set {
                vault::duress::set(&mut s, settings.as_ref(), &mut ui)
            } else {
                vault::duress::disable(&mut s, settings.as_ref(), &mut ui)
            };
            match r {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, None),
            }
        }
        Command::DiscardCard { card_file, vault } => {
            let settings = Settings::open().ok();
            match vault::discard::discard_card(
                &card_file,
                vault.as_deref(),
                settings.as_ref(),
                &mut ui,
            ) {
                Ok(o) if o.deleted => ExitCode::SUCCESS,
                Ok(_) => ExitCode::from(1),
                Err(e) => fail(&e, None),
            }
        }
        Command::CleanPartials => {
            let settings = match Settings::open() {
                Ok(s) => s,
                Err(e) => return fail(&e, None),
            };
            match vault::export::clean_partials(&settings, &mut ui) {
                Ok(r) if r.stale == 0 => {
                    if r.damaged.is_empty() {
                        eprintln!("No stale files are recorded.");
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(6)
                    }
                }
                Ok(r) if !r.confirmed => ExitCode::from(4),
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => fail(&e, None),
            }
        }
    }
}

/// Crash-test builds only: `PVAULT_TEST_NO_TERMINAL` makes the child behave
/// as if no terminal existed, so a developer's terminal is never read by a
/// test. The variable does not exist in release builds (F85).
#[cfg(feature = "fault-injection")]
fn test_without_terminal() -> bool {
    std::env::var_os("PVAULT_TEST_NO_TERMINAL").is_some()
}

#[cfg(not(feature = "fault-injection"))]
fn test_without_terminal() -> bool {
    false
}

fn report_kept(kept: &[String]) {
    if !kept.is_empty() {
        eprintln!(
            "{} vault files could not be proven unused and were left in place: {}.",
            kept.len(),
            kept.iter()
                .map(|k| render::text(k))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

/// Runs the CLI with the process arguments and returns its exit code.
pub fn main() -> ExitCode {
    // The custom-passphrase estimator child (SI-51). It hardens itself and
    // never reaches the argument parser.
    let mut args = std::env::args_os().skip(1);
    if let (Some(first), None) = (args.next(), args.next())
        && first == estimator::CHILD_ARG
    {
        return ExitCode::from(u8::try_from(estimator::run_child()).unwrap_or(1));
    }

    // The TPM stack's logs carry secrets at debug level and add detail to
    // `Unlock failed.` at every level: off, before any TPM operation.
    // SAFETY: nothing has started a thread yet (the estimator child returned
    // above without reaching here).
    #[allow(unsafe_code)]
    unsafe {
        pvault_core::platform::quiet_tpm_stack();
    }
    // Before anything else, so no later crash can write secrets to disk
    // (spec Section 10.3).
    let dumps = match disable_core_dumps() {
        Ok(p) => Some(p),
        Err(err) => {
            eprintln!("warning: {err}. A crash could write this process's memory to disk.");
            None
        }
    };

    let cli = Cli::parse();
    let code = run(cli, dumps);
    let _ = std::io::stderr().flush();
    code
}
