//! `status` (`docs/CLI.md` 6.6; spec 5.8): no passphrase, shared lock only,
//! public state only, never writes to the vault.

use std::fmt::Write as _;
use std::path::Path;

use crate::errors::Error;
use crate::header::{PassphraseKind, SlotFields};
use crate::journal::{InitPhase, Record, TransitionOp, UpdatePhase};
use crate::lock;
use crate::platform::CoreDumpProtection;
use crate::platform::fs::{self as pfs, Dir};
use crate::records::{Settings, hex};
use crate::resources::{self, SystemMemory};
use crate::secrets::LockedBuf;
use crate::store::{self, JOURNAL, JOURNAL_TMP};

/// The pending journal's public operation and phase (not verified).
fn pending_text(dir: &Dir) -> Result<String, Error> {
    let bytes = store::read_capped(dir, JOURNAL, crate::journal::MAX_JOURNAL_LEN, || {
        Error::JournalInvalid
    });
    Ok(match bytes {
        Ok(Some(b)) => match Record::parse(&b) {
            Ok(Record::Init(r)) => format!(
                "init {} (not verified)",
                match r.phase {
                    InitPhase::Prepared => "prepared",
                    InitPhase::KeytableCreated => "keytable_created",
                    InitPhase::KeytableWritten => "keytable_written",
                    InitPhase::Committing => "committing",
                }
            ),
            Ok(Record::Update(r)) => format!(
                "update {} (not verified)",
                match r.phase {
                    UpdatePhase::Staged => "staged",
                    UpdatePhase::Committing => "committing",
                    UpdatePhase::Cleaned => "cleaned",
                }
            ),
            Ok(Record::Transition(r)) => format!(
                "{} (not verified)",
                match r.op {
                    TransitionOp::Recover => "recovery",
                    TransitionOp::Convert => "conversion",
                }
            ),
            Err(_) => "a journal that does not parse".to_owned(),
        },
        Ok(None) if dir.exists(JOURNAL_TMP).map_err(Error::Io)? => "a journal temp only".to_owned(),
        Ok(None) => "none".to_owned(),
        Err(_) => "a journal that does not parse".to_owned(),
    })
}

/// Builds the `status` report, and the 9.7 warning when this computer has
/// seen a higher generation (the record is only read, never updated).
pub fn status(
    vault: &Path,
    settings: Option<&Settings>,
    dumps: Option<CoreDumpProtection>,
) -> Result<(String, Option<String>), Error> {
    let dir = Dir::open(vault).map_err(Error::Io)?;
    let _lock = lock::status_shared(&dir)?.ok_or(Error::VaultInUse)?;
    let header = super::header_of(&dir)?;
    let core = header.core();
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "Vault ID:            {}", hex(&core.vault_id));
    let _ = writeln!(w, "Mode:                {}", core.mode.as_str());
    let _ = writeln!(
        w,
        "Generation:          {}   (key table {})",
        core.generation, core.keytable_gen
    );
    let fits = resources::check_argon2(&core.argon2, &SystemMemory).is_ok();
    let _ = writeln!(
        w,
        "Argon2id:            {} MiB, t={}, p={}   (this computer: {})",
        core.argon2.m_kib / 1024,
        core.argon2.t,
        core.argon2.p,
        if fits { "OK" } else { "needs more memory" }
    );
    let _ = writeln!(
        w,
        "Passphrase kind:     {}",
        match core.passphrase_kind {
            PassphraseKind::Words => "generated",
            PassphraseKind::Custom => "custom",
        }
    );
    let duress = match header.slots() {
        SlotFields::Portable(p) => p.duress_tag.is_some(),
        SlotFields::Bound(b) => b.duress_tag.is_some(),
    };
    let _ = writeln!(
        w,
        "Duress:              {}",
        if duress { "configured" } else { "off" }
    );
    let _ = writeln!(w, "Card set:            {}", hex(&core.card_set_id));
    let _ = writeln!(w, "Pending operation:   {}", pending_text(&dir)?);
    let fs = match dir.volume() {
        Ok(v) if pfs::is_allowed(&v.fs_type) => format!("{}, supported", v.fs_type),
        Ok(v) => format!("{}, read-only for pvault", v.fs_type),
        Err(_) => "unknown, read-only for pvault".to_owned(),
    };
    let _ = writeln!(w, "File system:         {fs}");
    let mut warning = None;
    let rollback = match settings.map(|s| s.rollback_recorded(&core.vault_id)) {
        Some(Ok(Some(g))) => {
            if g > core.generation {
                warning = Some(format!(
                    "Warning: this vault is older than a copy opened on this computer before (generation {} < {g}). It may be an old copy.",
                    core.generation
                ));
            }
            format!("highest generation seen here {g}")
        }
        Some(Ok(None)) => "none".to_owned(),
        _ => "unavailable".to_owned(),
    };
    let _ = writeln!(w, "Rollback record:     {rollback}");
    let locking = LockedBuf::try_zeroed(4096).is_ok_and(|b| b.is_locked());
    let _ = writeln!(
        w,
        "Protection:          core dumps {}, memory locking {}",
        match dumps {
            Some(CoreDumpProtection::Disabled) => "off",
            _ => "best effort",
        },
        if locking { "available" } else { "limited" }
    );
    Ok((out, warning))
}
