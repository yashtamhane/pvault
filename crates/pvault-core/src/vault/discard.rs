//! `discard-card` (SI-52 8.3): the owner names one card file to destroy.
//!
//! pvault never chooses the file. It reads the named file through the
//! format 1 reader, shows its public fields, compares them with a vault's
//! public header when asked (an unauthenticated comparison, and labeled as
//! such), always requires the stronger typed confirmation on the terminal
//! device, and deletes only the file it opened, through that handle.

use std::path::Path;

use crate::card;
use crate::errors::Error;
use crate::lock;
use crate::platform::fs::Dir;
use crate::records::{Settings, hex, native_path};
use crate::render;
use crate::store;

use super::Prompter;
use super::export::open_parent;
use super::init::read_bounded;

/// What `discard-card` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardOutcome {
    /// Whether the file was deleted.
    pub deleted: bool,
    /// Card-record entries removed for that path.
    pub forgotten: usize,
}

/// `pvault discard-card <card-file> [--vault <vault-dir>]`.
pub fn discard_card(
    file: &Path,
    vault: Option<&Path>,
    settings: Option<&Settings>,
    ui: &mut dyn Prompter,
) -> Result<DiscardOutcome, Error> {
    let abs = std::path::absolute(file).map_err(Error::Io)?;
    let parent_path = abs
        .parent()
        .ok_or(Error::Unsupported("the card file needs a parent folder"))?;
    let name = abs
        .file_name()
        .ok_or(Error::Unsupported("the card file needs a name"))?;
    let parent = open_parent(parent_path)?;
    let opened = parent
        .open_regular(name, false)
        .map_err(Error::Io)?
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such card file",
            ))
        })?;
    let bytes = read_bounded(&opened)?;
    let read = card::parse_card_file(&bytes).map_err(Error::CardFile)?;
    let created = core::str::from_utf8(&bytes)
        .ok()
        .and_then(card::card_file_date)
        .unwrap_or("unknown")
        .to_owned();
    drop(bytes);
    let (vault_id, set_id, role) = (read.vault_id(), read.set_id(), read.role());
    drop(read);
    ui.notice(&format!(
        "{} is {role} of vault {}, card set {}, labeled as created {created}.",
        render::path(&abs),
        hex(&vault_id),
        hex(&set_id)
    ));
    if let Some(v) = vault {
        // Public header fields only, read without any secret: an
        // unauthenticated comparison, never a verification.
        let header = Dir::open(v).ok().and_then(|d| {
            let _shared = lock::status_shared(&d).ok().flatten();
            store::read_header(&d).ok().flatten()
        });
        match header {
            Some(h) => {
                let core = h.core();
                let what = if core.vault_id != vault_id {
                    "names a different vault"
                } else if core.card_set_id == set_id {
                    "names this card's set as its current card set"
                } else {
                    "names a different card set as current (this card may be old)"
                };
                ui.notice(&format!(
                    "Not verified: the header of {} {what}. These header fields were read without any secret; anyone who can write that folder could have changed them.",
                    render::path(v)
                ));
            }
            None => ui.notice(&format!(
                "The header of {} could not be read; nothing is known about this card's status.",
                render::path(v)
            )),
        }
    }
    ui.notice("pvault cannot verify whether this is a current card. Destroying a current card leaves the vault recoverable only with the passphrase or with another copy of this card.");
    if !ui.has_terminal() {
        return Err(Error::NotConfirmed(
            "Discarding a card file needs the typed confirmation on a terminal. Nothing was deleted.",
        ));
    }
    let phrase = format!("DISCARD RECOVERY CARD {}", hex(&set_id[..4]));
    if !ui.confirm(&format!("Type {phrase} to delete this file: "), &phrase)? {
        return Err(Error::NotConfirmed("Not confirmed. Nothing was deleted."));
    }
    // Only the file opened and read above, through that handle (7.2).
    if !parent.delete_held(name, &opened).map_err(Error::Io)? {
        ui.notice("The file changed after it was read; nothing was deleted.");
        return Ok(DiscardOutcome {
            deleted: false,
            forgotten: 0,
        });
    }
    drop(opened);
    parent.flush().map_err(Error::Io)?;
    let forgotten = match (settings, native_path(&abs)) {
        (Some(s), Some(p)) => s.forget_card_file(&p).unwrap_or(0),
        _ => 0,
    };
    ui.notice("Deleted. Deleting a card file does not erase it from flash storage, snapshots, backups, cloud history or thumbnail caches; destroy a drive that held it, or replace the card set.");
    Ok(DiscardOutcome {
        deleted: true,
        forgotten,
    })
}
