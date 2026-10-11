//! `duress set` and `duress disable` (spec 6.10; approved for Milestone 5,
//! D5 to D7; `docs/CLI.md` 6.9).
//!
//! Both are ordinary-unlock commits through the `update` journal: a new
//! key-table generation (same entries) and a header whose slots gain or lose
//! the duress tag. A configured duress passphrase is **inactive** until the
//! Milestone 9 trigger exists (D6): a match is `Unlock failed.` and changes
//! nothing.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{Prompter, Session, bound, duress_tag, edit};
use crate::crypto::kdf::{self, PassphraseKey};
use crate::errors::Error;
use crate::header::{CoreFields, PassphraseKind, SlotFields};
use crate::passphrase::{self, WordCount};
use crate::records::Settings;
use crate::secrets::SecretBuf;

/// Duress passphrases are generated, 12 words (SI-51).
const DURESS_WORDS: u8 = 12;

/// The N3 notice (D7), shown only when the main passphrase is custom and
/// generated-word handling refuses it.
pub const N3_NOTICE: &str = "Your custom passphrase is one that generated-word handling refuses. With a duress passphrase set, unlocking with it takes about one Argon2id run less than other inputs, so someone timing unlock attempts can tell. Choosing a passphrase that generated-word handling accepts avoids this.";

/// Why bound duress is unavailable on the session's TPM, or the EK digest
/// the bound tag needs.
fn bound_ek(s: &Session) -> Result<[u8; 32], Error> {
    let mut tpm = bound::connect(&s.tpm)?;
    let state = tpm.state()?;
    let ek = tpm.ek_digest();
    let why = state.duress_unavailable(ek.is_ok());
    if !why.is_empty() {
        return Err(Error::DuressUnavailable(why.join(", ")));
    }
    ek
}

/// A fresh 12-word duress passphrase, shown once on the terminal and typed
/// back; returns its handled words. `is_main` says whether raw words would
/// be the main passphrase (they must differ, 6.10); such words are replaced.
pub(crate) fn new_duress_words(
    ui: &mut dyn Prompter,
    is_main: &mut dyn FnMut(&[u8]) -> Result<bool, Error>,
) -> Result<SecretBuf, Error> {
    let count = WordCount::new(DURESS_WORDS).map_err(Error::Passphrase)?;
    loop {
        let words = passphrase::generate(count)?;
        if is_main(words.expose_secret())? {
            continue;
        }
        let handled = super::handle(PassphraseKind::Words, words.expose_secret())?;
        let text = std::str::from_utf8(words.expose_secret())
            .map_err(|_| Error::Unsupported("word list"))?;
        let shown = Zeroizing::new(format!(
            "Your duress passphrase:\n\n    {text}\n\nWrite it down and keep it apart from your passphrase. Press Enter when done."
        ));
        ui.show_secret(&shown)?;
        drop(shown);
        let attempts = if ui.interactive() { 3 } else { 1 };
        for attempt in 1..=attempts {
            let raw = ui.secret("Type the duress passphrase from memory: ")?;
            let ok = super::handle(PassphraseKind::Words, raw.as_bytes())
                .is_ok_and(|h| bool::from(h.expose_secret().ct_eq(handled.expose_secret())));
            if ok {
                return Ok(handled);
            }
            ui.notice(&Error::PassphraseMismatch.to_string());
            if attempt == attempts {
                break;
            }
        }
        return Err(Error::PassphraseMismatch);
    }
}

/// `slots` with the duress tag of the handled duress `words` (9.6): the
/// duress key comes from `H_w(words)` under the core's salt and Argon2
/// parameters, as an unlock derives it. Bound tags bind the EK digest.
pub(crate) fn slots_with_tag(
    core: &CoreFields,
    slots: &SlotFields,
    words: &SecretBuf,
    ek: Option<&[u8; 32]>,
) -> Result<SlotFields, Error> {
    let master = kdf::master_pw(words, &core.salt, core.argon2)?;
    let key = kdf::passphrase_subkey(&master, PassphraseKey::Duress)?;
    drop(master);
    let mut slots = slots.clone();
    match &mut slots {
        SlotFields::Portable(p) => p.duress_tag = Some(duress_tag(&key, &core.vault_id)),
        SlotFields::Bound(b) => {
            let ek = ek.ok_or(Error::DuressUnavailable(
                "the TPM identity cannot be measured".into(),
            ))?;
            b.duress_tag = Some(bound::duress_tag(&key, &core.vault_id, &b.index, ek));
        }
    }
    Ok(slots)
}

fn has_tag(slots: &SlotFields) -> bool {
    match slots {
        SlotFields::Portable(p) => p.duress_tag.is_some(),
        SlotFields::Bound(b) => b.duress_tag.is_some(),
    }
}

/// `pvault duress set <vault>`.
pub fn set(
    s: &mut Session,
    settings: Option<&Settings>,
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    if has_tag(s.header.slots()) {
        return Err(Error::DuressConfigured);
    }
    if !ui.has_terminal() {
        return Err(Error::NeedsTerminal(
            "The duress passphrase is shown only on a terminal.",
        ));
    }
    let ek = match s.header.slots() {
        SlotFields::Bound(_) => Some(bound_ek(s)?),
        SlotFields::Portable(_) => None,
    };
    if s.main_words_refused {
        ui.notice(N3_NOTICE);
    }
    let (kind, salt, argon2) = {
        let c = s.header.core();
        (c.passphrase_kind, c.salt, c.argon2)
    };
    let main_check = super::copy32(&s.main_check)?;
    let mut is_main = |raw: &[u8]| -> Result<bool, Error> {
        let Ok(as_main) = super::handle(kind, raw) else {
            return Ok(false);
        };
        let m = kdf::master_pw(&as_main, &salt, argon2)?;
        let check = kdf::hkdf_key(&m, b"pvault/v1/duress-differs")?;
        Ok(bool::from(
            check.expose_secret().ct_eq(main_check.expose_secret()),
        ))
    };
    let words = new_duress_words(ui, &mut is_main)?;
    let slots = slots_with_tag(s.header.core(), s.header.slots(), &words, ek.as_ref())?;
    drop(words);
    edit::transact(s, None, None, settings, Some(slots))?;
    ui.notice("Duress passphrase set. It is inactive in this version: entering it fails like a wrong passphrase and changes nothing.");
    Ok(())
}

/// `pvault duress disable <vault>`.
pub fn disable(
    s: &mut Session,
    settings: Option<&Settings>,
    ui: &mut dyn Prompter,
) -> Result<(), Error> {
    if !has_tag(s.header.slots()) {
        ui.notice("Duress is not configured; nothing was changed.");
        return Ok(());
    }
    let phrase = "DISABLE DURESS";
    if !ui.confirm(
        &format!("Type {phrase} to remove the duress passphrase: "),
        phrase,
    )? {
        return Err(Error::NotConfirmed("Not confirmed. Nothing was changed."));
    }
    let mut slots = s.header.slots().clone();
    match &mut slots {
        SlotFields::Portable(p) => p.duress_tag = None,
        SlotFields::Bound(b) => b.duress_tag = None,
    }
    edit::transact(s, None, None, settings, Some(slots))?;
    ui.notice("Duress disabled.");
    Ok(())
}
