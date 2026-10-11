//! Bound mode in the vault operations (spec 5.1, 5.2, 6.1, 9.1 to 9.3, 9.6;
//! approved for Milestone 5, D1 to D12).
//!
//! The TPM itself is behind [`crate::tpm::Tpm`]; this module holds what the
//! vault code does with it: the bound keys, the bound duress tag, the
//! unlock path (S1 from the header, S2 from the TPM after the 9.2a checks),
//! the 9.2b removal of an index, the owner-authorization prompt and the
//! bound recovery rehearsal (S1 + S3).

use subtle::ConstantTimeEq;

use super::{Bundle, Prompter};
use crate::card::{self, Card, CardMode};
use crate::crypto::{kdf, mac, wrap};
use crate::errors::Error;
use crate::header::{Header, SlotFields};
use crate::keytable;
use crate::platform::fs::Dir;
use crate::resources::SystemMemory;
use crate::secrets::{SecretBuf, SecretBytes};
use crate::shamir::{self, Share};
use crate::store::keytable_name;
use crate::tpm::{self, Tpm, TpmOptions, TpmState};
use crate::tpmid::IndexContext;

/// `k_s1wrap`, `k_s2wrap` and `tpm_auth` (5.1).
pub(crate) struct BoundKeys {
    pub(crate) s1: SecretBytes<32>,
    pub(crate) s2: SecretBytes<32>,
    pub(crate) auth: SecretBytes<32>,
}

impl BoundKeys {
    pub(crate) fn derive(master: &SecretBytes<32>) -> Result<Self, Error> {
        Ok(Self {
            s1: kdf::passphrase_subkey(master, kdf::PassphraseKey::S1Wrap)?,
            s2: kdf::passphrase_subkey(master, kdf::PassphraseKey::S2Wrap)?,
            auth: kdf::passphrase_subkey(master, kdf::PassphraseKey::TpmAuth)?,
        })
    }
}

/// Connects to the TPM, refusing bound mode where it is not supported
/// (D10).
pub(crate) fn connect(opts: &TpmOptions) -> Result<Box<dyn Tpm>, Error> {
    if !tpm::supported() {
        return Err(Error::BoundVault);
    }
    tpm::open(&opts.target)
}

/// Refuses before anything is written when owner authorization will be
/// needed but cannot be requested (D9).
pub(crate) fn owner_auth_possible(
    opts: &TpmOptions,
    state: &TpmState,
    ui: &dyn Prompter,
) -> Result<(), Error> {
    if state.owner_auth_set() && !opts.owner_auth_declared && !ui.interactive() {
        return Err(Error::TpmOwnerAuthRequired);
    }
    Ok(())
}

/// The owner authorization (D9): a hidden prompt, or the next
/// `--secrets-stdin` line when `--tpm-owner-auth` declares it. Never
/// stored, printed or put in arguments or the environment.
pub(crate) fn owner_auth(
    opts: &TpmOptions,
    state: &TpmState,
    ui: &mut dyn Prompter,
) -> Result<Option<SecretBuf>, Error> {
    if opts.owner_auth_declared || (state.owner_auth_set() && ui.interactive()) {
        let line = ui.secret("TPM owner authorization: ")?;
        return Ok(Some(SecretBuf::take_from(&mut line.as_bytes().to_vec())));
    }
    if state.owner_auth_set() {
        return Err(Error::TpmOwnerAuthRequired);
    }
    Ok(None)
}

/// The bound duress tag (9.6, with the approved EK digest).
pub(crate) fn duress_tag(
    duress_key: &SecretBytes<32>,
    vault_id: &[u8; 16],
    index: &IndexContext,
    ek_digest: &[u8; 32],
) -> [u8; 64] {
    mac::hmac_sha512(
        duress_key.expose_secret(),
        &[
            b"pvault/v1/duress-tag",
            vault_id,
            b"bound",
            &index.tpm_index.to_be_bytes(),
            &index.name_postwrite,
            &index.policy_nonce,
            ek_digest,
        ],
    )
}

/// 5.2 steps 4 to 8: S1 from the header, the 9.2a checks, S2 from the TPM,
/// combine, then both MACs. Every secret-dependent failure is
/// [`Error::HeaderInvalid`] (`Unlock failed.`).
pub(crate) fn open_bundle(
    header: &Header,
    master: &SecretBytes<32>,
    tpm: &mut dyn Tpm,
) -> Result<Bundle, Error> {
    let SlotFields::Bound(b) = header.slots() else {
        return Err(Error::HeaderInvalid);
    };
    let keys = BoundKeys::derive(master)?;
    let s1 = Share::new(1, wrap::unwrap::<96>(&keys.s1, &b.s1_nonce, &b.s1_ct))?;
    // 9.2a: the provisional fields must name an index of exactly pvault's
    // format with the stored post-write Name; otherwise no NV_Read (the DA
    // counter is not touched).
    let idx = &b.index;
    let public = tpm
        .read_public(idx.tpm_index)?
        .ok_or(Error::HeaderInvalid)?;
    if !public.matches(idx.tpm_index, &idx.policy_nonce, true)
        || !bool::from(public.name.as_slice().ct_eq(&idx.name_postwrite))
    {
        return Err(Error::HeaderInvalid);
    }
    let data = tpm.read(idx.tpm_index, &keys.auth)?;
    let d = data.expose_secret();
    if d[0] != 2 {
        return Err(Error::HeaderInvalid);
    }
    let mut ct = [0u8; 96];
    ct.copy_from_slice(&d[1..]);
    let s2 = Share::new(2, wrap::unwrap::<96>(&keys.s2, &b.s2_nonce, &ct))?;
    let secret = shamir::combine(&s1, &s2)?;
    let bundle = Bundle::from_bytes(&secret)?;
    if !header.verify_core(&bundle.k_mac) || !header.verify_slots(&bundle.k_mac) {
        return Err(Error::HeaderInvalid);
    }
    Ok(bundle)
}

/// The 97 index bytes `x = 2 || S2_wrapped`.
pub(crate) fn index_data(
    s2: &Share,
    k_s2wrap: &SecretBytes<32>,
) -> Result<([u8; 24], SecretBytes<97>), Error> {
    let (nonce, ct) = wrap::wrap::<96>(k_s2wrap, s2.y())?;
    let mut d = [0u8; 97];
    d[0] = 2;
    d[1..].copy_from_slice(&ct);
    Ok((nonce, SecretBytes::take_from(&mut d)?))
}

/// What a 9.2b resolution found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// The index was ours and is gone.
    Removed,
    /// Nothing is defined at the handle.
    Absent,
    /// Something else is defined there; it was left alone.
    Foreign,
}

/// 9.2b: removes the index described by an **authenticated** `index`
/// context only if this is the TPM that created it (`expected_ek`, from an
/// authenticated token, equals the live measurement) and the handle holds
/// exactly pvault's public area with one of the expected Names.
pub(crate) fn remove_owned(
    tpm: &mut dyn Tpm,
    index: &IndexContext,
    expected_ek: &SecretBytes<32>,
    owner: Option<&SecretBuf>,
) -> Result<Resolution, Error> {
    let live = tpm
        .ek_digest()
        .map_err(|_| Error::TpmIndexElsewhere(index.tpm_index))?;
    if !bool::from(live.ct_eq(expected_ek.expose_secret())) {
        return Err(Error::TpmIndexElsewhere(index.tpm_index));
    }
    let Some(public) = tpm.read_public(index.tpm_index)? else {
        return Ok(Resolution::Absent);
    };
    let post = public.matches(index.tpm_index, &index.policy_nonce, true)
        && public.name == index.name_postwrite;
    let pre = index.name_prewrite.is_some_and(|n| {
        public.matches(index.tpm_index, &index.policy_nonce, false) && public.name == n
    });
    if !(post || pre) {
        return Ok(Resolution::Foreign);
    }
    tpm.undefine(index.tpm_index, owner)?;
    Ok(Resolution::Removed)
}

/// The bound recovery rehearsal (SI-52 6.4, spec 6.1): S1 from the
/// candidate slots with `k_s1wrap`, S3 from the delivered card, combined to
/// the bundle that must verify the candidate header and key table. S2 is
/// not used.
pub(crate) fn rehearse(
    t: &Dir,
    k_s1wrap: &SecretBytes<32>,
    delivered: &SecretBytes<{ card::PAYLOAD_LEN }>,
    candidate: &[u8],
) -> Result<(), Error> {
    let header = Header::parse(candidate)?;
    let core = header.core();
    let SlotFields::Bound(b) = header.slots() else {
        return Err(Error::RehearsalFailed);
    };
    let card = Card::parse(SecretBytes::take_from(
        &mut delivered.expose_secret().to_vec(),
    )?)
    .map_err(Error::Card)?;
    card.check_for_vault(&core.vault_id, &core.card_set_id, CardMode::Bound)
        .map_err(Error::Card)?;
    let s1 = Share::new(1, wrap::unwrap::<96>(k_s1wrap, &b.s1_nonce, &b.s1_ct))?;
    let secret = shamir::combine(&s1, &card.share()?)?;
    let recovered = Bundle::from_bytes(&secret)?;
    drop(secret);
    if !header.verify_core(&recovered.k_mac) || !header.verify_slots(&recovered.k_mac) {
        return Err(Error::RehearsalFailed);
    }
    let table = t
        .open_regular(keytable_name(core.keytable_gen), false)
        .map_err(Error::Io)?
        .ok_or(Error::RehearsalFailed)?;
    keytable::read_file(
        table,
        &core.vault_id,
        core.keytable_gen,
        &core.keytable_digest,
        &recovered.keytable_keys()?,
        &SystemMemory,
    )
    .map_err(|_| Error::RehearsalFailed)?;
    Ok(())
}
