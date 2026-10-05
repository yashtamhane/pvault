//! The vault header, `vault.hdr` (spec 4.1 to 4.4; D1, D6).
//!
//! ```text
//! Header      = { "core": CoreFields, "slots": SlotFields,
//!                 "core_mac": bytes(64), "slots_mac": bytes(64) }
//! core_digest = SHA-512("pvault/v1/core" || canonical_cbor(CoreFields))
//! core_mac    = HMAC-SHA-512(K_mac, "pvault/v1/core-mac" || canonical_cbor(CoreFields))
//! slots_mac   = HMAC-SHA-512(K_mac, "pvault/v1/slots-mac" || core_digest
//!                            || canonical_cbor(SlotFields))
//! ```
//!
//! Parsing enforces the 4.4 profile, the 64 KiB cap, every fixed or capped
//! field length, the Argon2 hard caps, `keytable_gen == generation`, the
//! owner-range handles and SHA-256 Names, and the sorted, duplicate-free,
//! at most 32-entry `tpm_cleanup`. Any violation is [`Error::HeaderInvalid`],
//! which the user sees as `Unlock failed.` (5.8). A parsed header is still
//! unauthenticated until [`Header::verify_core`] and [`Header::verify_slots`]
//! succeed.

use subtle::ConstantTimeEq;

use crate::cbor::{CborError, Decoder, Encoder, Sink};
use crate::crypto::kdf::Argon2Params;
use crate::crypto::mac;
use crate::errors::Error;
use crate::secrets::SecretBytes;
use crate::tpmid::{
    IndexContext, NAME_LEN, TEMPLATE_H2_P256, TOKEN_CT_LEN, TOKEN_NONCE_LEN, Token,
};

/// Largest header file (4.3).
pub const MAX_HEADER_LEN: usize = 64 * 1024;
/// Most `tpm_cleanup` entries (D6).
pub const MAX_CLEANUP: usize = 32;
/// Header format version.
pub const VERSION: u64 = 1;

/// Vault mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// TPM-bound.
    Bound,
    /// Portable.
    Portable,
}

impl Mode {
    /// The encoded text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Portable => "portable",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self, CborError> {
        match s {
            "bound" => Ok(Self::Bound),
            "portable" => Ok(Self::Portable),
            _ => Err(CborError),
        }
    }
}

/// Main passphrase kind (D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKind {
    /// Generated words, handled by `H_w_v1`.
    Words,
    /// Custom text, handled by H_c.
    Custom,
}

impl PassphraseKind {
    /// The encoded text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Words => "words",
            Self::Custom => "custom",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self, CborError> {
        match s {
            "words" => Ok(Self::Words),
            "custom" => Ok(Self::Custom),
            _ => Err(CborError),
        }
    }
}

/// `(tpm_index, name_postwrite, policy_nonce, template, nonce, ct)`.
type SortKey<'a> = ([u8; 4], &'a [u8], &'a [u8], u8, &'a [u8], &'a [u8]);

/// A tracked TPM index awaiting cleanup on its original TPM (D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmCleanupEntry {
    /// The index context; `name_prewrite` is optional.
    pub index: IndexContext,
    /// Scope-5 identity token under the current `K_mac`.
    pub token: Token,
}

impl TpmCleanupEntry {
    /// Sort key: `(tpm_index, name_postwrite, policy_nonce, template, nonce, ct)`.
    fn sort_key(&self) -> SortKey<'_> {
        (
            self.index.tpm_index.to_be_bytes(),
            &self.index.name_postwrite,
            &self.index.policy_nonce,
            self.token.template,
            &self.token.nonce,
            &self.token.ct,
        )
    }
}

/// The authenticated core (4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreFields {
    /// Fixed for the vault's lifetime.
    pub vault_id: [u8; 16],
    /// Bound or portable.
    pub mode: Mode,
    /// Argon2id parameters, within the hard caps.
    pub argon2: Argon2Params,
    /// Argon2id salt.
    pub salt: [u8; 32],
    /// Transaction counter.
    pub generation: u64,
    /// Creation time, unix seconds.
    pub created_at: u64,
    /// Generation of the current key table; equals `generation`.
    pub keytable_gen: u64,
    /// SHA-512 of the current key-table file.
    pub keytable_digest: [u8; 64],
    /// Current recovery card set.
    pub card_set_id: [u8; 8],
    /// Written once by `init`.
    pub setup_id: [u8; 16],
    /// Main passphrase kind (D1).
    pub passphrase_kind: PassphraseKind,
    /// Tracked TPM indices, sorted, at most 32 (D6).
    pub tpm_cleanup: Vec<TpmCleanupEntry>,
}

/// Bound slots (4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSlots {
    /// S1 wrap nonce.
    pub s1_nonce: [u8; 24],
    /// Wrapped S1 (x = 1).
    pub s1_ct: [u8; 96],
    /// S2 wrap nonce (S2 itself lives in the TPM, x = 2).
    pub s2_nonce: [u8; 24],
    /// The live NV index and its post-write Name.
    pub index: IndexContext,
    /// Scope-1 identity token under `K_mac`.
    pub tpm_id: Token,
    /// Optional duress tag.
    pub duress_tag: Option<[u8; 64]>,
}

/// Portable slots (4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableSlots {
    /// Slot wrap nonce.
    pub slot_nonce: [u8; 24],
    /// The bundle, wrapped.
    pub slot_ct: [u8; 96],
    /// Optional duress tag.
    pub duress_tag: Option<[u8; 64]>,
}

/// Slots of either mode.
// One short-lived value per header; boxing would add an allocation for nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotFields {
    /// Bound mode.
    Bound(BoundSlots),
    /// Portable mode.
    Portable(PortableSlots),
}

// Canonical key orders (4.4; docs/M3_READINESS.md appendix A).
const HEADER_KEYS: &[&str] = &["core", "slots", "core_mac", "slots_mac"];
const CORE_KEYS: &[&str] = &[
    "mode",
    "salt",
    "magic",
    "version",
    "argon2_m",
    "argon2_p",
    "argon2_t",
    "setup_id",
    "vault_id",
    "created_at",
    "generation",
    "card_set_id",
    "tpm_cleanup",
    "keytable_gen",
    "keytable_digest",
    "passphrase_kind",
];
const BOUND_KEYS: &[&str] = &[
    "s1_x",
    "s2_x",
    "s1_ct",
    "s1_nonce",
    "s2_nonce",
    "tpm_id_ct",
    "duress_tag",
    "tpm_nv_name",
    "tpm_id_nonce",
    "tpm_nv_index",
    "tpm_id_template",
    "tpm_policy_nonce",
];
const PORTABLE_KEYS: &[&str] = &["slot_ct", "duress_tag", "slot_nonce"];
const CLEANUP_KEYS: &[&str] = &[
    "tpm_id_ct",
    "tpm_index",
    "policy_nonce",
    "tpm_id_nonce",
    "name_prewrite",
    "name_postwrite",
    "tpm_id_template",
];

const fn all(n: usize) -> u64 {
    (1u64 << n) - 1
}

impl CoreFields {
    /// Encodes the core canonically.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        self.write(&mut e).map_err(|_| Error::HeaderInvalid)?;
        Ok(e.into_sink())
    }

    fn write<S: Sink>(&self, e: &mut Encoder<S>) -> Result<(), CborError> {
        e.map(CORE_KEYS.len())?;
        e.key("mode")?;
        e.text(self.mode.as_str())?;
        e.key("salt")?;
        e.bytes(&self.salt)?;
        e.key("magic")?;
        e.text("PVLT")?;
        e.key("version")?;
        e.uint(VERSION)?;
        e.key("argon2_m")?;
        e.uint(self.argon2.m_kib.into())?;
        e.key("argon2_p")?;
        e.uint(self.argon2.p.into())?;
        e.key("argon2_t")?;
        e.uint(self.argon2.t.into())?;
        e.key("setup_id")?;
        e.bytes(&self.setup_id)?;
        e.key("vault_id")?;
        e.bytes(&self.vault_id)?;
        e.key("created_at")?;
        e.uint(self.created_at)?;
        e.key("generation")?;
        e.uint(self.generation)?;
        e.key("card_set_id")?;
        e.bytes(&self.card_set_id)?;
        e.key("tpm_cleanup")?;
        e.array(self.tpm_cleanup.len())?;
        for entry in &self.tpm_cleanup {
            write_cleanup(e, entry)?;
        }
        e.key("keytable_gen")?;
        e.uint(self.keytable_gen)?;
        e.key("keytable_digest")?;
        e.bytes(&self.keytable_digest)?;
        e.key("passphrase_kind")?;
        e.text(self.passphrase_kind.as_str())
    }

    /// `SHA-512("pvault/v1/core" || canonical_cbor(CoreFields))`.
    pub fn digest(&self) -> Result<[u8; 64], Error> {
        Ok(core_digest_of(&self.encode()?))
    }

    fn validate(&self) -> Result<(), CborError> {
        self.argon2.check_hard_caps().map_err(|_| CborError)?;
        if self.keytable_gen != self.generation || self.tpm_cleanup.len() > MAX_CLEANUP {
            return Err(CborError);
        }
        for w in self.tpm_cleanup.windows(2) {
            // Strictly ascending: sorted, and exact duplicates rejected.
            if w[0].sort_key() >= w[1].sort_key() {
                return Err(CborError);
            }
        }
        if self.tpm_cleanup.iter().any(|e| !e.index.is_valid()) {
            return Err(CborError);
        }
        Ok(())
    }

    /// Inserts a cleanup entry in sorted position. Refuses at capacity and
    /// never evicts (D6).
    pub fn add_cleanup(&mut self, entry: TpmCleanupEntry) -> Result<(), Error> {
        if self.tpm_cleanup.len() >= MAX_CLEANUP {
            return Err(Error::Capacity(
                "TPM cleanup capacity is full; resolve a recorded index on its original TPM.",
            ));
        }
        let at = self
            .tpm_cleanup
            .partition_point(|e| e.sort_key() < entry.sort_key());
        if self
            .tpm_cleanup
            .get(at)
            .is_some_and(|e| e.sort_key() == entry.sort_key())
        {
            return Err(Error::HeaderInvalid);
        }
        self.tpm_cleanup.insert(at, entry);
        Ok(())
    }
}

fn write_cleanup<S: Sink>(e: &mut Encoder<S>, c: &TpmCleanupEntry) -> Result<(), CborError> {
    let n = if c.index.name_prewrite.is_some() {
        7
    } else {
        6
    };
    e.map(n)?;
    e.key("tpm_id_ct")?;
    e.bytes(&c.token.ct)?;
    e.key("tpm_index")?;
    e.uint(c.index.tpm_index.into())?;
    e.key("policy_nonce")?;
    e.bytes(&c.index.policy_nonce)?;
    e.key("tpm_id_nonce")?;
    e.bytes(&c.token.nonce)?;
    if let Some(pre) = &c.index.name_prewrite {
        e.key("name_prewrite")?;
        e.bytes(pre)?;
    }
    e.key("name_postwrite")?;
    e.bytes(&c.index.name_postwrite)?;
    e.key("tpm_id_template")?;
    e.uint(c.token.template.into())
}

impl SlotFields {
    /// Encodes the slots canonically.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut e = Encoder::new(Vec::new());
        self.write(&mut e).map_err(|_| Error::HeaderInvalid)?;
        Ok(e.into_sink())
    }

    fn write<S: Sink>(&self, e: &mut Encoder<S>) -> Result<(), CborError> {
        match self {
            Self::Bound(b) => {
                e.map(if b.duress_tag.is_some() { 12 } else { 11 })?;
                e.key("s1_x")?;
                e.uint(1)?;
                e.key("s2_x")?;
                e.uint(2)?;
                e.key("s1_ct")?;
                e.bytes(&b.s1_ct)?;
                e.key("s1_nonce")?;
                e.bytes(&b.s1_nonce)?;
                e.key("s2_nonce")?;
                e.bytes(&b.s2_nonce)?;
                e.key("tpm_id_ct")?;
                e.bytes(&b.tpm_id.ct)?;
                if let Some(tag) = &b.duress_tag {
                    e.key("duress_tag")?;
                    e.bytes(tag)?;
                }
                e.key("tpm_nv_name")?;
                e.bytes(&b.index.name_postwrite)?;
                e.key("tpm_id_nonce")?;
                e.bytes(&b.tpm_id.nonce)?;
                e.key("tpm_nv_index")?;
                e.uint(b.index.tpm_index.into())?;
                e.key("tpm_id_template")?;
                e.uint(b.tpm_id.template.into())?;
                e.key("tpm_policy_nonce")?;
                e.bytes(&b.index.policy_nonce)
            }
            Self::Portable(p) => {
                e.map(if p.duress_tag.is_some() { 3 } else { 2 })?;
                e.key("slot_ct")?;
                e.bytes(&p.slot_ct)?;
                if let Some(tag) = &p.duress_tag {
                    e.key("duress_tag")?;
                    e.bytes(tag)?;
                }
                e.key("slot_nonce")?;
                e.bytes(&p.slot_nonce)
            }
        }
    }

    fn mode(&self) -> Mode {
        match self {
            Self::Bound(_) => Mode::Bound,
            Self::Portable(_) => Mode::Portable,
        }
    }
}

/// `SHA-512("pvault/v1/core" || core_bytes)`.
pub fn core_digest_of(core_bytes: &[u8]) -> [u8; 64] {
    mac::sha512(&[b"pvault/v1/core", core_bytes])
}

fn core_mac_of(k_mac: &SecretBytes<32>, core_bytes: &[u8]) -> [u8; 64] {
    mac::hmac_sha512(k_mac.expose_secret(), &[b"pvault/v1/core-mac", core_bytes])
}

fn slots_mac_of(k_mac: &SecretBytes<32>, core_digest: &[u8; 64], slots_bytes: &[u8]) -> [u8; 64] {
    mac::hmac_sha512(
        k_mac.expose_secret(),
        &[b"pvault/v1/slots-mac", core_digest, slots_bytes],
    )
}

/// A parsed header. Its fields are **unauthenticated** until the MACs verify.
#[derive(Debug, Clone)]
pub struct Header {
    raw: Vec<u8>,
    core_range: core::ops::Range<usize>,
    slots_range: core::ops::Range<usize>,
    core: CoreFields,
    slots: SlotFields,
    core_mac: [u8; 64],
    slots_mac: [u8; 64],
}

impl Header {
    /// Encodes and MACs a complete header.
    pub fn build(
        core: &CoreFields,
        slots: &SlotFields,
        k_mac: &SecretBytes<32>,
    ) -> Result<Vec<u8>, Error> {
        if slots.mode() != core.mode {
            return Err(Error::HeaderInvalid);
        }
        core.validate().map_err(|_| Error::HeaderInvalid)?;
        let core_bytes = core.encode()?;
        let slots_bytes = slots.encode()?;
        let digest = core_digest_of(&core_bytes);
        let mut e = Encoder::new(Vec::new());
        (|| -> Result<(), CborError> {
            e.map(4)?;
            e.key("core")?;
            e.raw(&core_bytes)?;
            e.key("slots")?;
            e.raw(&slots_bytes)?;
            e.key("core_mac")?;
            e.bytes(&core_mac_of(k_mac, &core_bytes))?;
            e.key("slots_mac")?;
            e.bytes(&slots_mac_of(k_mac, &digest, &slots_bytes))
        })()
        .map_err(|_| Error::HeaderInvalid)?;
        let out = e.into_sink();
        if out.len() > MAX_HEADER_LEN {
            return Err(Error::HeaderInvalid);
        }
        Ok(out)
    }

    /// Parses a header strictly (4.3, 4.4). The caller enforces
    /// [`MAX_HEADER_LEN`] before reading the file; it is checked again here.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::HeaderInvalid);
        }
        Self::parse_inner(bytes).map_err(|_| Error::HeaderInvalid)
    }

    fn parse_inner(bytes: &[u8]) -> Result<Self, CborError> {
        let mut d = Decoder::new(bytes);
        let mut core = None;
        let mut slots = None;
        let mut core_range = 0..0;
        let mut slots_range = 0..0;
        let mut core_mac = [0u8; 64];
        let mut slots_mac = [0u8; 64];
        d.map(HEADER_KEYS, all(4), |d, k| {
            match k {
                0 => {
                    let start = d.position();
                    core = Some(parse_core(d)?);
                    core_range = start..d.position();
                }
                1 => {
                    let mode = core.as_ref().ok_or(CborError)?.mode;
                    let start = d.position();
                    slots = Some(parse_slots(d, mode)?);
                    slots_range = start..d.position();
                }
                2 => core_mac = *d.bytes_exact::<64>()?,
                _ => slots_mac = *d.bytes_exact::<64>()?,
            }
            Ok(())
        })?;
        d.finish()?;
        let core = core.ok_or(CborError)?;
        core.validate()?;
        Ok(Self {
            raw: bytes.to_vec(),
            core_range,
            slots_range,
            core,
            slots: slots.ok_or(CborError)?,
            core_mac,
            slots_mac,
        })
    }

    /// The core (unauthenticated until [`Self::verify_core`]).
    pub fn core(&self) -> &CoreFields {
        &self.core
    }

    /// The slots (unauthenticated until [`Self::verify_slots`]).
    pub fn slots(&self) -> &SlotFields {
        &self.slots
    }

    /// The exact stored core bytes.
    pub fn core_bytes(&self) -> &[u8] {
        &self.raw[self.core_range.clone()]
    }

    /// The exact stored slots bytes.
    pub fn slots_bytes(&self) -> &[u8] {
        &self.raw[self.slots_range.clone()]
    }

    /// The stored header bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The core digest of the stored core bytes.
    pub fn core_digest(&self) -> [u8; 64] {
        core_digest_of(self.core_bytes())
    }

    /// Verifies `core_mac` in constant time.
    pub fn verify_core(&self, k_mac: &SecretBytes<32>) -> bool {
        mac::verify_hmac_sha512(
            k_mac.expose_secret(),
            &[b"pvault/v1/core-mac", self.core_bytes()],
            &self.core_mac,
        )
    }

    /// Verifies `slots_mac` in constant time.
    pub fn verify_slots(&self, k_mac: &SecretBytes<32>) -> bool {
        mac::verify_hmac_sha512(
            k_mac.expose_secret(),
            &[
                b"pvault/v1/slots-mac",
                &self.core_digest(),
                self.slots_bytes(),
            ],
            &self.slots_mac,
        )
    }

    /// Whether the stored core hashes to `expected` (constant time).
    pub fn core_digest_is(&self, expected: &[u8; 64]) -> bool {
        bool::from(self.core_digest().ct_eq(expected))
    }
}

fn parse_core(d: &mut Decoder<'_>) -> Result<CoreFields, CborError> {
    let mut mode = None;
    let mut salt = [0u8; 32];
    let mut magic_ok = false;
    let mut version_ok = false;
    let mut m = 0u32;
    let mut p = 0u32;
    let mut t = 0u32;
    let mut setup_id = [0u8; 16];
    let mut vault_id = [0u8; 16];
    let mut created_at = 0;
    let mut generation = 0;
    let mut card_set_id = [0u8; 8];
    let mut tpm_cleanup = Vec::new();
    let mut keytable_gen = 0;
    let mut keytable_digest = [0u8; 64];
    let mut kind = None;
    d.map(CORE_KEYS, all(CORE_KEYS.len()), |d, k| {
        match k {
            0 => mode = Some(Mode::parse(d.text()?)?),
            1 => salt = *d.bytes_exact()?,
            2 => magic_ok = d.text()? == "PVLT",
            3 => version_ok = d.uint()? == VERSION,
            4 => m = d.u32()?,
            5 => p = d.u32()?,
            6 => t = d.u32()?,
            7 => setup_id = *d.bytes_exact()?,
            8 => vault_id = *d.bytes_exact()?,
            9 => created_at = d.uint()?,
            10 => generation = d.uint()?,
            11 => card_set_id = *d.bytes_exact()?,
            12 => {
                d.array(MAX_CLEANUP, |d, _| {
                    tpm_cleanup.push(parse_cleanup(d)?);
                    Ok(())
                })?;
            }
            13 => keytable_gen = d.uint()?,
            14 => keytable_digest = *d.bytes_exact()?,
            _ => kind = Some(PassphraseKind::parse(d.text()?)?),
        }
        Ok(())
    })?;
    if !magic_ok || !version_ok {
        return Err(CborError);
    }
    Ok(CoreFields {
        vault_id,
        mode: mode.ok_or(CborError)?,
        argon2: Argon2Params { m_kib: m, t, p },
        salt,
        generation,
        created_at,
        keytable_gen,
        keytable_digest,
        card_set_id,
        setup_id,
        passphrase_kind: kind.ok_or(CborError)?,
        tpm_cleanup,
    })
}

fn parse_cleanup(d: &mut Decoder<'_>) -> Result<TpmCleanupEntry, CborError> {
    let mut ct = [0u8; TOKEN_CT_LEN];
    let mut tpm_index = 0;
    let mut policy_nonce = [0u8; 32];
    let mut nonce = [0u8; TOKEN_NONCE_LEN];
    let mut pre = None;
    let mut post = [0u8; NAME_LEN];
    let mut template = 0;
    // Every key except `name_prewrite` (index 4) is required.
    d.map(CLEANUP_KEYS, all(7) & !(1 << 4), |d, k| {
        match k {
            0 => ct = *d.bytes_exact()?,
            1 => tpm_index = d.u32()?,
            2 => policy_nonce = *d.bytes_exact()?,
            3 => nonce = *d.bytes_exact()?,
            4 => pre = Some(*d.bytes_exact()?),
            5 => post = *d.bytes_exact()?,
            _ => template = d.u8()?,
        }
        Ok(())
    })?;
    if template != TEMPLATE_H2_P256 {
        return Err(CborError);
    }
    Ok(TpmCleanupEntry {
        index: IndexContext {
            tpm_index,
            name_prewrite: pre,
            name_postwrite: post,
            policy_nonce,
        },
        token: Token {
            template,
            nonce,
            ct,
        },
    })
}

fn parse_slots(d: &mut Decoder<'_>, mode: Mode) -> Result<SlotFields, CborError> {
    match mode {
        Mode::Bound => {
            let mut s1_ct = [0u8; 96];
            let mut s1_nonce = [0u8; 24];
            let mut s2_nonce = [0u8; 24];
            let mut ct = [0u8; TOKEN_CT_LEN];
            let mut duress_tag = None;
            let mut name = [0u8; NAME_LEN];
            let mut nonce = [0u8; TOKEN_NONCE_LEN];
            let mut index = 0;
            let mut template = 0;
            let mut policy_nonce = [0u8; 32];
            let mut xs_ok = true;
            // `duress_tag` (index 6) is optional.
            d.map(BOUND_KEYS, all(12) & !(1 << 6), |d, k| {
                match k {
                    0 => xs_ok &= d.u8()? == 1,
                    1 => xs_ok &= d.u8()? == 2,
                    2 => s1_ct = *d.bytes_exact()?,
                    3 => s1_nonce = *d.bytes_exact()?,
                    4 => s2_nonce = *d.bytes_exact()?,
                    5 => ct = *d.bytes_exact()?,
                    6 => duress_tag = Some(*d.bytes_exact()?),
                    7 => name = *d.bytes_exact()?,
                    8 => nonce = *d.bytes_exact()?,
                    9 => index = d.u32()?,
                    10 => template = d.u8()?,
                    _ => policy_nonce = *d.bytes_exact()?,
                }
                Ok(())
            })?;
            let ctx = IndexContext {
                tpm_index: index,
                name_prewrite: None,
                name_postwrite: name,
                policy_nonce,
            };
            if !xs_ok || template != TEMPLATE_H2_P256 || !ctx.is_valid() {
                return Err(CborError);
            }
            Ok(SlotFields::Bound(BoundSlots {
                s1_nonce,
                s1_ct,
                s2_nonce,
                index: ctx,
                tpm_id: Token {
                    template,
                    nonce,
                    ct,
                },
                duress_tag,
            }))
        }
        Mode::Portable => {
            let mut slot_ct = [0u8; 96];
            let mut slot_nonce = [0u8; 24];
            let mut duress_tag = None;
            d.map(PORTABLE_KEYS, 0b101, |d, k| {
                match k {
                    0 => slot_ct = *d.bytes_exact()?,
                    1 => duress_tag = Some(*d.bytes_exact()?),
                    _ => slot_nonce = *d.bytes_exact()?,
                }
                Ok(())
            })?;
            Ok(SlotFields::Portable(PortableSlots {
                slot_nonce,
                slot_ct,
                duress_tag,
            }))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tpmid::NAME_ALG_SHA256;

    pub(crate) fn name(b: u8) -> [u8; NAME_LEN] {
        let mut n = [b; NAME_LEN];
        n[..2].copy_from_slice(&NAME_ALG_SHA256);
        n
    }

    pub(crate) fn sample_core(mode: Mode, kind: PassphraseKind) -> CoreFields {
        CoreFields {
            vault_id: [0xa1; 16],
            mode,
            argon2: Argon2Params::DEFAULT,
            salt: [0x5a; 32],
            generation: 7,
            created_at: 1_790_000_000,
            keytable_gen: 7,
            keytable_digest: [0xd1; 64],
            card_set_id: [0xc5; 8],
            setup_id: [0x5e; 16],
            passphrase_kind: kind,
            tpm_cleanup: Vec::new(),
        }
    }

    pub(crate) fn sample_bound_slots(duress: bool) -> SlotFields {
        SlotFields::Bound(BoundSlots {
            s1_nonce: [1; 24],
            s1_ct: [2; 96],
            s2_nonce: [3; 24],
            index: IndexContext {
                tpm_index: 0x0180_1234,
                name_prewrite: None,
                name_postwrite: name(4),
                policy_nonce: [5; 32],
            },
            tpm_id: Token {
                template: 1,
                nonce: [6; 24],
                ct: [7; 48],
            },
            duress_tag: duress.then_some([8; 64]),
        })
    }

    pub(crate) fn cleanup(index: u32, pre: bool) -> TpmCleanupEntry {
        TpmCleanupEntry {
            index: IndexContext {
                tpm_index: index,
                name_prewrite: pre.then(|| name(9)),
                name_postwrite: name(10),
                policy_nonce: [11; 32],
            },
            token: Token {
                template: 1,
                nonce: [12; 24],
                ct: [13; 48],
            },
        }
    }

    fn key(b: u8) -> SecretBytes<32> {
        SecretBytes::take_from(&mut [b; 32]).unwrap()
    }

    #[test]
    fn round_trip_both_modes_and_kinds() {
        let k = key(0x42);
        for (mode, slots) in [
            (Mode::Bound, sample_bound_slots(true)),
            (Mode::Bound, sample_bound_slots(false)),
            (
                Mode::Portable,
                SlotFields::Portable(PortableSlots {
                    slot_nonce: [1; 24],
                    slot_ct: [2; 96],
                    duress_tag: None,
                }),
            ),
        ] {
            for kind in [PassphraseKind::Words, PassphraseKind::Custom] {
                let mut core = sample_core(mode, kind);
                core.add_cleanup(cleanup(0x0180_0002, true)).unwrap();
                core.add_cleanup(cleanup(0x0180_0001, false)).unwrap();
                let bytes = Header::build(&core, &slots, &k).unwrap();
                let h = Header::parse(&bytes).unwrap();
                assert_eq!(h.core(), &core);
                assert_eq!(h.slots(), &slots);
                assert!(h.verify_core(&k) && h.verify_slots(&k));
                assert!(!h.verify_core(&key(1)) && !h.verify_slots(&key(1)));
                assert_eq!(h.core_digest(), core.digest().unwrap());
                assert_eq!(h.core().tpm_cleanup[0].index.tpm_index, 0x0180_0001);
            }
        }
    }

    /// F7: flipping any byte of the core or `core_mac` makes the header fail
    /// to parse or fail `core_mac`; never a silent acceptance.
    #[test]
    fn every_core_byte_flip_is_rejected_f7() {
        let k = key(0x42);
        let bytes = Header::build(
            &sample_core(Mode::Bound, PassphraseKind::Custom),
            &sample_bound_slots(false),
            &k,
        )
        .unwrap();
        let h = Header::parse(&bytes).unwrap();
        let core = h.core_range.clone();
        let tag = core_mac_of(&k, h.core_bytes());
        let mac_at = bytes.windows(64).position(|w| w == tag).unwrap();
        let mut targets: Vec<usize> = core.collect();
        targets.extend(mac_at..mac_at + 64);
        for i in targets {
            for bit in [0x01u8, 0x80] {
                let mut t = bytes.clone();
                t[i] ^= bit;
                if let Ok(h) = Header::parse(&t) {
                    assert!(!h.verify_core(&k), "byte {i} bit {bit:#x}");
                }
            }
        }
    }

    #[test]
    fn schema_violations_are_rejected_f14() {
        let k = key(1);
        let good = sample_core(Mode::Portable, PassphraseKind::Words);
        let slots = SlotFields::Portable(PortableSlots {
            slot_nonce: [1; 24],
            slot_ct: [2; 96],
            duress_tag: None,
        });
        // Argon2 outside the hard caps (F13 at parse time).
        for (m, t, p) in [
            (1u32 << 30, 4, 4),
            (262_143, 4, 4),
            (262_144, 2, 4),
            (262_144, 4, 9),
        ] {
            let mut c = good.clone();
            c.argon2 = Argon2Params { m_kib: m, t, p };
            let bytes = encode_unchecked(&c, &slots, &k);
            assert!(Header::parse(&bytes).is_err(), "{m} {t} {p}");
        }
        // keytable_gen != generation.
        let mut c = good.clone();
        c.keytable_gen += 1;
        assert!(Header::parse(&encode_unchecked(&c, &slots, &k)).is_err());
        // Unsorted or duplicate cleanup entries, handle outside the owner range.
        for list in [
            vec![cleanup(0x0180_0002, false), cleanup(0x0180_0001, false)],
            vec![cleanup(0x0180_0001, false), cleanup(0x0180_0001, false)],
            vec![cleanup(0x0100_0001, false)],
        ] {
            let mut c = good.clone();
            c.tpm_cleanup = list;
            assert!(Header::parse(&encode_unchecked(&c, &slots, &k)).is_err());
        }
        // 33 cleanup entries.
        let mut c = good.clone();
        c.tpm_cleanup = (0..33).map(|i| cleanup(0x0180_0000 + i, false)).collect();
        assert!(Header::parse(&encode_unchecked(&c, &slots, &k)).is_err());
        // Over 64 KiB.
        assert!(Header::parse(&vec![0xa0; MAX_HEADER_LEN + 1]).is_err());
        // Trailing byte.
        let mut bytes = Header::build(&good, &slots, &k).unwrap();
        bytes.push(0);
        assert!(Header::parse(&bytes).is_err());
    }

    #[test]
    fn capacity_refuses_instead_of_evicting() {
        let mut c = sample_core(Mode::Portable, PassphraseKind::Words);
        for i in 0..32 {
            c.add_cleanup(cleanup(0x0180_0000 + i, false)).unwrap();
        }
        assert!(matches!(
            c.add_cleanup(cleanup(0x0180_1000, false)),
            Err(Error::Capacity(_))
        ));
        assert_eq!(c.tpm_cleanup.len(), 32);
        // 32 worst-case entries stay far below the 64 KiB cap.
        let mut c = sample_core(Mode::Bound, PassphraseKind::Custom);
        c.tpm_cleanup = (0..32).map(|i| cleanup(0x0180_0000 + i, true)).collect();
        let bytes = Header::build(&c, &sample_bound_slots(true), &key(1)).unwrap();
        assert!(bytes.len() < 16 * 1024, "{}", bytes.len());
    }

    /// Encodes without the build-time checks, to construct invalid headers.
    fn encode_unchecked(core: &CoreFields, slots: &SlotFields, k: &SecretBytes<32>) -> Vec<u8> {
        let core_bytes = core.encode().unwrap();
        let slots_bytes = slots.encode().unwrap();
        let mut e = Encoder::new(Vec::new());
        e.map(4).unwrap();
        e.key("core").unwrap();
        e.raw(&core_bytes).unwrap();
        e.key("slots").unwrap();
        e.raw(&slots_bytes).unwrap();
        e.key("core_mac").unwrap();
        e.bytes(&core_mac_of(k, &core_bytes)).unwrap();
        e.key("slots_mac").unwrap();
        e.bytes(&slots_mac_of(k, &core_digest_of(&core_bytes), &slots_bytes))
            .unwrap();
        e.into_sink()
    }
}
