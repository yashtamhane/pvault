//! The journal, `vault.journal` (spec 8.1 to 8.3; D6).
//!
//! Two record families share one canonical key schema:
//! - **init** (`op: "init"`): `prepared` → `keytable_created` →
//!   `keytable_written` → `committing`, MACed with `init_journal_key`;
//! - **transitions** (`op: "recover"` or `"convert"`):
//!   - `prepared` → `target_created` → `committing`, the forward path;
//!   - `tracking_created` → `rollback_tracking`, remote rollback with the +2
//!     generation.
//!
//!   `committing` carries `mac_old` and `mac_new`; every other phase carries
//!   one `mac` under `journal_key(old_bundle)`.
//!
//! `MAC = HMAC-SHA-512(key, "pvault/v1/journal" || encoding of the record
//! without its MAC field or fields)`.
//!
//! Parsing is strict: the 4.4 profile, at most 16 KiB, and **exactly** the
//! fields the record's op, phase and mode require. This module also holds the
//! restart decisions that need no file system: journal-temp promotion
//! (spec 8.2 and 8.3), side classification by exact core digest (6.6), and
//! reconstruction of the tracking core (8.2).

use crate::cbor::{CborError, Decoder, Encoder, key_order};
use crate::crypto::kdf::Argon2Params;
use crate::crypto::mac;
use crate::errors::Error;
use crate::header::{CoreFields, Mode, PassphraseKind, TpmCleanupEntry};
use crate::secrets::SecretBytes;
use crate::tpmid::{
    IndexContext, NAME_LEN, TEMPLATE_H2_P256, TOKEN_CT_LEN, TOKEN_NONCE_LEN, Token,
};

/// Largest journal (8.1).
pub const MAX_JOURNAL_LEN: usize = 16 * 1024;

/// Union of every journal key, in canonical order (4.4).
const KEYS: &[&str] = &[
    "op",
    "mac",
    "mode",
    "salt",
    "phase",
    "mac_new",
    "mac_old",
    "new_gen",
    "old_gen",
    "argon2_m",
    "argon2_p",
    "argon2_t",
    "setup_id",
    "vault_id",
    "target_mode",
    "tracking_gen",
    "new_tpm_index",
    "header_file_id",
    "header_id_kind",
    "keytable_digest",
    "new_core_digest",
    "new_tpm_id_ct_i",
    "new_tpm_id_ct_o",
    "old_core_digest",
    "passphrase_kind",
    "keytable_file_id",
    "keytable_id_kind",
    "new_policy_nonce",
    "track_kt_file_id",
    "track_kt_id_kind",
    "cleanup_tpm_id_ct",
    "new_name_prewrite",
    "target_kt_file_id",
    "target_kt_id_kind",
    "track_hdr_file_id",
    "track_hdr_id_kind",
    "new_name_postwrite",
    "new_tpm_id_nonce_i",
    "new_tpm_id_nonce_o",
    "new_tpm_id_template",
    "old_keytable_digest",
    "cleanup_tpm_id_nonce",
    "tracking_core_digest",
    "cleanup_tpm_id_template",
    "old_slots_authenticated",
];

/// A platform file identity (spec 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileIdentity {
    /// `u64_be(st_ino) || i64_be(birth_sec) || u32_be(birth_nsec)`.
    Unix([u8; 20]),
    /// `u64_be(VolumeSerialNumber) || FileId[16] || u64_be(CreationTime)`.
    Windows([u8; 32]),
}

impl FileIdentity {
    fn kind(&self) -> &'static str {
        match self {
            Self::Unix(_) => "unix",
            Self::Windows(_) => "windows",
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Unix(b) => b,
            Self::Windows(b) => b,
        }
    }

    fn parse(kind: &str, bytes: &[u8]) -> Result<Self, CborError> {
        match kind {
            "unix" => Ok(Self::Unix(bytes.try_into().map_err(|_| CborError)?)),
            "windows" => Ok(Self::Windows(bytes.try_into().map_err(|_| CborError)?)),
            _ => Err(CborError),
        }
    }
}

/// The `IDX` fields: a new TPM index and its identity token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Idx {
    /// Handle, both Names (`name_prewrite` is always present) and nonce.
    pub index: IndexContext,
    /// Scope-2 (init) or scope-3 (transition) token.
    pub token: Token,
}

/// The MAC field or fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Macs {
    /// `mac`.
    Single([u8; 64]),
    /// `mac_old` and `mac_new` (transition `committing`).
    Dual {
        /// Under `journal_key(old_bundle)`.
        old: [u8; 64],
        /// Under `journal_key(new_bundle)`.
        new: [u8; 64],
    },
}

/// Init phases, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InitPhase {
    /// Before any artifact.
    Prepared,
    /// The key-table temp exists and its identity is recorded.
    KeytableCreated,
    /// The key table is final; its digest and the future core digest are known.
    KeytableWritten,
    /// The header temp exists and its identity is recorded.
    Committing,
}

impl InitPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::KeytableCreated => "keytable_created",
            Self::KeytableWritten => "keytable_written",
            Self::Committing => "committing",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "prepared" => Self::Prepared,
            "keytable_created" => Self::KeytableCreated,
            "keytable_written" => Self::KeytableWritten,
            "committing" => Self::Committing,
            _ => return None,
        })
    }

    fn successor(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::KeytableCreated),
            Self::KeytableCreated => Some(Self::KeytableWritten),
            Self::KeytableWritten => Some(Self::Committing),
            Self::Committing => None,
        }
    }
}

/// Transition phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionPhase {
    /// Before any target side effect.
    Prepared,
    /// The target key-table temp exists and its identity is recorded.
    TargetCreated,
    /// Ready to replace the header (dual MAC).
    Committing,
    /// Remote rollback: the tracking key-table temp is recorded.
    TrackingCreated,
    /// Remote rollback: the tracking core and header temp are recorded.
    RollbackTracking,
}

impl TransitionPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::TargetCreated => "target_created",
            Self::Committing => "committing",
            Self::TrackingCreated => "tracking_created",
            Self::RollbackTracking => "rollback_tracking",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "prepared" => Self::Prepared,
            "target_created" => Self::TargetCreated,
            "committing" => Self::Committing,
            "tracking_created" => Self::TrackingCreated,
            "rollback_tracking" => Self::RollbackTracking,
            _ => return None,
        })
    }

    /// The permitted canonical → temp transitions (spec 8.2).
    pub fn permits(self, next: Self) -> bool {
        use TransitionPhase::*;
        matches!(
            (self, next),
            (Prepared, TargetCreated)
                | (Prepared, TrackingCreated)
                | (TargetCreated, Committing)
                | (TargetCreated, TrackingCreated)
                | (Committing, TrackingCreated)
                | (TrackingCreated, RollbackTracking)
        )
    }
}

/// An init record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitRecord {
    /// Phase.
    pub phase: InitPhase,
    /// Future `core.vault_id`.
    pub vault_id: [u8; 16],
    /// Future `core.setup_id`.
    pub setup_id: [u8; 16],
    /// Future mode.
    pub mode: Mode,
    /// Future `core.salt`.
    pub salt: [u8; 32],
    /// Argon2id parameters, within the hard caps.
    pub argon2: Argon2Params,
    /// Main passphrase kind (D1).
    pub passphrase_kind: PassphraseKind,
    /// New index (bound only), scope-2 token.
    pub idx: Option<Idx>,
    /// `keytable.1.pv.tmp` identity (from `keytable_created`).
    pub keytable_id: Option<FileIdentity>,
    /// SHA-512 of `keytable.1.pv` (from `keytable_written`).
    pub keytable_digest: Option<[u8; 64]>,
    /// Digest of the future core (from `keytable_written`).
    pub new_core_digest: Option<[u8; 64]>,
    /// `vault.hdr.tmp` identity (`committing`).
    pub header_id: Option<FileIdentity>,
    /// MAC under `init_journal_key`.
    pub mac: [u8; 64],
}

/// Recovery or conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionOp {
    /// `recover`.
    Recover,
    /// `convert`.
    Convert,
}

/// A transition record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRecord {
    /// Recover or convert.
    pub op: TransitionOp,
    /// Phase.
    pub phase: TransitionPhase,
    /// `core.vault_id`.
    pub vault_id: [u8; 16],
    /// Generation of the old core.
    pub old_gen: u64,
    /// `old_gen + 1`.
    pub new_gen: u64,
    /// Target mode.
    pub target_mode: Mode,
    /// Exact old core digest.
    pub old_core_digest: [u8; 64],
    /// The old core's `keytable_digest`.
    pub old_keytable_digest: [u8; 64],
    /// New index (bound target), scope-3 token.
    pub idx: Option<Idx>,
    /// Target key-table temp identity.
    pub target_kt_id: Option<FileIdentity>,
    /// Exact new core digest (`committing`).
    pub new_core_digest: Option<[u8; 64]>,
    /// Header temp identity (`committing`, retained into tracking).
    pub header_id: Option<FileIdentity>,
    /// Whether the old slots authenticated (`committing`).
    pub old_slots_authenticated: Option<bool>,
    /// `old_gen + 2` (tracking phases).
    pub tracking_gen: Option<u64>,
    /// Scope-5 rewrap of the new index's token under the old `K_mac`.
    pub cleanup_token: Option<Token>,
    /// Tracking key-table temp identity.
    pub track_kt_id: Option<FileIdentity>,
    /// Exact tracking core digest (`rollback_tracking`).
    pub tracking_core_digest: Option<[u8; 64]>,
    /// Tracking header temp identity (`rollback_tracking`).
    pub track_hdr_id: Option<FileIdentity>,
    /// `mac`, or `mac_old` and `mac_new`.
    pub macs: Macs,
}

/// Either record family.
// One short-lived value per journal; boxing would add an allocation for nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// `op: "init"`.
    Init(InitRecord),
    /// `op: "recover"` or `"convert"`.
    Transition(TransitionRecord),
}

#[derive(Clone, Copy)]
enum Val<'a> {
    U(u64),
    B(&'a [u8]),
    T(&'a str),
    Bool(bool),
}

type Fields<'a> = Vec<(&'static str, Val<'a>)>;

fn push_idx<'a>(f: &mut Fields<'a>, idx: &'a Idx, suffix: char) {
    let (nonce_key, ct_key) = match suffix {
        'i' => ("new_tpm_id_nonce_i", "new_tpm_id_ct_i"),
        _ => ("new_tpm_id_nonce_o", "new_tpm_id_ct_o"),
    };
    f.push(("new_tpm_index", Val::U(idx.index.tpm_index.into())));
    if let Some(pre) = &idx.index.name_prewrite {
        f.push(("new_name_prewrite", Val::B(pre)));
    }
    f.push(("new_name_postwrite", Val::B(&idx.index.name_postwrite)));
    f.push(("new_policy_nonce", Val::B(&idx.index.policy_nonce)));
    f.push(("new_tpm_id_template", Val::U(idx.token.template.into())));
    f.push((nonce_key, Val::B(&idx.token.nonce)));
    f.push((ct_key, Val::B(&idx.token.ct)));
}

fn push_id<'a>(
    f: &mut Fields<'a>,
    kind: &'static str,
    file: &'static str,
    id: &'a Option<FileIdentity>,
) {
    if let Some(id) = id {
        f.push((kind, Val::T(id.kind())));
        f.push((file, Val::B(id.bytes())));
    }
}

impl Record {
    fn fields(&self, with_macs: bool) -> Fields<'_> {
        let mut f: Fields<'_> = Vec::with_capacity(32);
        match self {
            Self::Init(r) => {
                f.push(("op", Val::T("init")));
                f.push(("phase", Val::T(r.phase.as_str())));
                f.push(("vault_id", Val::B(&r.vault_id)));
                f.push(("setup_id", Val::B(&r.setup_id)));
                f.push(("mode", Val::T(r.mode.as_str())));
                f.push(("salt", Val::B(&r.salt)));
                f.push(("argon2_m", Val::U(r.argon2.m_kib.into())));
                f.push(("argon2_t", Val::U(r.argon2.t.into())));
                f.push(("argon2_p", Val::U(r.argon2.p.into())));
                f.push(("passphrase_kind", Val::T(r.passphrase_kind.as_str())));
                if let Some(idx) = &r.idx {
                    push_idx(&mut f, idx, 'i');
                }
                push_id(
                    &mut f,
                    "keytable_id_kind",
                    "keytable_file_id",
                    &r.keytable_id,
                );
                if let Some(d) = &r.keytable_digest {
                    f.push(("keytable_digest", Val::B(d)));
                }
                if let Some(d) = &r.new_core_digest {
                    f.push(("new_core_digest", Val::B(d)));
                }
                push_id(&mut f, "header_id_kind", "header_file_id", &r.header_id);
                if with_macs {
                    f.push(("mac", Val::B(&r.mac)));
                }
            }
            Self::Transition(r) => {
                f.push((
                    "op",
                    Val::T(match r.op {
                        TransitionOp::Recover => "recover",
                        TransitionOp::Convert => "convert",
                    }),
                ));
                f.push(("phase", Val::T(r.phase.as_str())));
                f.push(("vault_id", Val::B(&r.vault_id)));
                f.push(("old_gen", Val::U(r.old_gen)));
                f.push(("new_gen", Val::U(r.new_gen)));
                f.push(("target_mode", Val::T(r.target_mode.as_str())));
                f.push(("old_core_digest", Val::B(&r.old_core_digest)));
                f.push(("old_keytable_digest", Val::B(&r.old_keytable_digest)));
                if let Some(idx) = &r.idx {
                    push_idx(&mut f, idx, 'o');
                }
                push_id(
                    &mut f,
                    "target_kt_id_kind",
                    "target_kt_file_id",
                    &r.target_kt_id,
                );
                if let Some(d) = &r.new_core_digest {
                    f.push(("new_core_digest", Val::B(d)));
                }
                push_id(&mut f, "header_id_kind", "header_file_id", &r.header_id);
                if let Some(b) = r.old_slots_authenticated {
                    f.push(("old_slots_authenticated", Val::Bool(b)));
                }
                if let Some(g) = r.tracking_gen {
                    f.push(("tracking_gen", Val::U(g)));
                }
                if let Some(t) = &r.cleanup_token {
                    f.push(("cleanup_tpm_id_template", Val::U(t.template.into())));
                    f.push(("cleanup_tpm_id_nonce", Val::B(&t.nonce)));
                    f.push(("cleanup_tpm_id_ct", Val::B(&t.ct)));
                }
                push_id(
                    &mut f,
                    "track_kt_id_kind",
                    "track_kt_file_id",
                    &r.track_kt_id,
                );
                if let Some(d) = &r.tracking_core_digest {
                    f.push(("tracking_core_digest", Val::B(d)));
                }
                push_id(
                    &mut f,
                    "track_hdr_id_kind",
                    "track_hdr_file_id",
                    &r.track_hdr_id,
                );
                if with_macs {
                    match &r.macs {
                        Macs::Single(m) => f.push(("mac", Val::B(m))),
                        Macs::Dual { old, new } => {
                            f.push(("mac_old", Val::B(old)));
                            f.push(("mac_new", Val::B(new)));
                        }
                    }
                }
            }
        }
        f.sort_by(|a, b| key_order(a.0, b.0));
        f
    }

    fn encode_fields(&self, with_macs: bool) -> Vec<u8> {
        let fields = self.fields(with_macs);
        let mut e = Encoder::new(Vec::new());
        // Writing to a Vec cannot fail.
        let _ = (|| -> Result<(), CborError> {
            e.map(fields.len())?;
            for (k, v) in &fields {
                e.key(k)?;
                match v {
                    Val::U(u) => e.uint(*u)?,
                    Val::B(b) => e.bytes(b)?,
                    Val::T(t) => e.text(t)?,
                    Val::Bool(b) => e.bool(*b)?,
                }
            }
            Ok(())
        })();
        e.into_sink()
    }

    /// The canonical encoding, MACs included.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_fields(true)
    }

    /// The MAC input: the encoding without the MAC field or fields.
    pub fn mac_input(&self) -> Vec<u8> {
        self.encode_fields(false)
    }

    fn mac_with(&self, key: &SecretBytes<32>) -> [u8; 64] {
        mac::hmac_sha512(
            key.expose_secret(),
            &[b"pvault/v1/journal", &self.mac_input()],
        )
    }

    fn check_with(&self, key: &SecretBytes<32>, tag: &[u8; 64]) -> bool {
        mac::verify_hmac_sha512(
            key.expose_secret(),
            &[b"pvault/v1/journal", &self.mac_input()],
            tag,
        )
    }

    /// Sets the MAC(s). `new` is required exactly for transition `committing`.
    pub fn seal(
        &mut self,
        key: &SecretBytes<32>,
        new: Option<&SecretBytes<32>>,
    ) -> Result<(), Error> {
        let m = self.mac_with(key);
        match self {
            Self::Init(r) => {
                if new.is_some() {
                    return Err(Error::JournalInvalid);
                }
                r.mac = m;
            }
            Self::Transition(r) => {
                let dual = r.phase == TransitionPhase::Committing;
                match (dual, new) {
                    (true, Some(nk)) => {
                        let mn = Self::Transition(r.clone()).mac_with(nk);
                        r.macs = Macs::Dual { old: m, new: mn };
                    }
                    (false, None) => r.macs = Macs::Single(m),
                    _ => return Err(Error::JournalInvalid),
                }
            }
        }
        Ok(())
    }

    /// Verifies the record with the old-side key (`mac`, or `mac_old`).
    pub fn verify_old(&self, key: &SecretBytes<32>) -> bool {
        match self {
            Self::Init(r) => self.check_with(key, &r.mac),
            Self::Transition(r) => match &r.macs {
                Macs::Single(m) => self.check_with(key, m),
                Macs::Dual { old, .. } => self.check_with(key, old),
            },
        }
    }

    /// Verifies `mac_new` (transition `committing` only).
    pub fn verify_new(&self, key: &SecretBytes<32>) -> bool {
        match self {
            Self::Transition(TransitionRecord {
                macs: Macs::Dual { new, .. },
                ..
            }) => self.check_with(key, new),
            _ => false,
        }
    }

    /// Parses a record strictly. It is unauthenticated until verified.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_JOURNAL_LEN {
            return Err(Error::JournalInvalid);
        }
        let record = parse_inner(bytes).map_err(|_| Error::JournalInvalid)?;
        // Exactly the expected fields, and nothing else: re-encoding must
        // reproduce the input byte for byte (the input is canonical).
        if record.encode() != bytes {
            return Err(Error::JournalInvalid);
        }
        Ok(record)
    }
}

#[derive(Default)]
struct Raw<'a> {
    op: Option<&'a str>,
    mac: Option<[u8; 64]>,
    mode: Option<&'a str>,
    salt: Option<[u8; 32]>,
    phase: Option<&'a str>,
    mac_new: Option<[u8; 64]>,
    mac_old: Option<[u8; 64]>,
    new_gen: Option<u64>,
    old_gen: Option<u64>,
    m: Option<u32>,
    p: Option<u32>,
    t: Option<u32>,
    setup_id: Option<[u8; 16]>,
    vault_id: Option<[u8; 16]>,
    target_mode: Option<&'a str>,
    tracking_gen: Option<u64>,
    new_tpm_index: Option<u32>,
    header_file_id: Option<&'a [u8]>,
    header_id_kind: Option<&'a str>,
    keytable_digest: Option<[u8; 64]>,
    new_core_digest: Option<[u8; 64]>,
    ct_i: Option<[u8; TOKEN_CT_LEN]>,
    ct_o: Option<[u8; TOKEN_CT_LEN]>,
    old_core_digest: Option<[u8; 64]>,
    passphrase_kind: Option<&'a str>,
    keytable_file_id: Option<&'a [u8]>,
    keytable_id_kind: Option<&'a str>,
    new_policy_nonce: Option<[u8; 32]>,
    track_kt_file_id: Option<&'a [u8]>,
    track_kt_id_kind: Option<&'a str>,
    cleanup_ct: Option<[u8; TOKEN_CT_LEN]>,
    new_name_prewrite: Option<[u8; NAME_LEN]>,
    target_kt_file_id: Option<&'a [u8]>,
    target_kt_id_kind: Option<&'a str>,
    track_hdr_file_id: Option<&'a [u8]>,
    track_hdr_id_kind: Option<&'a str>,
    new_name_postwrite: Option<[u8; NAME_LEN]>,
    nonce_i: Option<[u8; TOKEN_NONCE_LEN]>,
    nonce_o: Option<[u8; TOKEN_NONCE_LEN]>,
    new_tpm_id_template: Option<u8>,
    old_keytable_digest: Option<[u8; 64]>,
    cleanup_nonce: Option<[u8; TOKEN_NONCE_LEN]>,
    tracking_core_digest: Option<[u8; 64]>,
    cleanup_template: Option<u8>,
    old_slots_authenticated: Option<bool>,
}

fn id(kind: Option<&str>, bytes: Option<&[u8]>) -> Result<Option<FileIdentity>, CborError> {
    match (kind, bytes) {
        (None, None) => Ok(None),
        (Some(k), Some(b)) => FileIdentity::parse(k, b).map(Some),
        _ => Err(CborError),
    }
}

fn idx(
    r: &Raw<'_>,
    nonce: Option<[u8; 24]>,
    ct: Option<[u8; 48]>,
) -> Result<Option<Idx>, CborError> {
    let parts = (
        r.new_tpm_index,
        r.new_name_prewrite,
        r.new_name_postwrite,
        r.new_policy_nonce,
        r.new_tpm_id_template,
        nonce,
        ct,
    );
    match parts {
        (None, None, None, None, None, None, None) => Ok(None),
        (Some(i), Some(pre), Some(post), Some(pn), Some(tpl), Some(n), Some(c)) => {
            let index = IndexContext {
                tpm_index: i,
                name_prewrite: Some(pre),
                name_postwrite: post,
                policy_nonce: pn,
            };
            if tpl != TEMPLATE_H2_P256 || !index.is_valid() {
                return Err(CborError);
            }
            Ok(Some(Idx {
                index,
                token: Token {
                    template: tpl,
                    nonce: n,
                    ct: c,
                },
            }))
        }
        _ => Err(CborError),
    }
}

fn req<T>(o: Option<T>) -> Result<T, CborError> {
    o.ok_or(CborError)
}

fn parse_inner(bytes: &[u8]) -> Result<Record, CborError> {
    let mut r = Raw::default();
    let mut d = Decoder::new(bytes);
    d.map(KEYS, 0, |d, k| {
        match KEYS[k] {
            "op" => r.op = Some(d.text()?),
            "mac" => r.mac = Some(*d.bytes_exact()?),
            "mode" => r.mode = Some(d.text()?),
            "salt" => r.salt = Some(*d.bytes_exact()?),
            "phase" => r.phase = Some(d.text()?),
            "mac_new" => r.mac_new = Some(*d.bytes_exact()?),
            "mac_old" => r.mac_old = Some(*d.bytes_exact()?),
            "new_gen" => r.new_gen = Some(d.uint()?),
            "old_gen" => r.old_gen = Some(d.uint()?),
            "argon2_m" => r.m = Some(d.u32()?),
            "argon2_p" => r.p = Some(d.u32()?),
            "argon2_t" => r.t = Some(d.u32()?),
            "setup_id" => r.setup_id = Some(*d.bytes_exact()?),
            "vault_id" => r.vault_id = Some(*d.bytes_exact()?),
            "target_mode" => r.target_mode = Some(d.text()?),
            "tracking_gen" => r.tracking_gen = Some(d.uint()?),
            "new_tpm_index" => r.new_tpm_index = Some(d.u32()?),
            "header_file_id" => r.header_file_id = Some(d.bytes_max(32)?),
            "header_id_kind" => r.header_id_kind = Some(d.text()?),
            "keytable_digest" => r.keytable_digest = Some(*d.bytes_exact()?),
            "new_core_digest" => r.new_core_digest = Some(*d.bytes_exact()?),
            "new_tpm_id_ct_i" => r.ct_i = Some(*d.bytes_exact()?),
            "new_tpm_id_ct_o" => r.ct_o = Some(*d.bytes_exact()?),
            "old_core_digest" => r.old_core_digest = Some(*d.bytes_exact()?),
            "passphrase_kind" => r.passphrase_kind = Some(d.text()?),
            "keytable_file_id" => r.keytable_file_id = Some(d.bytes_max(32)?),
            "keytable_id_kind" => r.keytable_id_kind = Some(d.text()?),
            "new_policy_nonce" => r.new_policy_nonce = Some(*d.bytes_exact()?),
            "track_kt_file_id" => r.track_kt_file_id = Some(d.bytes_max(32)?),
            "track_kt_id_kind" => r.track_kt_id_kind = Some(d.text()?),
            "cleanup_tpm_id_ct" => r.cleanup_ct = Some(*d.bytes_exact()?),
            "new_name_prewrite" => r.new_name_prewrite = Some(*d.bytes_exact()?),
            "target_kt_file_id" => r.target_kt_file_id = Some(d.bytes_max(32)?),
            "target_kt_id_kind" => r.target_kt_id_kind = Some(d.text()?),
            "track_hdr_file_id" => r.track_hdr_file_id = Some(d.bytes_max(32)?),
            "track_hdr_id_kind" => r.track_hdr_id_kind = Some(d.text()?),
            "new_name_postwrite" => r.new_name_postwrite = Some(*d.bytes_exact()?),
            "new_tpm_id_nonce_i" => r.nonce_i = Some(*d.bytes_exact()?),
            "new_tpm_id_nonce_o" => r.nonce_o = Some(*d.bytes_exact()?),
            "new_tpm_id_template" => r.new_tpm_id_template = Some(d.u8()?),
            "old_keytable_digest" => r.old_keytable_digest = Some(*d.bytes_exact()?),
            "cleanup_tpm_id_nonce" => r.cleanup_nonce = Some(*d.bytes_exact()?),
            "tracking_core_digest" => r.tracking_core_digest = Some(*d.bytes_exact()?),
            "cleanup_tpm_id_template" => r.cleanup_template = Some(d.u8()?),
            _ => r.old_slots_authenticated = Some(d.bool()?),
        }
        Ok(())
    })?;
    d.finish()?;
    let op = req(r.op)?;
    let vault_id = req(r.vault_id)?;
    let phase = req(r.phase)?;
    if op == "init" {
        let phase = InitPhase::parse(phase).ok_or(CborError)?;
        let mode = Mode::parse(req(r.mode)?)?;
        let argon2 = Argon2Params {
            m_kib: req(r.m)?,
            t: req(r.t)?,
            p: req(r.p)?,
        };
        argon2.check_hard_caps().map_err(|_| CborError)?;
        let idx = idx(&r, r.nonce_i, r.ct_i)?;
        if idx.is_some() != (mode == Mode::Bound) {
            return Err(CborError);
        }
        let rec = InitRecord {
            phase,
            vault_id,
            setup_id: req(r.setup_id)?,
            mode,
            salt: req(r.salt)?,
            argon2,
            passphrase_kind: PassphraseKind::parse(req(r.passphrase_kind)?)?,
            idx,
            keytable_id: id(r.keytable_id_kind, r.keytable_file_id)?,
            keytable_digest: r.keytable_digest,
            new_core_digest: r.new_core_digest,
            header_id: id(r.header_id_kind, r.header_file_id)?,
            mac: req(r.mac)?,
        };
        let has = |p: InitPhase| phase >= p;
        let ok = rec.keytable_id.is_some() == has(InitPhase::KeytableCreated)
            && rec.keytable_digest.is_some() == has(InitPhase::KeytableWritten)
            && rec.new_core_digest.is_some() == has(InitPhase::KeytableWritten)
            && rec.header_id.is_some() == has(InitPhase::Committing);
        return if ok {
            Ok(Record::Init(rec))
        } else {
            Err(CborError)
        };
    }
    let op = match op {
        "recover" => TransitionOp::Recover,
        "convert" => TransitionOp::Convert,
        _ => return Err(CborError),
    };
    let phase = TransitionPhase::parse(phase).ok_or(CborError)?;
    let old_gen = req(r.old_gen)?;
    let new_gen = req(r.new_gen)?;
    if old_gen.checked_add(1) != Some(new_gen) {
        return Err(CborError);
    }
    let target_mode = Mode::parse(req(r.target_mode)?)?;
    let idx = idx(&r, r.nonce_o, r.ct_o)?;
    let cleanup_token = match (r.cleanup_template, r.cleanup_nonce, r.cleanup_ct) {
        (None, None, None) => None,
        (Some(t), Some(n), Some(c)) if t == TEMPLATE_H2_P256 => Some(Token {
            template: t,
            nonce: n,
            ct: c,
        }),
        _ => return Err(CborError),
    };
    let macs = match (r.mac, r.mac_old, r.mac_new) {
        (Some(m), None, None) => Macs::Single(m),
        (None, Some(old), Some(new)) => Macs::Dual { old, new },
        _ => return Err(CborError),
    };
    let rec = TransitionRecord {
        op,
        phase,
        vault_id,
        old_gen,
        new_gen,
        target_mode,
        old_core_digest: req(r.old_core_digest)?,
        old_keytable_digest: req(r.old_keytable_digest)?,
        idx,
        target_kt_id: id(r.target_kt_id_kind, r.target_kt_file_id)?,
        new_core_digest: r.new_core_digest,
        header_id: id(r.header_id_kind, r.header_file_id)?,
        old_slots_authenticated: r.old_slots_authenticated,
        tracking_gen: r.tracking_gen,
        cleanup_token,
        track_kt_id: id(r.track_kt_id_kind, r.track_kt_file_id)?,
        tracking_core_digest: r.tracking_core_digest,
        track_hdr_id: id(r.track_hdr_id_kind, r.track_hdr_file_id)?,
        macs,
    };
    if transition_shape_ok(&rec) {
        Ok(Record::Transition(rec))
    } else {
        Err(CborError)
    }
}

/// Exact field presence per phase (spec 8.1).
fn transition_shape_ok(r: &TransitionRecord) -> bool {
    use TransitionPhase::*;
    if r.idx.is_some() != (r.target_mode == Mode::Bound) {
        return false;
    }
    let dual = matches!(r.macs, Macs::Dual { .. });
    let tracking = matches!(r.phase, TrackingCreated | RollbackTracking);
    let forward = match r.phase {
        Prepared => r.target_kt_id.is_none() && r.header_id.is_none(),
        TargetCreated => r.target_kt_id.is_some() && r.header_id.is_none(),
        Committing => r.target_kt_id.is_some() && r.header_id.is_some(),
        // The tracking phases keep whatever target/header identities their
        // predecessor recorded; a header identity implies a target identity.
        TrackingCreated | RollbackTracking => r.header_id.is_none() || r.target_kt_id.is_some(),
    };
    let committing_fields = r.new_core_digest.is_some() == (r.phase == Committing)
        && r.old_slots_authenticated.is_some() == (r.phase == Committing)
        && dual == (r.phase == Committing);
    let tracking_fields = r.tracking_gen.is_some() == tracking
        && r.cleanup_token.is_some() == tracking
        && r.track_kt_id.is_some() == tracking
        && r.tracking_core_digest.is_some() == (r.phase == RollbackTracking)
        && r.track_hdr_id.is_some() == (r.phase == RollbackTracking)
        // Tracking only exists for a bound target index, and needs old_gen + 2.
        && (!tracking
            || (r.idx.is_some() && r.tracking_gen == r.old_gen.checked_add(2)));
    forward && committing_fields && tracking_fields
}

/// Which bundle authenticated the current header's `core_mac`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bundle {
    /// The bundle before the transition.
    Old,
    /// The bundle after it.
    New,
}

/// A header whose `core_mac` has verified, and its exact core digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedHeader {
    /// SHA-512 of the stored core bytes (4.2).
    pub core_digest: [u8; 64],
    /// The bundle whose `K_mac` verified `core_mac`.
    pub by: Bundle,
}

/// Journal keys available at restart (from the material the owner supplied).
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalKeys<'a> {
    /// `journal_key(old_bundle)`.
    pub old: Option<&'a SecretBytes<32>>,
    /// `journal_key(new_bundle)`.
    pub new: Option<&'a SecretBytes<32>>,
}

/// The decision about a journal temp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Promotion {
    /// Replace the canonical record with the temp.
    Promote,
    /// The temp is a byte-identical authenticated duplicate; unlink it.
    Duplicate,
    /// Unowned residue: never promoted or deleted automatically. Further
    /// journal rewrites are blocked until the owner confirms its removal.
    Residue,
}

/// Which side of the commit the vault is on (6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The header is exactly the old core.
    Old,
    /// The header is exactly the new core (`committing` only).
    New,
    /// The header is exactly the tracking core (`rollback_tracking` only).
    Tracking,
    /// Nothing matches: delete nothing, report.
    Indeterminate,
}

fn eq64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

fn authenticated(rec: &Record, keys: &JournalKeys<'_>) -> bool {
    keys.old.is_some_and(|k| rec.verify_old(k)) || keys.new.is_some_and(|k| rec.verify_new(k))
}

/// Classifies a transition restart by exact core digest (6.6). Generation,
/// mode and file names never decide. The caller has verified the record's
/// MAC with the key of the side it acts on.
pub fn classify(rec: &TransitionRecord, header: &AuthenticatedHeader) -> Side {
    match header.by {
        Bundle::Old if eq64(&header.core_digest, &rec.old_core_digest) => Side::Old,
        Bundle::Old
            if rec.phase == TransitionPhase::RollbackTracking
                && rec
                    .tracking_core_digest
                    .is_some_and(|d| eq64(&header.core_digest, &d)) =>
        {
            Side::Tracking
        }
        Bundle::New
            if rec.phase == TransitionPhase::Committing
                && rec
                    .new_core_digest
                    .is_some_and(|d| eq64(&header.core_digest, &d)) =>
        {
            Side::New
        }
        _ => Side::Indeterminate,
    }
}

/// Transition journal-temp promotion (spec 8.2). `header` is the current
/// header if its `core_mac` verified with the bundle named in it.
pub fn promote_transition(
    canonical: &[u8],
    temp: &[u8],
    keys: &JournalKeys<'_>,
    header: Option<&AuthenticatedHeader>,
) -> Promotion {
    let Ok(Record::Transition(t)) = Record::parse(temp) else {
        return Promotion::Residue;
    };
    let t_auth_new = keys
        .new
        .is_some_and(|k| Record::Transition(t.clone()).verify_new(k));
    let t_auth = authenticated(&Record::Transition(t.clone()), keys);
    let Ok(Record::Transition(c)) = Record::parse(canonical) else {
        return Promotion::Residue;
    };
    let c_auth = authenticated(&Record::Transition(c.clone()), keys);
    if temp == canonical {
        // A duplicate is unlinked only under the same header condition as a
        // promotion: the header is exactly C's old core, or C's new core for
        // a `committing` record.
        let header_matches = header.is_some_and(|h| {
            (h.by == Bundle::Old && eq64(&h.core_digest, &c.old_core_digest))
                || (h.by == Bundle::New
                    && c.phase == TransitionPhase::Committing
                    && c.new_core_digest.is_some_and(|d| eq64(&h.core_digest, &d)))
        });
        return if c_auth && header_matches {
            Promotion::Duplicate
        } else {
            Promotion::Residue
        };
    }
    if !t_auth || !c.phase.permits(t.phase) {
        return Promotion::Residue;
    }
    let old_header =
        |h: &AuthenticatedHeader| h.by == Bundle::Old && eq64(&h.core_digest, &c.old_core_digest);
    let new_header = |h: &AuthenticatedHeader| {
        h.by == Bundle::New && t.new_core_digest.is_some_and(|d| eq64(&h.core_digest, &d))
    };
    let header_ok = match (t.phase, header) {
        (TransitionPhase::Committing, Some(h)) => old_header(h) || new_header(h),
        (_, Some(h)) => old_header(h),
        (_, None) => false,
    };
    if !header_ok {
        return Promotion::Residue;
    }
    // C must authenticate, except: a `committing` temp authenticated through
    // `mac_new` whose core matches the authenticated new header may replace
    // a canonical record that only parses (the Windows WO-1 case).
    let exception =
        t.phase == TransitionPhase::Committing && t_auth_new && header.is_some_and(new_header);
    if !c_auth && !exception {
        return Promotion::Residue;
    }
    if preserves(&c, &t) {
        Promotion::Promote
    } else {
        Promotion::Residue
    }
}

/// Immutable fields, `IDX`, recorded identities, `tracking_gen` and the
/// cleanup token are preserved byte-for-byte; a successor only adds fields.
fn kept<T: PartialEq>(a: &Option<T>, b: &Option<T>) -> bool {
    a.is_none() || a == b
}

fn preserves(c: &TransitionRecord, t: &TransitionRecord) -> bool {
    c.op == t.op
        && c.vault_id == t.vault_id
        && c.old_gen == t.old_gen
        && c.new_gen == t.new_gen
        && c.target_mode == t.target_mode
        && c.old_core_digest == t.old_core_digest
        && c.old_keytable_digest == t.old_keytable_digest
        && c.idx == t.idx
        && kept(&c.target_kt_id, &t.target_kt_id)
        && kept(&c.header_id, &t.header_id)
        && kept(&c.track_kt_id, &t.track_kt_id)
        && kept(&c.tracking_gen, &t.tracking_gen)
        && kept(&c.cleanup_token, &t.cleanup_token)
}

/// Init journal-temp promotion (spec 8.3): both records authenticate with
/// `init_journal_key`, the temp is the single successor phase, and every
/// immutable field and recorded identity or digest is preserved.
pub fn promote_init(canonical: &[u8], temp: &[u8], init_key: &SecretBytes<32>) -> Promotion {
    let (Ok(Record::Init(c)), Ok(Record::Init(t))) =
        (Record::parse(canonical), Record::parse(temp))
    else {
        return Promotion::Residue;
    };
    let c_ok = Record::Init(c.clone()).verify_old(init_key);
    if temp == canonical {
        return if c_ok {
            Promotion::Duplicate
        } else {
            Promotion::Residue
        };
    }
    let ok = c_ok
        && Record::Init(t.clone()).verify_old(init_key)
        && c.phase.successor() == Some(t.phase)
        && c.vault_id == t.vault_id
        && c.setup_id == t.setup_id
        && c.mode == t.mode
        && c.salt == t.salt
        && c.argon2 == t.argon2
        && c.passphrase_kind == t.passphrase_kind
        && c.idx == t.idx
        && kept(&c.keytable_id, &t.keytable_id)
        && kept(&c.keytable_digest, &t.keytable_digest)
        && kept(&c.new_core_digest, &t.new_core_digest);
    if ok {
        Promotion::Promote
    } else {
        Promotion::Residue
    }
}

/// Reconstructs the tracking core (spec 8.2): the authenticated old core with
/// `generation = keytable_gen = tracking_gen`, the tracking key table's
/// digest, and the journaled cleanup entry added. For `rollback_tracking`
/// the result must hash to `tracking_core_digest`; otherwise the state is
/// indeterminate (fresh encryption nonces change the key-table digest, so a
/// rewritten tracking key table can never satisfy an earlier core digest).
pub fn tracking_core(
    old_core: &CoreFields,
    rec: &TransitionRecord,
    tracking_keytable_digest: &[u8; 64],
) -> Result<CoreFields, Error> {
    let (Some(tracking_gen), Some(token), Some(idx)) =
        (rec.tracking_gen, rec.cleanup_token, rec.idx)
    else {
        return Err(Error::JournalInvalid);
    };
    let mut core = old_core.clone();
    core.generation = tracking_gen;
    core.keytable_gen = tracking_gen;
    core.keytable_digest = *tracking_keytable_digest;
    core.add_cleanup(TpmCleanupEntry {
        index: idx.index,
        token,
    })?;
    if let Some(expected) = rec.tracking_core_digest
        && !eq64(&core.digest()?, &expected)
    {
        return Err(Error::JournalInvalid);
    }
    Ok(core)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::header::tests::{name, sample_core};

    pub(crate) fn key(b: u8) -> SecretBytes<32> {
        SecretBytes::take_from(&mut [b; 32]).unwrap()
    }

    pub(crate) fn sample_idx() -> Idx {
        Idx {
            index: IndexContext {
                tpm_index: 0x0180_4000,
                name_prewrite: Some(name(0x31)),
                name_postwrite: name(0x32),
                policy_nonce: [0x33; 32],
            },
            token: Token {
                template: 1,
                nonce: [0x34; 24],
                ct: [0x35; 48],
            },
        }
    }

    pub(crate) fn prepared(target: Mode) -> TransitionRecord {
        TransitionRecord {
            op: TransitionOp::Recover,
            phase: TransitionPhase::Prepared,
            vault_id: [0xa1; 16],
            old_gen: 7,
            new_gen: 8,
            target_mode: target,
            old_core_digest: [0x0c; 64],
            old_keytable_digest: [0x0d; 64],
            idx: (target == Mode::Bound).then(sample_idx),
            target_kt_id: None,
            new_core_digest: None,
            header_id: None,
            old_slots_authenticated: None,
            tracking_gen: None,
            cleanup_token: None,
            track_kt_id: None,
            tracking_core_digest: None,
            track_hdr_id: None,
            macs: Macs::Single([0; 64]),
        }
    }

    /// Advances a transition record to `phase`, as the protocol does.
    pub(crate) fn advance(mut r: TransitionRecord, phase: TransitionPhase) -> TransitionRecord {
        use TransitionPhase::*;
        match phase {
            TargetCreated => r.target_kt_id = Some(FileIdentity::Unix([0x71; 20])),
            Committing => {
                r.new_core_digest = Some([0x4e; 64]);
                r.header_id = Some(FileIdentity::Unix([0x72; 20]));
                r.old_slots_authenticated = Some(true);
                r.macs = Macs::Dual {
                    old: [0; 64],
                    new: [0; 64],
                };
            }
            TrackingCreated => {
                r.new_core_digest = None;
                r.old_slots_authenticated = None;
                r.macs = Macs::Single([0; 64]);
                r.tracking_gen = Some(r.old_gen + 2);
                r.cleanup_token = Some(Token {
                    template: 1,
                    nonce: [0x36; 24],
                    ct: [0x37; 48],
                });
                r.track_kt_id = Some(FileIdentity::Unix([0x73; 20]));
            }
            RollbackTracking => {
                r.tracking_core_digest = Some([0x7c; 64]);
                r.track_hdr_id = Some(FileIdentity::Windows([0x74; 32]));
            }
            Prepared => {}
        }
        r.phase = phase;
        r
    }

    pub(crate) fn sealed(
        r: TransitionRecord,
        old: &SecretBytes<32>,
        new: &SecretBytes<32>,
    ) -> Vec<u8> {
        let dual = r.phase == TransitionPhase::Committing;
        let mut rec = Record::Transition(r);
        rec.seal(old, dual.then_some(new)).unwrap();
        rec.encode()
    }

    #[test]
    fn every_phase_round_trips_and_authenticates() {
        let (old, new) = (key(1), key(2));
        let p = prepared(Mode::Bound);
        let tc = advance(p.clone(), TransitionPhase::TargetCreated);
        let cm = advance(tc.clone(), TransitionPhase::Committing);
        let tr = advance(cm.clone(), TransitionPhase::TrackingCreated);
        let rt = advance(tr.clone(), TransitionPhase::RollbackTracking);
        for r in [p, tc, cm, tr, rt] {
            let bytes = sealed(r, &old, &new);
            let rec = Record::parse(&bytes).unwrap();
            assert!(rec.verify_old(&old));
            assert!(!rec.verify_old(&new));
            assert_eq!(rec.encode(), bytes);
            assert!(bytes.len() < MAX_JOURNAL_LEN);
        }
        let cm = sealed(
            advance(
                advance(prepared(Mode::Portable), TransitionPhase::TargetCreated),
                TransitionPhase::Committing,
            ),
            &old,
            &new,
        );
        let rec = Record::parse(&cm).unwrap();
        assert!(rec.verify_old(&old) && rec.verify_new(&new));
        assert!(!rec.verify_new(&old));
    }

    #[test]
    fn wrong_shapes_are_rejected() {
        let (old, new) = (key(1), key(2));
        // Tracking needs a bound target.
        let mut r = advance(prepared(Mode::Portable), TransitionPhase::TrackingCreated);
        r.idx = None;
        let mut rec = Record::Transition(r);
        rec.seal(&old, None).unwrap();
        assert!(Record::parse(&rec.encode()).is_err());
        // tracking_gen must be old_gen + 2.
        let mut r = advance(prepared(Mode::Bound), TransitionPhase::TrackingCreated);
        r.tracking_gen = Some(r.old_gen + 1);
        assert!(Record::parse(&sealed(r, &old, &new)).is_err());
        // new_gen must be old_gen + 1.
        let mut r = prepared(Mode::Bound);
        r.new_gen = 10;
        assert!(Record::parse(&sealed(r, &old, &new)).is_err());
        // Committing without a header identity.
        let mut r = advance(
            advance(prepared(Mode::Bound), TransitionPhase::TargetCreated),
            TransitionPhase::Committing,
        );
        r.header_id = None;
        let mut rec = Record::Transition(r);
        rec.seal(&old, Some(&new)).unwrap();
        assert!(Record::parse(&rec.encode()).is_err());
        // Over 16 KiB, and garbage.
        assert!(Record::parse(&vec![0xa0; MAX_JOURNAL_LEN + 1]).is_err());
        assert!(Record::parse(&[0xa0]).is_err());
    }

    fn header(by: Bundle, digest: [u8; 64]) -> AuthenticatedHeader {
        AuthenticatedHeader {
            core_digest: digest,
            by,
        }
    }

    /// Every permitted transition, authenticated on the side it needs.
    #[test]
    fn permitted_promotions() {
        use TransitionPhase::*;
        let (old, new) = (key(1), key(2));
        let old_only = JournalKeys {
            old: Some(&old),
            new: None,
        };
        let new_only = JournalKeys {
            old: None,
            new: Some(&new),
        };
        let old_hdr = header(Bundle::Old, [0x0c; 64]);
        let new_hdr = header(Bundle::New, [0x4e; 64]);
        let p = prepared(Mode::Bound);
        let tc = advance(p.clone(), TargetCreated);
        let cm = advance(tc.clone(), Committing);
        let tr_from_p = advance(p.clone(), TrackingCreated);
        let tr_from_tc = advance(tc.clone(), TrackingCreated);
        let tr_from_cm = advance(cm.clone(), TrackingCreated);
        let rt = advance(tr_from_cm.clone(), RollbackTracking);
        let cases = [
            (&p, &tc),
            (&p, &tr_from_p),
            (&tc, &cm),
            (&tc, &tr_from_tc),
            (&cm, &tr_from_cm),
            (&tr_from_cm, &rt),
        ];
        for (c, t) in cases {
            let (cb, tb) = (sealed(c.clone(), &old, &new), sealed(t.clone(), &old, &new));
            assert_eq!(
                promote_transition(&cb, &tb, &old_only, Some(&old_hdr)),
                Promotion::Promote,
                "{:?} -> {:?}",
                c.phase,
                t.phase
            );
            // Without an authenticated header, or with a foreign header digest: residue.
            assert_eq!(
                promote_transition(&cb, &tb, &old_only, None),
                Promotion::Residue
            );
            let foreign = header(Bundle::Old, [0x99; 64]);
            assert_eq!(
                promote_transition(&cb, &tb, &old_only, Some(&foreign)),
                Promotion::Residue
            );
        }
        // New side: target_created -> committing with only the new material,
        // header already replaced (the Windows WO-1 case).
        let (cb, tb) = (
            sealed(tc.clone(), &old, &new),
            sealed(cm.clone(), &old, &new),
        );
        assert_eq!(
            promote_transition(&cb, &tb, &new_only, Some(&new_hdr)),
            Promotion::Promote
        );
        // ...but not if the new header does not match the temp's new core.
        let wrong_new = header(Bundle::New, [0x55; 64]);
        assert_eq!(
            promote_transition(&cb, &tb, &new_only, Some(&wrong_new)),
            Promotion::Residue
        );
        // committing -> tracking_created never on the new side.
        let (cb, tb) = (
            sealed(cm.clone(), &old, &new),
            sealed(tr_from_cm.clone(), &old, &new),
        );
        let both = JournalKeys {
            old: Some(&old),
            new: Some(&new),
        };
        assert_eq!(
            promote_transition(&cb, &tb, &both, Some(&new_hdr)),
            Promotion::Residue
        );
        // Duplicate.
        assert_eq!(
            promote_transition(&cb, &cb, &old_only, Some(&old_hdr)),
            Promotion::Duplicate
        );
        assert_eq!(
            promote_transition(&cb, &cb, &JournalKeys::default(), Some(&old_hdr)),
            Promotion::Residue
        );
        // A duplicate needs the header condition too: none, or a foreign
        // one, leaves it as residue; the exact new core (committing) works.
        assert_eq!(
            promote_transition(&cb, &cb, &old_only, None),
            Promotion::Residue
        );
        let foreign = header(Bundle::Old, [0x99; 64]);
        assert_eq!(
            promote_transition(&cb, &cb, &old_only, Some(&foreign)),
            Promotion::Residue
        );
        assert_eq!(
            promote_transition(&cb, &cb, &new_only, Some(&new_hdr)),
            Promotion::Duplicate
        );
    }

    #[test]
    fn invalid_temps_are_residue() {
        use TransitionPhase::*;
        let (old, new) = (key(1), key(2));
        let keys = JournalKeys {
            old: Some(&old),
            new: Some(&new),
        };
        let hdr = header(Bundle::Old, [0x0c; 64]);
        let p = prepared(Mode::Bound);
        let tc = advance(p.clone(), TargetCreated);
        let cm = advance(tc.clone(), Committing);
        let tr = advance(cm.clone(), TrackingCreated);
        let rt = advance(tr.clone(), RollbackTracking);
        let pb = sealed(p.clone(), &old, &new);
        let tcb = sealed(tc.clone(), &old, &new);
        let cmb = sealed(cm.clone(), &old, &new);
        let trb = sealed(tr.clone(), &old, &new);
        // Skipped and backward phases.
        for (c, t) in [
            (&pb, &cmb),
            (&tcb, &sealed(rt.clone(), &old, &new)),
            (&cmb, &tcb),
            (&trb, &cmb),
        ] {
            assert_eq!(
                promote_transition(c, t, &keys, Some(&hdr)),
                Promotion::Residue
            );
        }
        // Incomplete temp.
        assert_eq!(
            promote_transition(&tcb, &cmb[..cmb.len() - 5], &keys, Some(&hdr)),
            Promotion::Residue
        );
        // Wrong key.
        let k3 = key(3);
        let wrong = sealed(cm.clone(), &k3, &k3);
        assert_eq!(
            promote_transition(&tcb, &wrong, &keys, Some(&hdr)),
            Promotion::Residue
        );
        // Divergent immutable field, dropped identity, changed identity.
        let mut d = cm.clone();
        d.old_keytable_digest = [0xee; 64];
        assert_eq!(
            promote_transition(&tcb, &sealed(d, &old, &new), &keys, Some(&hdr)),
            Promotion::Residue
        );
        let mut d = tr.clone();
        d.header_id = None; // committing's header identity not retained
        assert_eq!(
            promote_transition(&cmb, &sealed(d, &old, &new), &keys, Some(&hdr)),
            Promotion::Residue
        );
        let mut d = cm.clone();
        d.target_kt_id = Some(FileIdentity::Unix([0x99; 20]));
        assert_eq!(
            promote_transition(&tcb, &sealed(d, &old, &new), &keys, Some(&hdr)),
            Promotion::Residue
        );
        // Canonical unauthenticated (and no exception): residue.
        let tcb_wrong = sealed(tc.clone(), &k3, &k3);
        assert_eq!(
            promote_transition(&tcb_wrong, &cmb, &keys, Some(&hdr)),
            Promotion::Residue
        );
    }

    #[test]
    fn classification_by_exact_digest() {
        use TransitionPhase::*;
        let p = prepared(Mode::Bound);
        let cm = advance(advance(p.clone(), TargetCreated), Committing);
        let rt = advance(advance(cm.clone(), TrackingCreated), RollbackTracking);
        assert_eq!(classify(&p, &header(Bundle::Old, [0x0c; 64])), Side::Old);
        assert_eq!(classify(&cm, &header(Bundle::New, [0x4e; 64])), Side::New);
        assert_eq!(
            classify(&cm, &header(Bundle::Old, [0x4e; 64])),
            Side::Indeterminate
        );
        assert_eq!(
            classify(&p, &header(Bundle::New, [0x0c; 64])),
            Side::Indeterminate
        );
        assert_eq!(
            classify(&rt, &header(Bundle::Old, [0x7c; 64])),
            Side::Tracking
        );
        assert_eq!(
            classify(&rt, &header(Bundle::Old, [0x11; 64])),
            Side::Indeterminate
        );
    }

    #[test]
    fn init_records_and_promotion() {
        let k = key(9);
        let mut base = InitRecord {
            phase: InitPhase::Prepared,
            vault_id: [1; 16],
            setup_id: [2; 16],
            mode: Mode::Bound,
            salt: [3; 32],
            argon2: Argon2Params::DEFAULT,
            passphrase_kind: PassphraseKind::Custom,
            idx: Some(sample_idx()),
            keytable_id: None,
            keytable_digest: None,
            new_core_digest: None,
            header_id: None,
            mac: [0; 64],
        };
        let seal = |r: &InitRecord| {
            let mut rec = Record::Init(r.clone());
            rec.seal(&k, None).unwrap();
            rec.encode()
        };
        let p = seal(&base);
        base.phase = InitPhase::KeytableCreated;
        base.keytable_id = Some(FileIdentity::Unix([5; 20]));
        let kc = seal(&base);
        base.phase = InitPhase::KeytableWritten;
        base.keytable_digest = Some([6; 64]);
        base.new_core_digest = Some([7; 64]);
        let kw = seal(&base);
        base.phase = InitPhase::Committing;
        base.header_id = Some(FileIdentity::Unix([8; 20]));
        let cm = seal(&base);
        for b in [&p, &kc, &kw, &cm] {
            assert!(Record::parse(b).unwrap().verify_old(&k));
        }
        assert_eq!(promote_init(&p, &kc, &k), Promotion::Promote);
        assert_eq!(promote_init(&kc, &kw, &k), Promotion::Promote);
        assert_eq!(promote_init(&kw, &cm, &k), Promotion::Promote);
        assert_eq!(promote_init(&p, &kw, &k), Promotion::Residue); // skipped
        assert_eq!(promote_init(&kw, &kc, &k), Promotion::Residue); // backward
        assert_eq!(promote_init(&kc, &kc, &k), Promotion::Duplicate);
        assert_eq!(promote_init(&p, &kc, &key(1)), Promotion::Residue);
        // A bound init without IDX, and a portable one with it, are invalid.
        let mut r = base.clone();
        r.idx = None;
        assert!(Record::parse(&seal(&r)).is_err());
        // Argon2 out of caps is rejected before anything else (F71).
        let mut r = base.clone();
        r.argon2.m_kib = u32::MAX;
        assert!(Record::parse(&seal(&r)).is_err());
    }

    #[test]
    fn tracking_core_reconstruction() {
        let old = sample_core(Mode::Bound, PassphraseKind::Words);
        let mut rec = advance(
            advance(prepared(Mode::Bound), TransitionPhase::TargetCreated),
            TransitionPhase::Committing,
        );
        rec = advance(rec, TransitionPhase::TrackingCreated);
        let kt = [0x5d; 64];
        let core = tracking_core(&old, &rec, &kt).unwrap();
        assert_eq!(core.generation, old.generation + 2);
        assert_eq!(core.keytable_gen, core.generation);
        assert_eq!(core.tpm_cleanup.len(), 1);
        let digest = core.digest().unwrap();
        let mut rt = advance(rec, TransitionPhase::RollbackTracking);
        rt.tracking_core_digest = Some(digest);
        assert_eq!(tracking_core(&old, &rt, &kt).unwrap(), core);
        // A key table re-encrypted with fresh nonces has another digest, and
        // the reconstructed core no longer matches tracking_core_digest.
        assert!(matches!(
            tracking_core(&old, &rt, &[0x5e; 64]),
            Err(Error::JournalInvalid)
        ));
    }
}
