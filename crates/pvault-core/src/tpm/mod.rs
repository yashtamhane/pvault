//! Bound mode's TPM layer (spec 9.1 to 9.3; SI-18, SI-22, SI-35, SI-36,
//! SI-42; approved for Milestone 5, D1 to D4).
//!
//! This module is platform independent: the exact public area and Name
//! computation, the per-command session attributes that pvault enforces,
//! the capability checks C1 to C4, the H-2 template bytes and the
//! [`Tpm`] interface used by the vault code. The `tss-esapi` backend exists
//! only on Linux with the `tpm` feature (D1, D10); elsewhere [`open`]
//! refuses with [`Error::BoundVault`].

use sha2::{Digest as _, Sha256};

use crate::errors::Error;
use crate::secrets::{SecretBuf, SecretBytes};
use crate::tpmid::{NAME_ALG_SHA256, NAME_LEN};

#[cfg(all(target_os = "linux", feature = "tpm"))]
mod esapi;
#[cfg(all(test, target_os = "linux", feature = "tpm"))]
pub(crate) mod testing;
#[cfg(test)]
mod tests;

/// Index attributes before the first write: ordinary, AUTHWRITE, AUTHREAD;
/// every other bit clear, so DA protection is on (9.1).
pub const ATTRS_PREWRITE: u32 = 0x0004_0004;
/// After the first write: the same plus WRITTEN (bit 29).
pub const ATTRS_POSTWRITE: u32 = 0x2004_0004;
/// Index data: `u8(x = 2) || S2_wrapped[96]`.
pub const DATA_SIZE: u16 = 97;
/// `TPM_CC_PolicyAuthValue`.
const CC_POLICY_AUTH_VALUE: u32 = 0x0000_016B;
/// `TPM_CC_PolicyOR`.
const CC_POLICY_OR: u32 = 0x0000_0171;
/// Handle attempts before "no free handle" (SI-35 item 3).
pub const HANDLE_ATTEMPTS: usize = 32;

/// Which TPM bound mode talks to (`--tpm`, `docs/CLI.md` 4; D9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmTarget {
    /// `/dev/tpmrm0` (the default). Never opened by tests.
    Device,
    /// A local `swtpm` on `127.0.0.1`: commands on `port`, control on
    /// `port + 1`.
    Swtpm {
        /// Command port.
        port: u16,
    },
}

impl TpmTarget {
    /// Parses `device` or `swtpm:PORT`.
    pub fn parse(s: &str) -> Option<Self> {
        if s == "device" {
            return Some(Self::Device);
        }
        let port: u16 = s.strip_prefix("swtpm:")?.parse().ok()?;
        (port != 0 && port != u16::MAX).then_some(Self::Swtpm { port })
    }
}

impl std::fmt::Display for TpmTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Device => f.write_str("device"),
            Self::Swtpm { port } => write!(f, "swtpm:{port}"),
        }
    }
}

/// The TPM options of one command (`--tpm`, `--tpm-owner-auth`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmOptions {
    /// The TPM.
    pub target: TpmTarget,
    /// `--tpm-owner-auth`: the owner authorization is supplied (a hidden
    /// prompt, or the documented `--secrets-stdin` line).
    pub owner_auth_declared: bool,
}

impl Default for TpmOptions {
    fn default() -> Self {
        Self {
            target: TpmTarget::Device,
            owner_auth_declared: false,
        }
    }
}

/// `authPolicy = SHA-256(0^32 || CC_PolicyOR || A || B)`, with
/// `A = SHA-256(0^32 || CC_PolicyAuthValue)` and
/// `B = SHA-256("pvault/v1/policy-nonce" || nonce)` (9.1).
pub fn auth_policy(nonce: &[u8; 32]) -> [u8; 32] {
    let a: [u8; 32] = Sha256::new()
        .chain_update([0u8; 32])
        .chain_update(CC_POLICY_AUTH_VALUE.to_be_bytes())
        .finalize()
        .into();
    let b: [u8; 32] = Sha256::new()
        .chain_update(b"pvault/v1/policy-nonce")
        .chain_update(nonce)
        .finalize()
        .into();
    Sha256::new()
        .chain_update([0u8; 32])
        .chain_update(CC_POLICY_OR.to_be_bytes())
        .chain_update(a)
        .chain_update(b)
        .finalize()
        .into()
}

/// The 46-byte marshalled `TPMS_NV_PUBLIC` of a pvault index.
fn nv_public_bytes(index: u32, attributes: u32, policy: &[u8; 32]) -> [u8; 46] {
    let mut m = [0u8; 46];
    m[..4].copy_from_slice(&index.to_be_bytes());
    m[4..6].copy_from_slice(&NAME_ALG_SHA256);
    m[6..10].copy_from_slice(&attributes.to_be_bytes());
    m[10..12].copy_from_slice(&32u16.to_be_bytes());
    m[12..44].copy_from_slice(policy);
    m[44..].copy_from_slice(&DATA_SIZE.to_be_bytes());
    m
}

/// The Name of a pvault index: `u16(0x000B) || SHA-256(public area)`.
pub fn name(index: u32, attributes: u32, nonce: &[u8; 32]) -> [u8; NAME_LEN] {
    let digest: [u8; 32] =
        Sha256::digest(nv_public_bytes(index, attributes, &auth_policy(nonce))).into();
    let mut n = [0u8; NAME_LEN];
    n[..2].copy_from_slice(&NAME_ALG_SHA256);
    n[2..].copy_from_slice(&digest);
    n
}

/// Both expected Names, precomputed before the index exists (6.3 d).
pub fn expected_names(index: u32, nonce: &[u8; 32]) -> ([u8; NAME_LEN], [u8; NAME_LEN]) {
    (
        name(index, ATTRS_PREWRITE, nonce),
        name(index, ATTRS_POSTWRITE, nonce),
    )
}

/// A public area as the TPM reported it (`NV_ReadPublic`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPublicInfo {
    /// `nvIndex`.
    pub index: u32,
    /// `nameAlg` (`TPM_ALG_ID`).
    pub name_alg: u16,
    /// `attributes` (`TPMA_NV`).
    pub attributes: u32,
    /// `authPolicy`.
    pub auth_policy: Vec<u8>,
    /// `dataSize`.
    pub data_size: u16,
    /// The Name the TPM returned.
    pub name: Vec<u8>,
}

impl NvPublicInfo {
    /// The exact pvault format (9.1) for `index` and `nonce`, either before
    /// or after the first write, with a Name equal to pvault's computation.
    /// Used by 9.2a (provisional reads) and 9.2b (ownership).
    pub fn matches(&self, index: u32, nonce: &[u8; 32], written: bool) -> bool {
        let attributes = if written {
            ATTRS_POSTWRITE
        } else {
            ATTRS_PREWRITE
        };
        self.index == index
            && self.name_alg == u16::from_be_bytes(NAME_ALG_SHA256)
            && self.attributes == attributes
            && self.auth_policy == auth_policy(nonce)
            && self.data_size == DATA_SIZE
            && self.name == name(index, attributes, nonce)
    }
}

/// A command that runs in a session, and the session pvault gives it (9.1,
/// D2). The table is fixed here and enforced by pvault; it is never left to
/// the TPM stack to reject a wrong combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `NV_DefineSpace` (owner): the `auth` parameter is `tpm_auth`.
    DefineSpace,
    /// `NV_Write` (index): `x || S2_wrapped`.
    Write,
    /// `NV_Read` (index): the response carries `x || S2_wrapped`.
    Read,
    /// `NV_UndefineSpace` (owner): no parameter to protect.
    UndefineSpace,
}

/// Session attributes for one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAttrs {
    /// Encrypt the first command parameter.
    pub decrypt: bool,
    /// Encrypt the first response parameter.
    pub encrypt: bool,
}

impl Command {
    /// The approved attributes (9.1): decrypt for `NV_DefineSpace` and
    /// `NV_Write`, encrypt for `NV_Read`, neither for `NV_UndefineSpace`.
    pub const fn attrs(self) -> SessionAttrs {
        match self {
            Self::DefineSpace | Self::Write => SessionAttrs {
                decrypt: true,
                encrypt: false,
            },
            Self::Read => SessionAttrs {
                decrypt: false,
                encrypt: true,
            },
            Self::UndefineSpace => SessionAttrs {
                decrypt: false,
                encrypt: false,
            },
        }
    }
}

#[cfg(test)]
thread_local! {
    static WEAKENED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test builds only: turns parameter encryption off on this thread, for the
/// F103 negative cases that prove the transport capture works. Not present
/// in any other build.
#[cfg(all(test, target_os = "linux", feature = "tpm"))]
pub(crate) fn weaken_for_test(on: bool) {
    WEAKENED.with(|w| w.set(on));
}

/// The attributes a session is given: [`Command::attrs`], except in the
/// F103 negative cases of test builds.
#[cfg_attr(not(all(target_os = "linux", feature = "tpm")), allow(dead_code))]
pub(crate) fn effective_attrs(cmd: Command) -> SessionAttrs {
    #[cfg(test)]
    if WEAKENED.with(|w| w.get()) {
        return SessionAttrs {
            decrypt: false,
            encrypt: false,
        };
    }
    cmd.attrs()
}

/// `TPM_PT_PERMANENT` and `TPM_PT_STARTUP_CLEAR` as read with
/// `GetCapability`, plus the DA counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmState {
    /// `TPM_PT_PERMANENT`.
    pub permanent: u32,
    /// `TPM_PT_STARTUP_CLEAR`.
    pub startup_clear: u32,
    /// `TPM_PT_LOCKOUT_COUNTER`.
    pub lockout_counter: u32,
    /// `TPM_PT_MAX_AUTH_FAIL`.
    pub max_auth_fail: u32,
}

impl TpmState {
    /// C1 fails: owner authorization is set (`ownerAuthSet`).
    pub fn owner_auth_set(&self) -> bool {
        self.permanent & 0x1 != 0
    }
    /// `endorsementAuthSet` (part of C4).
    pub fn endorsement_auth_set(&self) -> bool {
        self.permanent & 0x2 != 0
    }
    /// C3 fails: `inLockout`.
    pub fn in_lockout(&self) -> bool {
        self.permanent & 0x200 != 0
    }
    /// C2: `shEnable`.
    pub fn storage_enabled(&self) -> bool {
        self.startup_clear & 0x2 != 0
    }
    /// `ehEnable` (part of C4).
    pub fn endorsement_enabled(&self) -> bool {
        self.startup_clear & 0x4 != 0
    }

    /// Why bound duress is unavailable (9.3, D4), or an empty list. C4's
    /// "EK creatable" part is `ek_measurable`, measured separately.
    pub fn duress_unavailable(&self, ek_measurable: bool) -> Vec<&'static str> {
        let mut why = Vec::new();
        if self.owner_auth_set() {
            why.push("owner authorization is set");
        }
        if !self.storage_enabled() {
            why.push("the storage hierarchy is disabled");
        }
        if self.in_lockout() {
            why.push("the TPM is in lockout");
        }
        if !self.endorsement_enabled() {
            why.push("the endorsement hierarchy is disabled");
        }
        if self.endorsement_auth_set() {
            why.push("endorsement authorization is set");
        }
        if !ek_measurable && self.endorsement_enabled() && !self.endorsement_auth_set() {
            why.push("the TPM identity cannot be measured");
        }
        why
    }
}

/// Policy-B-SHA256 of the TCG EK Credential Profile (H-2 `authPolicy`).
pub const POLICY_B_SHA256: [u8; 32] = [
    0xca, 0x3d, 0x0a, 0x99, 0xa2, 0xb9, 0x39, 0x06, 0xf7, 0xa3, 0x34, 0x24, 0x14, 0xef, 0xcf, 0xb3,
    0xa3, 0x85, 0xd4, 0x4c, 0xd1, 0xfd, 0x45, 0x90, 0x89, 0xd1, 0x9b, 0x50, 0x71, 0xc0, 0xb7, 0xa0,
];

/// The H-2 template (spec 8.1) as a marshalled `TPMT_PUBLIC`: ECC,
/// SHA-256, attributes `0x000300F2` (fixedTPM, fixedParent,
/// sensitiveDataOrigin, userWithAuth, adminWithPolicy, restricted, decrypt),
/// Policy-B-SHA256, AES-128-CFB, null scheme, NIST P-256, null KDF, empty
/// `unique`. pvault builds this itself (D4); the backend's template is
/// checked against these bytes.
pub const H2_TEMPLATE: [u8; 58] = {
    let mut t = [0u8; 58];
    let head: [u8; 10] = [0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x00, 0xF2, 0x00, 0x20];
    let mut i = 0;
    while i < 10 {
        t[i] = head[i];
        i += 1;
    }
    let mut j = 0;
    while j < 32 {
        t[10 + j] = POLICY_B_SHA256[j];
        j += 1;
    }
    let tail: [u8; 16] = [
        0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // AES, 128 bits, CFB
        0x00, 0x10, // scheme: null
        0x00, 0x03, // NIST P-256
        0x00, 0x10, // KDF: null
        0x00, 0x00, 0x00, 0x00, // unique: x and y empty
    ];
    let mut k = 0;
    while k < 16 {
        t[42 + k] = tail[k];
        k += 1;
    }
    t
};

/// What bound mode needs from a TPM. One implementation exists (the Linux
/// `tss-esapi` backend); every method fails closed.
pub trait Tpm {
    /// `GetCapability(TPM_PROPERTIES)`: C1 to C3 and the DA counters.
    fn state(&mut self) -> Result<TpmState, Error>;
    /// The H-2 EK digest (spec 8.1): SHA-256 of the marshalled returned
    /// `TPMT_PUBLIC`. [`Error::TpmIdentity`] when it cannot be measured.
    fn ek_digest(&mut self) -> Result<[u8; 32], Error>;
    /// `NV_ReadPublic`; `None` when nothing is defined at `index`.
    fn read_public(&mut self, index: u32) -> Result<Option<NvPublicInfo>, Error>;
    /// `NV_DefineSpace` with the 9.1 public area, `authValue = tpm_auth`.
    /// [`Error::TpmHandleTaken`] when the handle is defined (nothing was
    /// created); [`Error::TpmDefineUnknown`] when the outcome is unknown.
    fn define(
        &mut self,
        index: u32,
        nonce: &[u8; 32],
        tpm_auth: &SecretBytes<32>,
        owner_auth: Option<&SecretBuf>,
    ) -> Result<(), Error>;
    /// `NV_Write` of the 97 index bytes at offset 0.
    fn write(
        &mut self,
        index: u32,
        tpm_auth: &SecretBytes<32>,
        data: &SecretBytes<97>,
    ) -> Result<(), Error>;
    /// `NV_Read` of the 97 index bytes. An authorization failure is
    /// [`Error::HeaderInvalid`] (`Unlock failed.`).
    fn read(&mut self, index: u32, tpm_auth: &SecretBytes<32>) -> Result<SecretBytes<97>, Error>;
    /// `NV_UndefineSpace` (owner).
    fn undefine(&mut self, index: u32, owner_auth: Option<&SecretBuf>) -> Result<(), Error>;
}

/// Connects to the TPM (`--tpm`).
#[cfg(all(target_os = "linux", feature = "tpm"))]
pub fn open(target: &TpmTarget) -> Result<Box<dyn Tpm>, Error> {
    Ok(Box::new(esapi::Esapi::open(target)?))
}

/// Without TPM support bound mode is refused (D10).
#[cfg(not(all(target_os = "linux", feature = "tpm")))]
pub fn open(_target: &TpmTarget) -> Result<Box<dyn Tpm>, Error> {
    Err(Error::BoundVault)
}

/// Whether this build supports bound mode.
pub const fn supported() -> bool {
    cfg!(all(target_os = "linux", feature = "tpm"))
}

/// A fresh owner-range handle that is free on this TPM (SI-35 item 3):
/// uniformly random, probed with `NV_ReadPublic`, at most 32 attempts.
pub fn free_handle(tpm: &mut dyn Tpm) -> Result<u32, Error> {
    let span = crate::tpmid::OWNER_RANGE.end() - crate::tpmid::OWNER_RANGE.start() + 1;
    for _ in 0..HANDLE_ATTEMPTS {
        let r = u32::from_be_bytes(crate::crypto::random::array::<4>()?);
        let handle = crate::tpmid::OWNER_RANGE.start() + r % span;
        if tpm.read_public(handle)?.is_none() {
            return Ok(handle);
        }
    }
    Err(Error::TpmNoFreeHandle)
}
