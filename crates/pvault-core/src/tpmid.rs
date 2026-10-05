//! Encrypted, rekeyable TPM-identity tokens (spec 8.1; SI-36; D6).
//!
//! A token encrypts the 32-byte `ek_digest` of the TPM that owns an NV
//! index, so that:
//! - a bundle rotation can re-encrypt it without the old TPM;
//! - remote recovery can verify an old duress tag;
//! - deletion is attempted only on the TPM whose live measurement matches.
//!
//! Measuring `ek_digest` is TPM work and arrives in Milestone 5; this
//! module is the format and its cryptography.
//!
//! ```text
//! key   = HKDF-SHA-512(ikm = base_key, salt = empty, info = scope label, L = 32)
//! aad   = "pvault/v1/tpm-id-token\0" || u8(scope) || vault_id[16] || u8(template)
//!         || u32_be(tpm_index) || u8(prewrite_present) || [name_prewrite[34]]
//!         || name_postwrite[34] || policy_nonce[32]
//! token = XChaCha20-Poly1305(key, nonce[24], aad).encrypt(ek_digest[32])   48 bytes
//! ```

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};

use crate::crypto::kdf;
use crate::crypto::random;
use crate::errors::Error;
use crate::secrets::SecretBytes;

/// `tpm_id_template = 1`: TCG EK Credential Profile 2.5 R2, template H-2,
/// the ECC NIST P-256 storage EK (spec 8.1). Any other value is a parse
/// failure.
pub const TEMPLATE_H2_P256: u8 = 1;
/// Token ciphertext length: 32-byte digest plus 16-byte tag.
pub const TOKEN_CT_LEN: usize = 48;
/// Token nonce length.
pub const TOKEN_NONCE_LEN: usize = 24;
/// Length of a stored TPM Name: `u16 nameAlg || SHA-256 digest`.
pub const NAME_LEN: usize = 34;
/// `TPM_ALG_SHA256`, the only Name algorithm pvault uses.
pub const NAME_ALG_SHA256: [u8; 2] = [0x00, 0x0B];
/// The owner range of NV handles.
pub const OWNER_RANGE: core::ops::RangeInclusive<u32> = 0x0180_0000..=0x01BF_FFFF;

/// Key scope of a token. Scope 4 is reserved and never used in v1 (N4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Current bound slots; key `K_mac`.
    Slots = 1,
    /// Safe-init journal; key `init_journal_key`.
    Init = 2,
    /// New index, old side of a transition; key `journal_key(old_bundle)`.
    NewIndexOldSide = 3,
    /// Core cleanup entry; key `K_mac`.
    Cleanup = 5,
}

impl Scope {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Slots => b"pvault/v1/tpm-id/slots",
            Self::Init => b"pvault/v1/tpm-id/init",
            Self::NewIndexOldSide => b"pvault/v1/tpm-id/new-index/old-side",
            Self::Cleanup => b"pvault/v1/tpm-id/cleanup",
        }
    }
}

/// The public NV-index context a token is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexContext {
    /// NV handle (owner range).
    pub tpm_index: u32,
    /// Pre-write Name, when the record has one.
    pub name_prewrite: Option<[u8; NAME_LEN]>,
    /// Post-write Name.
    pub name_postwrite: [u8; NAME_LEN],
    /// The index's policy nonce.
    pub policy_nonce: [u8; 32],
}

impl IndexContext {
    /// Checks the format rules shared by every record: owner-range handle and
    /// SHA-256 Names.
    pub fn is_valid(&self) -> bool {
        OWNER_RANGE.contains(&self.tpm_index)
            && self.name_postwrite[..2] == NAME_ALG_SHA256
            && self.name_prewrite.is_none_or(|n| n[..2] == NAME_ALG_SHA256)
    }
}

/// A stored token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// Always [`TEMPLATE_H2_P256`] in v1.
    pub template: u8,
    /// Fresh random nonce.
    pub nonce: [u8; TOKEN_NONCE_LEN],
    /// Ciphertext and tag.
    pub ct: [u8; TOKEN_CT_LEN],
}

const AAD_MAX: usize = 23 + 1 + 16 + 1 + 4 + 1 + NAME_LEN + NAME_LEN + 32;

fn aad(
    scope: Scope,
    vault_id: &[u8; 16],
    template: u8,
    ctx: &IndexContext,
    out: &mut [u8; AAD_MAX],
) -> usize {
    let mut at = 0;
    let mut put = |b: &[u8]| {
        out[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    };
    put(b"pvault/v1/tpm-id-token\0");
    put(&[scope as u8]);
    put(vault_id);
    put(&[template]);
    put(&ctx.tpm_index.to_be_bytes());
    match &ctx.name_prewrite {
        Some(n) => {
            put(&[1]);
            put(n);
        }
        None => put(&[0]),
    }
    put(&ctx.name_postwrite);
    put(&ctx.policy_nonce);
    at
}

fn cipher(scope: Scope, base_key: &SecretBytes<32>) -> Result<XChaCha20Poly1305, Error> {
    let key = kdf::hkdf_key(base_key, scope.label())?;
    XChaCha20Poly1305::new_from_slice(key.expose_secret()).map_err(|_| Error::TpmIdToken)
}

/// Encrypts `ek_digest` under `scope` with a fresh nonce.
pub fn seal(
    scope: Scope,
    base_key: &SecretBytes<32>,
    vault_id: &[u8; 16],
    ctx: &IndexContext,
    ek_digest: &SecretBytes<32>,
) -> Result<Token, Error> {
    seal_with_nonce(scope, base_key, vault_id, ctx, ek_digest, random::array()?)
}

pub(crate) fn seal_with_nonce(
    scope: Scope,
    base_key: &SecretBytes<32>,
    vault_id: &[u8; 16],
    ctx: &IndexContext,
    ek_digest: &SecretBytes<32>,
    nonce: [u8; TOKEN_NONCE_LEN],
) -> Result<Token, Error> {
    if !ctx.is_valid() {
        return Err(Error::TpmIdToken);
    }
    let mut a = [0u8; AAD_MAX];
    let n = aad(scope, vault_id, TEMPLATE_H2_P256, ctx, &mut a);
    let mut ct = [0u8; TOKEN_CT_LEN];
    ct[..32].copy_from_slice(ek_digest.expose_secret());
    let tag = cipher(scope, base_key)?
        .encrypt_inout_detached(&nonce.into(), &a[..n], (&mut ct[..32]).into())
        .map_err(|_| Error::TpmIdToken)?;
    ct[32..].copy_from_slice(&tag);
    Ok(Token {
        template: TEMPLATE_H2_P256,
        nonce,
        ct,
    })
}

/// Decrypts a token. Callers open a token only after the slots, core or
/// journal MAC that contains it has verified. Any failure is corruption and
/// never authorizes a deletion.
pub fn open(
    scope: Scope,
    base_key: &SecretBytes<32>,
    vault_id: &[u8; 16],
    ctx: &IndexContext,
    token: &Token,
) -> Result<SecretBytes<32>, Error> {
    if token.template != TEMPLATE_H2_P256 || !ctx.is_valid() {
        return Err(Error::TpmIdToken);
    }
    let mut a = [0u8; AAD_MAX];
    let n = aad(scope, vault_id, token.template, ctx, &mut a);
    let mut out = SecretBytes::<32>::zeroed();
    out.expose_secret_mut().copy_from_slice(&token.ct[..32]);
    let tag: [u8; 16] = token.ct[32..].try_into().map_err(|_| Error::TpmIdToken)?;
    cipher(scope, base_key)?
        .decrypt_inout_detached(
            &token.nonce.into(),
            &a[..n],
            (&mut out.expose_secret_mut()[..]).into(),
            &tag.into(),
        )
        .map_err(|_| Error::TpmIdToken)?;
    Ok(out)
}

/// Re-encrypts a token for another scope or key with a fresh nonce (bundle
/// rotation, rollback tracking). The plaintext digest is wiped on return.
pub fn rewrap(
    from: (Scope, &SecretBytes<32>),
    to: (Scope, &SecretBytes<32>),
    vault_id: &[u8; 16],
    ctx: &IndexContext,
    token: &Token,
) -> Result<Token, Error> {
    let digest = open(from.0, from.1, vault_id, ctx, token)?;
    seal(to.0, to.1, vault_id, ctx, &digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> IndexContext {
        let mut post = [0x11; NAME_LEN];
        post[..2].copy_from_slice(&NAME_ALG_SHA256);
        IndexContext {
            tpm_index: 0x0180_0001,
            name_prewrite: None,
            name_postwrite: post,
            policy_nonce: [0x22; 32],
        }
    }

    fn key(b: u8) -> SecretBytes<32> {
        SecretBytes::take_from(&mut [b; 32]).unwrap()
    }

    #[test]
    fn round_trip_and_scope_separation() {
        let digest = key(0x5a);
        let t = seal(Scope::Slots, &key(1), &[9; 16], &ctx(), &digest).unwrap();
        let back = open(Scope::Slots, &key(1), &[9; 16], &ctx(), &t).unwrap();
        assert_eq!(back.expose_secret(), digest.expose_secret());
        // Another scope, key, vault or context cannot open it.
        assert!(open(Scope::Cleanup, &key(1), &[9; 16], &ctx(), &t).is_err());
        assert!(open(Scope::Slots, &key(2), &[9; 16], &ctx(), &t).is_err());
        assert!(open(Scope::Slots, &key(1), &[8; 16], &ctx(), &t).is_err());
        let mut other = ctx();
        other.policy_nonce[0] ^= 1;
        assert!(open(Scope::Slots, &key(1), &[9; 16], &other, &t).is_err());
        let mut with_pre = ctx();
        with_pre.name_prewrite = Some(ctx().name_postwrite);
        assert!(open(Scope::Slots, &key(1), &[9; 16], &with_pre, &t).is_err());
        let mut bad_template = t;
        bad_template.template = 2;
        assert!(open(Scope::Slots, &key(1), &[9; 16], &ctx(), &bad_template).is_err());
    }

    #[test]
    fn rewrap_survives_repeated_rotation_without_the_tpm() {
        let digest = key(0x77);
        let t0 = seal(Scope::Slots, &key(1), &[3; 16], &ctx(), &digest).unwrap();
        let t1 = rewrap(
            (Scope::Slots, &key(1)),
            (Scope::Cleanup, &key(2)),
            &[3; 16],
            &ctx(),
            &t0,
        )
        .unwrap();
        let t2 = rewrap(
            (Scope::Cleanup, &key(2)),
            (Scope::Cleanup, &key(3)),
            &[3; 16],
            &ctx(),
            &t1,
        )
        .unwrap();
        assert_ne!(t1.nonce, t2.nonce);
        let back = open(Scope::Cleanup, &key(3), &[3; 16], &ctx(), &t2).unwrap();
        assert_eq!(back.expose_secret(), digest.expose_secret());
    }

    #[test]
    fn invalid_contexts_are_refused() {
        let mut c = ctx();
        c.tpm_index = 0x0100_0000;
        assert!(seal(Scope::Init, &key(1), &[0; 16], &c, &key(2)).is_err());
        let mut c = ctx();
        c.name_postwrite[1] = 0x04; // SHA-1 Name
        assert!(seal(Scope::Init, &key(1), &[0; 16], &c, &key(2)).is_err());
    }
}
