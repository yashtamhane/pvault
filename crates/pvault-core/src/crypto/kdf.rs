//! Passphrase and subkey derivation (spec Section 5.1).
//!
//! `master_pw = Argon2id(version 0x13, normalized passphrase, core.salt, m, t, p)`,
//! with no secret and no associated data, producing 32 bytes. Subkeys are
//! `HKDF-SHA-512(ikm, salt = none, info, L = 32)`.
//!
//! Argon2id working memory is owned by pvault, not by the `argon2` crate: the
//! crate's own allocation is freed without being wiped, so this module
//! allocates the block buffer itself and wipes it on every exit path
//! (spec Section 10.2).
//!
//! This module enforces only the Argon2 hard caps of spec Section 4.3. The
//! total-RAM policy limit and the available-memory check are applied by the
//! callers that open a vault (Milestone 3).

use argon2::{Algorithm, Argon2, Block, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::errors::Error;
use crate::secrets::{SecretBuf, SecretBytes};

/// Length of every derived key, in bytes.
pub const KEY_LEN: usize = 32;

/// Length of `core.salt`, in bytes.
pub const SALT_LEN: usize = 32;

/// Argon2id cost parameters, with memory in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u32,
}

impl Argon2Params {
    /// Defaults for new vaults (spec Section 7.3): 1 GiB, 4 passes, 4 lanes.
    pub const DEFAULT: Self = Self {
        m_kib: 1_048_576,
        t: 4,
        p: 4,
    };

    /// Smallest permitted memory cost: 256 MiB.
    pub const M_KIB_MIN: u32 = 262_144;
    /// Largest permitted memory cost: 4 GiB.
    pub const M_KIB_MAX: u32 = 4_194_304;
    /// Permitted range of passes.
    pub const T_RANGE: core::ops::RangeInclusive<u32> = 3..=16;
    /// Permitted range of lanes.
    pub const P_RANGE: core::ops::RangeInclusive<u32> = 1..=8;

    /// Checks the hard caps of spec Section 4.3. Runs before any allocation.
    pub fn check_hard_caps(&self) -> Result<(), Error> {
        let in_caps = (Self::M_KIB_MIN..=Self::M_KIB_MAX).contains(&self.m_kib)
            && Self::T_RANGE.contains(&self.t)
            && Self::P_RANGE.contains(&self.p);
        if in_caps {
            Ok(())
        } else {
            Err(Error::KdfParams)
        }
    }
}

/// Argon2id block memory that is wiped before it is freed, including on
/// error and while unwinding.
struct WipedBlocks(Vec<Block>);

impl Drop for WipedBlocks {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Derives `master_pw` from an already-normalized passphrase (spec 5.1, 7.3).
pub fn master_pw(
    passphrase: &SecretBuf,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<SecretBytes<KEY_LEN>, Error> {
    params.check_hard_caps()?;
    let argon_params = argon2::Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| Error::KdfParams)?;

    let block_count = argon_params.block_count();
    let mut memory = WipedBlocks(Vec::new());
    memory
        .0
        .try_reserve_exact(block_count)
        .map_err(|_| Error::OutOfMemory)?;
    memory.0.resize(block_count, Block::default());

    let mut out = SecretBytes::<KEY_LEN>::zeroed();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into_with_memory(
            passphrase.expose_secret(),
            salt,
            out.expose_secret_mut(),
            memory.0.as_mut_slice(),
        )
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

/// The passphrase-derived subkeys of spec Section 5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKey {
    /// `k_s1wrap` (bound).
    S1Wrap,
    /// `k_s2wrap` (bound).
    S2Wrap,
    /// `tpm_auth` (bound).
    TpmAuth,
    /// `k_slot` (portable).
    PortableSlot,
    /// `duress_key` (both modes).
    Duress,
}

impl PassphraseKey {
    /// The HKDF `info` string for this subkey.
    pub const fn info(self) -> &'static [u8] {
        match self {
            Self::S1Wrap => b"pvault/v1/s1-wrap",
            Self::S2Wrap => b"pvault/v1/s2-wrap",
            Self::TpmAuth => b"pvault/v1/tpm-auth",
            Self::PortableSlot => b"pvault/v1/portable-slot",
            Self::Duress => b"pvault/v1/duress",
        }
    }
}

/// Derives one passphrase subkey from `master_pw`.
pub fn passphrase_subkey(
    master_pw: &SecretBytes<KEY_LEN>,
    which: PassphraseKey,
) -> Result<SecretBytes<KEY_LEN>, Error> {
    hkdf32(master_pw.expose_secret(), which.info())
}

/// Derives `journal_key` from `K_mac` (spec Section 5.1).
pub fn journal_key(k_mac: &SecretBytes<KEY_LEN>) -> Result<SecretBytes<KEY_LEN>, Error> {
    hkdf32(k_mac.expose_secret(), b"pvault/v1/journal")
}

/// Derives `init_journal_key` from `master_pw` (spec 8.3; D6): the same
/// single Argon2id result that keys the future vault.
pub fn init_journal_key(master_pw: &SecretBytes<KEY_LEN>) -> Result<SecretBytes<KEY_LEN>, Error> {
    hkdf32(master_pw.expose_secret(), b"pvault/v1/init-journal")
}

/// HKDF-SHA-512 with no salt and `L = 32`, for keys whose `info` is defined
/// elsewhere (for example the TPM-identity token scopes, spec 8.1).
pub fn hkdf_key(ikm: &SecretBytes<KEY_LEN>, info: &[u8]) -> Result<SecretBytes<KEY_LEN>, Error> {
    hkdf32(ikm.expose_secret(), info)
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> Result<SecretBytes<KEY_LEN>, Error> {
    let mut out = SecretBytes::<KEY_LEN>::zeroed();
    hkdf_sha512(None, ikm, info, out.expose_secret_mut())?;
    Ok(out)
}

/// HKDF-SHA-512 extract and expand into `okm`.
fn hkdf_sha512(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    Hkdf::<Sha512>::new(salt, ikm)
        .expand(info, okm)
        .map_err(|_| Error::Kdf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{field, hex, hex_field, records};

    fn params_of(v: &crate::testvec::Record) -> Argon2Params {
        Argon2Params {
            m_kib: field(v, "m_kib").parse().unwrap(),
            t: field(v, "t").parse().unwrap(),
            p: field(v, "p").parse().unwrap(),
        }
    }

    #[test]
    fn pvault_kdf_vectors() {
        let vectors = records(include_str!("../../testdata/pvault_kdf.txt"));
        assert_eq!(vectors.len(), 2);
        for v in &vectors {
            let passphrase = SecretBuf::take_from(&mut hex_field(v, "passphrase_utf8"));
            let salt: [u8; SALT_LEN] = hex_field(v, "salt").try_into().unwrap();
            let master = master_pw(&passphrase, &salt, params_of(v)).unwrap();
            assert_eq!(master.expose_secret().as_slice(), hex_field(v, "master_pw"));

            for (name, which) in [
                ("s1_wrap", PassphraseKey::S1Wrap),
                ("s2_wrap", PassphraseKey::S2Wrap),
                ("tpm_auth", PassphraseKey::TpmAuth),
                ("portable_slot", PassphraseKey::PortableSlot),
                ("duress", PassphraseKey::Duress),
            ] {
                let key = passphrase_subkey(&master, which).unwrap();
                assert_eq!(key.expose_secret().as_slice(), hex_field(v, name), "{name}");
            }

            let k_mac = SecretBytes::<KEY_LEN>::take_from(&mut hex_field(v, "k_mac")).unwrap();
            let journal = journal_key(&k_mac).unwrap();
            assert_eq!(
                journal.expose_secret().as_slice(),
                hex_field(v, "journal_key")
            );
        }
    }

    /// RFC 9106 section 5.3. The vector uses 32 KiB, a secret and associated
    /// data, none of which pvault permits, so it checks the `argon2` crate
    /// directly rather than through [`master_pw`].
    #[test]
    fn rfc9106_argon2id_vector() {
        let v = &records(include_str!("../../testdata/rfc9106_argon2id.txt"))[0];
        let secret = hex_field(v, "secret");
        let mut builder = argon2::ParamsBuilder::new();
        builder
            .m_cost(field(v, "m_kib").parse().unwrap())
            .t_cost(field(v, "t").parse().unwrap())
            .p_cost(field(v, "p").parse().unwrap())
            .output_len(32)
            .data(argon2::AssociatedData::new(&hex_field(v, "ad")).unwrap());
        let params = builder.build().unwrap();
        let mut memory = vec![Block::default(); params.block_count()];
        let argon =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut tag = [0u8; 32];
        argon
            .hash_password_into_with_memory(
                &hex_field(v, "password"),
                &hex_field(v, "salt"),
                &mut tag,
                memory.as_mut_slice(),
            )
            .unwrap();
        assert_eq!(tag.as_slice(), hex_field(v, "tag"));
    }

    #[test]
    fn wycheproof_hkdf_sha512() {
        let vectors = records(include_str!("../../testdata/wycheproof_hkdf_sha512.txt"));
        assert!(vectors.len() > 50);
        for v in &vectors {
            let size: usize = field(v, "size").parse().unwrap();
            let mut okm = vec![0u8; size];
            let result = hkdf_sha512(
                Some(&hex_field(v, "salt")),
                &hex_field(v, "ikm"),
                &hex_field(v, "info"),
                &mut okm,
            );
            match field(v, "result") {
                "valid" => {
                    result.unwrap();
                    assert_eq!(okm, hex_field(v, "okm"), "tcId {}", field(v, "tcId"));
                }
                _ => assert!(result.is_err(), "tcId {}", field(v, "tcId")),
            }
        }
    }

    #[test]
    fn empty_salt_equals_no_salt() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha512(None, b"ikm", b"info", &mut a).unwrap();
        hkdf_sha512(Some(&[]), b"ikm", b"info", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hard_caps_are_enforced_before_allocation() {
        let salt = [0u8; SALT_LEN];
        let passphrase = SecretBuf::take_from(&mut b"a b".to_vec());
        for params in [
            // 1 TiB must be refused without any attempt to allocate it.
            Argon2Params {
                m_kib: 1 << 30,
                t: 4,
                p: 4,
            },
            Argon2Params {
                m_kib: Argon2Params::M_KIB_MIN - 1,
                t: 4,
                p: 4,
            },
            Argon2Params {
                m_kib: Argon2Params::M_KIB_MAX + 1,
                t: 4,
                p: 4,
            },
            Argon2Params {
                m_kib: Argon2Params::M_KIB_MIN,
                t: 2,
                p: 4,
            },
            Argon2Params {
                m_kib: Argon2Params::M_KIB_MIN,
                t: 17,
                p: 4,
            },
            Argon2Params {
                m_kib: Argon2Params::M_KIB_MIN,
                t: 3,
                p: 0,
            },
            Argon2Params {
                m_kib: Argon2Params::M_KIB_MIN,
                t: 3,
                p: 9,
            },
        ] {
            assert!(matches!(
                master_pw(&passphrase, &salt, params),
                Err(Error::KdfParams)
            ));
        }
        Argon2Params::DEFAULT.check_hard_caps().unwrap();
    }

    #[test]
    fn labels_are_distinct() {
        let master = SecretBytes::<KEY_LEN>::take_from(&mut hex(&"11".repeat(32))).unwrap();
        let keys: Vec<_> = [
            PassphraseKey::S1Wrap,
            PassphraseKey::S2Wrap,
            PassphraseKey::TpmAuth,
            PassphraseKey::PortableSlot,
            PassphraseKey::Duress,
        ]
        .into_iter()
        .map(|which| *passphrase_subkey(&master, which).unwrap().expose_secret())
        .collect();
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
