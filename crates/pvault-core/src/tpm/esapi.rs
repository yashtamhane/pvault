//! The `tss-esapi` backend (Linux, feature `tpm`; D1). Calls and their
//! behavior were checked on `swtpm` by the E1 probe
//! (`docs/M5_READINESS.md` 12.2).
//!
//! Every command that carries a secret runs in a salted HMAC session whose
//! attributes come from [`Command::attrs`]; pvault sets them itself and
//! flushes each session exactly once (D2). The salting key is a transient
//! ECC P-256 restricted decryption primary in the NULL hierarchy, created
//! with an empty password session (the NULL hierarchy's authorization is
//! always empty). There is no fallback: a failure aborts the command.

use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use tss_esapi::Context;
use tss_esapi::attributes::{
    NvIndexAttributesBuilder, ObjectAttributesBuilder, SessionAttributesBuilder,
};
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::{CapabilityType, PropertyTag, SessionType};
use tss_esapi::handles::{
    KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, SessionHandle, TpmHandle,
};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, CapabilityData, Digest, EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme,
    MaxNvBuffer, NvPublicBuilder, Public, PublicBuilder, PublicEccParametersBuilder,
    SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::Marshall;

use super::{
    ATTRS_PREWRITE, Command, DATA_SIZE, NvPublicInfo, POLICY_B_SHA256, Tpm, TpmState, TpmTarget,
    auth_policy,
};
use crate::errors::Error;
use crate::secrets::{SecretBuf, SecretBytes};

/// The raw `TSS2_RC` of an error (layer in bits 16 to 23; 0 is the TPM).
/// `tss-esapi` 7.7.0 keeps the value private; its `Debug` form shows it.
fn raw_rc(e: &tss_esapi::Error) -> Option<u32> {
    let tss_esapi::Error::Tss2Error(rc) = e else {
        return None;
    };
    let d = format!("{rc:?}");
    let start = d.find(".0: ")? + 4;
    let digits: String = d[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The TPM-layer response kind, or `None` for errors raised by the TSS
/// stack or the transport (any other layer).
fn tpm_kind(e: &tss_esapi::Error) -> Option<Tss2ResponseCodeKind> {
    let raw = raw_rc(e)?;
    if (raw >> 16) & 0xff != 0 {
        return None;
    }
    match e {
        tss_esapi::Error::Tss2Error(rc) => rc.kind(),
        tss_esapi::Error::WrapperError(_) => None,
    }
}

/// A short, secret-free description for [`Error::Tpm`].
fn describe(e: &tss_esapi::Error) -> String {
    match raw_rc(e) {
        Some(raw) => format!("TPM response 0x{raw:08x}"),
        None => "TPM software error".to_owned(),
    }
}

/// Maps errors common to every command; anything else is [`Error::Tpm`].
fn common(e: &tss_esapi::Error) -> Error {
    match tpm_kind(e) {
        Some(Tss2ResponseCodeKind::Lockout) => Error::TpmLockout,
        Some(Tss2ResponseCodeKind::Hierarchy) => Error::TpmHierarchyDisabled,
        _ => Error::Tpm(describe(e)),
    }
}

fn session_failed(_e: tss_esapi::Error) -> Error {
    Error::TpmSession
}

fn auth_of(bytes: &[u8]) -> Result<Auth, Error> {
    Auth::try_from(bytes.to_vec()).map_err(|_| Error::Tpm("authorization value too long".into()))
}

/// The H-2 template (spec 8.1), built field by field; checked against
/// [`super::H2_TEMPLATE`] by a test (D4). Never a library EK helper.
pub(super) fn h2_template() -> Result<Public, Error> {
    let fail = |_| Error::Tpm("EK template".into());
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_admin_with_policy(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(fail)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(Digest::try_from(POLICY_B_SHA256.to_vec()).map_err(fail)?)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()
                .map_err(fail)?,
        )
        .with_ecc_unique_identifier(EccPoint::new(
            EccParameter::try_from(Vec::<u8>::new()).map_err(fail)?,
            EccParameter::try_from(Vec::<u8>::new()).map_err(fail)?,
        ))
        .build()
        .map_err(fail)
}

/// The salting key's template: ECC P-256 restricted decryption key.
fn salting_template() -> Result<Public, Error> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(session_failed)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()
                .map_err(session_failed)?,
        )
        .with_ecc_unique_identifier(EccPoint::new(
            EccParameter::try_from(Vec::<u8>::new()).map_err(session_failed)?,
            EccParameter::try_from(Vec::<u8>::new()).map_err(session_failed)?,
        ))
        .build()
        .map_err(session_failed)
}

/// A connected TPM.
pub(super) struct Esapi {
    ctx: Context,
    salting: Option<KeyHandle>,
}

impl Esapi {
    pub(super) fn open(target: &TpmTarget) -> Result<Self, Error> {
        let conf = match target {
            TpmTarget::Device => {
                // Development uses swtpm only (spec 0 item 8; E2): tests
                // never reach a real TPM.
                #[cfg(test)]
                panic!("tests must not open a real TPM");
                #[cfg(not(test))]
                TctiNameConf::from_str("device:/dev/tpmrm0")
            }
            TpmTarget::Swtpm { port } => {
                TctiNameConf::from_str(&format!("swtpm:host=127.0.0.1,port={port}"))
            }
        }
        .map_err(|_| Error::TpmUnavailable(target.to_string()))?;
        let ctx = Context::new(conf).map_err(|_| Error::TpmUnavailable(target.to_string()))?;
        Ok(Self { ctx, salting: None })
    }

    fn salting_key(&mut self) -> Result<KeyHandle, Error> {
        if let Some(k) = self.salting {
            return Ok(k);
        }
        let template = salting_template()?;
        let key = self
            .ctx
            .execute_with_nullauth_session(|c| {
                c.create_primary(Hierarchy::Null, template, None, None, None, None)
            })
            .map_err(|e| match tpm_kind(&e) {
                Some(Tss2ResponseCodeKind::Lockout) => Error::TpmLockout,
                _ => Error::TpmSession,
            })?
            .key_handle;
        self.salting = Some(key);
        Ok(key)
    }

    /// A salted HMAC session with exactly the attributes of `cmd`.
    fn session(&mut self, cmd: Command) -> Result<AuthSession, Error> {
        let key = self.salting_key()?;
        let session = self
            .ctx
            .start_auth_session(
                Some(key),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(session_failed)?
            .ok_or(Error::TpmSession)?;
        let a = super::effective_attrs(cmd);
        let (attrs, mask) = SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_decrypt(a.decrypt)
            .with_encrypt(a.encrypt)
            .build();
        if let Err(e) = self.ctx.tr_sess_set_attributes(session, attrs, mask) {
            self.flush_session(session);
            return Err(session_failed(e));
        }
        Ok(session)
    }

    fn flush_session(&mut self, session: AuthSession) {
        let _ = self
            .ctx
            .flush_context(ObjectHandle::from(SessionHandle::from(session)));
    }

    /// The ESYS object for an NV index, or `None` when nothing is defined.
    fn nv_handle(&mut self, index: u32) -> Result<Option<ObjectHandle>, Error> {
        let tpm_handle = NvIndexTpmHandle::new(index).map_err(|_| Error::Tpm("handle".into()))?;
        match self
            .ctx
            .execute_without_session(|c| c.tr_from_tpm_public(TpmHandle::NvIndex(tpm_handle)))
        {
            Ok(h) => Ok(Some(h)),
            Err(e) if tpm_kind(&e) == Some(Tss2ResponseCodeKind::Handle) => Ok(None),
            Err(e) => Err(common(&e)),
        }
    }

    fn close(&mut self, mut h: ObjectHandle) {
        let _ = self.ctx.tr_close(&mut h);
    }

    fn set_owner_auth(&mut self, owner: Option<&SecretBuf>) -> Result<(), Error> {
        let bytes = owner.map(|o| o.expose_secret()).unwrap_or(&[]);
        self.ctx
            .tr_set_auth(ObjectHandle::Owner, auth_of(bytes)?)
            .map_err(|e| common(&e))
    }
}

impl Drop for Esapi {
    fn drop(&mut self) {
        if let Some(k) = self.salting.take() {
            let _ = self.ctx.flush_context(ObjectHandle::from(k));
        }
    }
}

impl Tpm for Esapi {
    fn state(&mut self) -> Result<TpmState, Error> {
        // TPM_PT_PERMANENT (0x200) .. TPM_PT_MAX_AUTH_FAIL (0x20F).
        let (data, _) = self
            .ctx
            .get_capability(CapabilityType::TpmProperties, 0x200, 16)
            .map_err(|e| common(&e))?;
        let CapabilityData::TpmProperties(list) = data else {
            return Err(Error::Tpm("capability data".into()));
        };
        let get = |t: PropertyTag| list.find(t).map(|p| p.value());
        Ok(TpmState {
            permanent: get(PropertyTag::Permanent).ok_or(Error::Tpm("TPM_PT_PERMANENT".into()))?,
            startup_clear: get(PropertyTag::StartupClear)
                .ok_or(Error::Tpm("TPM_PT_STARTUP_CLEAR".into()))?,
            lockout_counter: get(PropertyTag::LockoutCounter).unwrap_or(0),
            max_auth_fail: get(PropertyTag::MaxAuthFail).unwrap_or(0),
        })
    }

    fn ek_digest(&mut self) -> Result<[u8; 32], Error> {
        let template = h2_template()?;
        let result = self
            .ctx
            .execute_with_nullauth_session(|c| {
                c.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
            })
            .map_err(|_| Error::TpmIdentity)?;
        let marshalled = result.out_public.marshall();
        let _ = self
            .ctx
            .flush_context(ObjectHandle::from(result.key_handle));
        let marshalled = marshalled.map_err(|_| Error::TpmIdentity)?;
        Ok(Sha256::digest(&marshalled).into())
    }

    fn read_public(&mut self, index: u32) -> Result<Option<NvPublicInfo>, Error> {
        let Some(h) = self.nv_handle(index)? else {
            return Ok(None);
        };
        let r = self
            .ctx
            .execute_without_session(|c| c.nv_read_public(NvIndexHandle::from(h)));
        self.close(h);
        let (public, name) = r.map_err(|e| common(&e))?;
        let attributes = tss_esapi::tss2_esys::TPMA_NV::try_from(public.attributes())
            .map_err(|_| Error::Tpm("NV attributes".into()))?;
        Ok(Some(NvPublicInfo {
            index: u32::from(public.nv_index()),
            name_alg: u16::from(public.name_algorithm()),
            attributes,
            auth_policy: public.authorization_policy().value().to_vec(),
            data_size: u16::try_from(public.data_size()).unwrap_or(u16::MAX),
            name: name.value().to_vec(),
        }))
    }

    fn define(
        &mut self,
        index: u32,
        nonce: &[u8; 32],
        tpm_auth: &SecretBytes<32>,
        owner_auth: Option<&SecretBuf>,
    ) -> Result<(), Error> {
        let fail = |_| Error::Tpm("NV public area".into());
        let attrs = NvIndexAttributesBuilder::new()
            .with_auth_write(true)
            .with_auth_read(true)
            .build()
            .map_err(fail)?;
        debug_assert_eq!(
            tss_esapi::tss2_esys::TPMA_NV::try_from(attrs).ok(),
            Some(ATTRS_PREWRITE)
        );
        let public = NvPublicBuilder::new()
            .with_nv_index(NvIndexTpmHandle::new(index).map_err(fail)?)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attrs)
            .with_index_auth_policy(Digest::try_from(auth_policy(nonce).to_vec()).map_err(fail)?)
            .with_data_area_size(usize::from(DATA_SIZE))
            .build()
            .map_err(fail)?;
        self.set_owner_auth(owner_auth)?;
        let session = self.session(Command::DefineSpace)?;
        let auth = auth_of(tpm_auth.expose_secret())?;
        let r = self.ctx.execute_with_session(Some(session), |c| {
            c.nv_define_space(Provision::Owner, Some(auth), public)
        });
        self.flush_session(session);
        let _ = self.set_owner_auth(None);
        match r {
            Ok(h) => {
                self.close(ObjectHandle::from(h));
                Ok(())
            }
            Err(e) => Err(match tpm_kind(&e) {
                Some(Tss2ResponseCodeKind::NvDefined) => Error::TpmHandleTaken,
                Some(Tss2ResponseCodeKind::BadAuth | Tss2ResponseCodeKind::AuthFail) => {
                    Error::TpmOwnerAuthRejected
                }
                Some(Tss2ResponseCodeKind::Lockout) => Error::TpmLockout,
                Some(Tss2ResponseCodeKind::Hierarchy) => Error::TpmHierarchyDisabled,
                Some(Tss2ResponseCodeKind::NvSpace) => Error::Tpm(describe(&e)),
                // Anything raised outside the TPM (TSS stack, transport,
                // timeout) leaves the outcome unknown (SI-35, F88).
                None => Error::TpmDefineUnknown,
                Some(_) => Error::Tpm(describe(&e)),
            }),
        }
    }

    fn write(
        &mut self,
        index: u32,
        tpm_auth: &SecretBytes<32>,
        data: &SecretBytes<97>,
    ) -> Result<(), Error> {
        let h = self
            .nv_handle(index)?
            .ok_or(Error::Tpm("index missing".into()))?;
        let nv = NvIndexHandle::from(h);
        let r = (|| {
            self.ctx
                .tr_set_auth(h, auth_of(tpm_auth.expose_secret())?)
                .map_err(|e| common(&e))?;
            let session = self.session(Command::Write)?;
            let buffer = MaxNvBuffer::try_from(data.expose_secret().to_vec())
                .map_err(|_| Error::Tpm("NV buffer".into()))?;
            let r = self.ctx.execute_with_session(Some(session), |c| {
                c.nv_write(NvAuth::NvIndex(nv), nv, buffer, 0)
            });
            self.flush_session(session);
            r.map_err(|e| common(&e))
        })();
        self.close(h);
        r
    }

    fn read(&mut self, index: u32, tpm_auth: &SecretBytes<32>) -> Result<SecretBytes<97>, Error> {
        let h = self.nv_handle(index)?.ok_or(Error::HeaderInvalid)?;
        let nv = NvIndexHandle::from(h);
        let r = (|| {
            self.ctx
                .tr_set_auth(h, auth_of(tpm_auth.expose_secret())?)
                .map_err(|e| common(&e))?;
            let session = self.session(Command::Read)?;
            let r = self.ctx.execute_with_session(Some(session), |c| {
                c.nv_read(NvAuth::NvIndex(nv), nv, DATA_SIZE, 0)
            });
            self.flush_session(session);
            match r {
                Ok(buffer) => {
                    let mut bytes = buffer.value().to_vec();
                    SecretBytes::take_from(&mut bytes).map_err(|_| Error::HeaderInvalid)
                }
                Err(e) => Err(match tpm_kind(&e) {
                    Some(Tss2ResponseCodeKind::Lockout) => Error::TpmLockout,
                    // A wrong passphrase gives a wrong `tpm_auth`: the same
                    // generic failure as every other secret-dependent one.
                    Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                        Error::HeaderInvalid
                    }
                    _ => common(&e),
                }),
            }
        })();
        self.close(h);
        r
    }

    fn undefine(&mut self, index: u32, owner_auth: Option<&SecretBuf>) -> Result<(), Error> {
        let h = self
            .nv_handle(index)?
            .ok_or(Error::Tpm("index missing".into()))?;
        let nv = NvIndexHandle::from(h);
        self.set_owner_auth(owner_auth)?;
        let session = match self.session(Command::UndefineSpace) {
            Ok(s) => s,
            Err(e) => {
                self.close(h);
                return Err(e);
            }
        };
        let r = self
            .ctx
            .execute_with_session(Some(session), |c| c.nv_undefine_space(Provision::Owner, nv));
        self.flush_session(session);
        let _ = self.set_owner_auth(None);
        match r {
            // The ESYS object is gone with the index.
            Ok(()) => Ok(()),
            Err(e) => {
                self.close(h);
                Err(match tpm_kind(&e) {
                    Some(Tss2ResponseCodeKind::BadAuth | Tss2ResponseCodeKind::AuthFail) => {
                        Error::TpmOwnerAuthRejected
                    }
                    _ => common(&e),
                })
            }
        }
    }
}
