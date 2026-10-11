use super::*;

/// The Names reported by `swtpm` in the E1 probe (an independent
/// implementation: the TPM computed them) for handle 0x01801234 and a
/// policy nonce of 32 bytes 0x11 (`docs/M5_READINESS.md` 12.2 check 4).
#[test]
fn names_equal_the_emulator_observation() {
    let (pre, post) = expected_names(0x0180_1234, &[0x11; 32]);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(
        hex(&pre),
        "000b015dd1a49cce12139979dcd5439c8daff83dd026251632760ad8c09691ad9232"
    );
    assert_eq!(
        hex(&post),
        "000bb8be497b1a6a38c90d717f908481207577494c61a8f76ecc8ce29121d5f4b246"
    );
}

/// D2: the per-command session table is pinned.
#[test]
fn session_table_is_pinned() {
    let t = |c: Command| (c.attrs().decrypt, c.attrs().encrypt);
    assert_eq!(t(Command::DefineSpace), (true, false));
    assert_eq!(t(Command::Write), (true, false));
    assert_eq!(t(Command::Read), (false, true));
    assert_eq!(t(Command::UndefineSpace), (false, false));
    for c in [
        Command::DefineSpace,
        Command::Write,
        Command::Read,
        Command::UndefineSpace,
    ] {
        assert_eq!(effective_attrs(c), c.attrs());
    }
}

#[test]
fn public_area_matching_is_exact() {
    let nonce = [7u8; 32];
    let good = |written: bool| NvPublicInfo {
        index: 0x0180_0001,
        name_alg: 0x000B,
        attributes: if written {
            ATTRS_POSTWRITE
        } else {
            ATTRS_PREWRITE
        },
        auth_policy: auth_policy(&nonce).to_vec(),
        data_size: DATA_SIZE,
        name: name(
            0x0180_0001,
            if written {
                ATTRS_POSTWRITE
            } else {
                ATTRS_PREWRITE
            },
            &nonce,
        )
        .to_vec(),
    };
    assert!(good(true).matches(0x0180_0001, &nonce, true));
    assert!(good(false).matches(0x0180_0001, &nonce, false));
    assert!(!good(false).matches(0x0180_0001, &nonce, true));
    let mut bad = good(true);
    bad.attributes |= 1 << 25; // NO_DA
    assert!(!bad.matches(0x0180_0001, &nonce, true));
    let mut bad = good(true);
    bad.data_size = 96;
    assert!(!bad.matches(0x0180_0001, &nonce, true));
    assert!(!good(true).matches(0x0180_0001, &[8; 32], true));
    let mut bad = good(true);
    bad.name[5] ^= 1;
    assert!(!bad.matches(0x0180_0001, &nonce, true));
}

/// C1 to C4 decoding, with the values swtpm reported in the E1 probe.
#[test]
fn capability_decoding() {
    let fresh = TpmState {
        permanent: 0x0000_0400,
        startup_clear: 0x8000_000f,
        lockout_counter: 0,
        max_auth_fail: 3,
    };
    assert!(fresh.duress_unavailable(true).is_empty());
    assert_eq!(
        fresh.duress_unavailable(false),
        ["the TPM identity cannot be measured"]
    );
    let owner = TpmState {
        permanent: 0x401,
        ..fresh
    };
    assert!(owner.owner_auth_set());
    assert_eq!(
        owner.duress_unavailable(true),
        ["owner authorization is set"]
    );
    let locked = TpmState {
        permanent: 0x600,
        ..fresh
    };
    assert!(locked.in_lockout());
    let no_sh = TpmState {
        startup_clear: 0x8000_000d,
        ..fresh
    };
    assert!(!no_sh.storage_enabled());
    let no_eh = TpmState {
        startup_clear: 0x8000_000b,
        ..fresh
    };
    assert!(!no_eh.endorsement_enabled());
    assert_eq!(
        no_eh.duress_unavailable(false),
        ["the endorsement hierarchy is disabled"]
    );
}

#[test]
fn targets_parse() {
    assert_eq!(TpmTarget::parse("device"), Some(TpmTarget::Device));
    assert_eq!(
        TpmTarget::parse("swtpm:2321"),
        Some(TpmTarget::Swtpm { port: 2321 })
    );
    for bad in [
        "",
        "swtpm:",
        "swtpm:0",
        "swtpm:x",
        "/dev/tpm0",
        "mssim:2321",
    ] {
        assert_eq!(TpmTarget::parse(bad), None, "{bad}");
    }
}

#[test]
fn h2_template_bytes() {
    assert_eq!(H2_TEMPLATE.len(), 58);
    assert_eq!(
        &H2_TEMPLATE[..8],
        &[0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x00, 0xF2]
    );
    assert_eq!(&H2_TEMPLATE[10..42], &POLICY_B_SHA256);
}

#[cfg(not(all(target_os = "linux", feature = "tpm")))]
#[test]
fn bound_mode_is_refused_without_tpm_support() {
    assert!(!supported());
    assert!(matches!(
        open(&TpmTarget::Swtpm { port: 2321 }),
        Err(Error::BoundVault)
    ));
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
mod emulator {
    use super::super::testing::{Recorder, Swtpm};
    use super::*;
    use crate::tpmid::NAME_LEN;
    use tss_esapi::traits::Marshall;

    fn secret32(b: u8) -> SecretBytes<32> {
        SecretBytes::take_from(&mut [b; 32]).unwrap()
    }

    fn data(b: u8) -> SecretBytes<97> {
        let mut d = [b; 97];
        d[0] = 2;
        SecretBytes::take_from(&mut d).unwrap()
    }

    /// D4: pvault's own H-2 template marshals to the pinned bytes.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn h2_template_is_built_by_pvault() {
        let t = super::super::esapi::h2_template().unwrap();
        assert_eq!(t.marshall().unwrap(), H2_TEMPLATE);
    }

    /// F30 and the 9.1 public area; read back through an encrypt session.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn define_write_read_undefine() {
        let Some(sw) = Swtpm::start() else { return };
        let mut tpm = open(&sw.target()).unwrap();
        let nonce = [0x42; 32];
        let index = free_handle(tpm.as_mut()).unwrap();
        tpm.define(index, &nonce, &secret32(1), None).unwrap();
        let (pre, post) = expected_names(index, &nonce);
        let p = tpm.read_public(index).unwrap().unwrap();
        assert!(p.matches(index, &nonce, false), "{p:?}");
        assert_eq!(p.name, pre);
        tpm.write(index, &secret32(1), &data(9)).unwrap();
        let p = tpm.read_public(index).unwrap().unwrap();
        assert!(p.matches(index, &nonce, true), "{p:?}");
        assert_eq!(p.name, post);
        assert_eq!(p.name.len(), NAME_LEN);
        let got = tpm.read(index, &secret32(1)).unwrap();
        assert_eq!(got.expose_secret(), data(9).expose_secret());
        tpm.undefine(index, None).unwrap();
        assert!(tpm.read_public(index).unwrap().is_none());
    }

    /// F87 at the TPM layer: a raced handle is `TpmHandleTaken`, and the
    /// existing index is untouched.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn raced_handle_is_reported_and_untouched() {
        let Some(sw) = Swtpm::start() else { return };
        let mut tpm = open(&sw.target()).unwrap();
        let index = 0x0180_7777;
        tpm.define(index, &[1; 32], &secret32(1), None).unwrap();
        let before = tpm.read_public(index).unwrap();
        assert!(matches!(
            tpm.define(index, &[2; 32], &secret32(2), None),
            Err(Error::TpmHandleTaken)
        ));
        assert_eq!(tpm.read_public(index).unwrap(), before);
    }

    /// F2 and F19: a wrong `tpm_auth` is the generic failure and increments
    /// the DA counter; lockout is reported as such.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn wrong_auth_counts_and_locks_out() {
        let Some(sw) = Swtpm::start() else { return };
        sw.short_lockout(2);
        let mut tpm = open(&sw.target()).unwrap();
        let index = 0x0180_1000;
        tpm.define(index, &[3; 32], &secret32(1), None).unwrap();
        tpm.write(index, &secret32(1), &data(1)).unwrap();
        assert_eq!(tpm.state().unwrap().lockout_counter, 0);
        assert!(matches!(
            tpm.read(index, &secret32(9)),
            Err(Error::HeaderInvalid)
        ));
        assert_eq!(tpm.state().unwrap().lockout_counter, 1);
        assert!(matches!(
            tpm.read(index, &secret32(9)),
            Err(Error::HeaderInvalid)
        ));
        assert!(tpm.state().unwrap().in_lockout());
        assert!(matches!(
            tpm.read(index, &secret32(1)),
            Err(Error::TpmLockout)
        ));
    }

    /// C1 to C4 after each setup (D12), and the define refusals.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn capability_setups() {
        let Some(sw) = Swtpm::start() else { return };
        let mut tpm = open(&sw.target()).unwrap();
        let s = tpm.state().unwrap();
        assert!(s.duress_unavailable(true).is_empty(), "{s:?}");
        let ek = tpm.ek_digest().unwrap();
        assert_eq!(tpm.ek_digest().unwrap(), ek, "one TPM state, one identity");
        drop(tpm);
        let Some(other) = Swtpm::start() else { return };
        assert_ne!(open(&other.target()).unwrap().ek_digest().unwrap(), ek);

        let Some(sw) = Swtpm::start() else { return };
        sw.tool(&["tpm2_changeauth", "-c", "owner", "owner-test-auth"]);
        let mut tpm = open(&sw.target()).unwrap();
        assert!(tpm.state().unwrap().owner_auth_set());
        assert!(matches!(
            tpm.define(0x0180_2000, &[1; 32], &secret32(1), None),
            Err(Error::TpmOwnerAuthRejected)
        ));
        let owner = crate::secrets::SecretBuf::take_from(&mut b"owner-test-auth".to_vec());
        tpm.define(0x0180_2000, &[1; 32], &secret32(1), Some(&owner))
            .unwrap();
        tpm.undefine(0x0180_2000, Some(&owner)).unwrap();

        let Some(sw) = Swtpm::start() else { return };
        sw.tool(&["tpm2_hierarchycontrol", "-C", "p", "shEnable", "clear"]);
        let mut tpm = open(&sw.target()).unwrap();
        assert!(!tpm.state().unwrap().storage_enabled());
        assert!(matches!(
            tpm.define(0x0180_2000, &[1; 32], &secret32(1), None),
            Err(Error::TpmHierarchyDisabled)
        ));

        let Some(sw) = Swtpm::start() else { return };
        sw.tool(&["tpm2_changeauth", "-c", "endorsement", "e-test-auth"]);
        let mut tpm = open(&sw.target()).unwrap();
        assert!(tpm.state().unwrap().endorsement_auth_set());
        assert!(matches!(tpm.ek_digest(), Err(Error::TpmIdentity)));

        let Some(sw) = Swtpm::start() else { return };
        sw.tool(&["tpm2_hierarchycontrol", "-C", "p", "ehEnable", "clear"]);
        let mut tpm = open(&sw.target()).unwrap();
        assert!(!tpm.state().unwrap().endorsement_enabled());
        assert!(matches!(tpm.ek_digest(), Err(Error::TpmIdentity)));
    }

    /// F103: on a controlled transport, `tpm_auth`, the written data, the
    /// read data and the owner authorization never appear; with encryption
    /// deliberately disabled (test builds only) they do, which proves the
    /// capture works.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn parameter_encryption_on_the_wire() {
        let Some(sw) = Swtpm::start() else { return };
        sw.tool(&[
            "tpm2_changeauth",
            "-c",
            "owner",
            "owner-auth-marker-0123456789",
        ]);
        let owner =
            crate::secrets::SecretBuf::take_from(&mut b"owner-auth-marker-0123456789".to_vec());
        let auth = [0xA7u8; 32];
        let mut payload = [0u8; 97];
        payload[0] = 2;
        for (i, b) in payload[1..].iter_mut().enumerate() {
            *b = 0x30 + (i % 61) as u8;
        }
        let secret_auth = || SecretBytes::<32>::take_from(&mut auth.clone()).unwrap();
        let secret_data = || SecretBytes::<97>::take_from(&mut payload.clone()).unwrap();
        let run = |weak: bool| {
            let rec = Recorder::start(&sw);
            weaken_for_test(weak);
            let mut tpm = open(&rec.target()).unwrap();
            let index = if weak { 0x0180_3002 } else { 0x0180_3001 };
            tpm.define(index, &[5; 32], &secret_auth(), Some(&owner))
                .unwrap();
            tpm.write(index, &secret_auth(), &secret_data()).unwrap();
            let back = tpm.read(index, &secret_auth()).unwrap();
            assert_eq!(back.expose_secret(), &payload);
            tpm.undefine(index, Some(&owner)).unwrap();
            drop(tpm);
            weaken_for_test(false);
            rec
        };
        let protected = run(false);
        assert!(
            protected.bytes().len() > 1000,
            "the capture recorded the session"
        );
        assert!(!protected.saw(&auth), "tpm_auth on the wire");
        assert!(!protected.saw(&payload[1..]), "S2 data on the wire");
        assert!(
            !protected.saw(b"owner-auth-marker"),
            "owner auth on the wire"
        );
        // Negative case: without parameter encryption the same values show.
        let weak = run(true);
        assert!(
            weak.saw(&auth),
            "capture must see tpm_auth without encryption"
        );
        assert!(
            weak.saw(&payload[1..]),
            "capture must see the data without encryption"
        );
        // Authorization values key HMACs; they are never sent, even weak.
        assert!(!weak.saw(b"owner-auth-marker"));
    }

    /// A raw response code survives the conversion used for layering.
    #[test]
    #[ignore = "starts processes: runs in its own test process (test_process)"]
    fn response_codes_are_classified_by_layer() {
        let Some(sw) = Swtpm::start() else { return };
        let mut tpm = open(&sw.target()).unwrap();
        assert!(
            tpm.read_public(0x0180_0042).unwrap().is_none(),
            "TPM_RC_HANDLE is absent"
        );
        drop(tpm);
        let rec = Recorder::start(&sw);
        let mut tpm = open(&rec.target()).unwrap();
        tpm.state().unwrap();
        drop(sw); // the emulator goes away: a transport failure
        assert!(matches!(
            tpm.define(0x0180_0043, &[1; 32], &secret32(1), None),
            Err(Error::TpmDefineUnknown | Error::TpmSession)
        ));
    }
}
