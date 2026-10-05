//! Writes valid seed inputs for the `fuzz/` targets (spec 12), so fuzzing
//! starts from canonical structures instead of random bytes. Run with
//! `PVAULT_FUZZ_SEEDS=<dir> cargo test -p pvault-core --lib fuzz_seeds -- --ignored`.

use std::path::Path;

use crate::crypto::cascade::{self, StreamHeader, StreamKeys, StreamKind};
use crate::header::tests::{cleanup, sample_bound_slots, sample_core};
use crate::header::{Header, Mode, PassphraseKind, PortableSlots, SlotFields};
use crate::journal::tests::{advance, key, prepared, sealed};
use crate::journal::{InitPhase, InitRecord, Record, TransitionPhase};
use crate::keytable::KeyTable;
use crate::keytable::tests::{dir, file, sample};
use crate::secrets::SecretBytes;

fn write(dir: &Path, target: &str, name: &str, bytes: &[u8]) {
    let d = dir.join(target);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(name), bytes).unwrap();
}

#[test]
#[ignore = "writes fuzz seeds to PVAULT_FUZZ_SEEDS"]
fn fuzz_seeds() {
    let Some(out) = std::env::var_os("PVAULT_FUZZ_SEEDS") else {
        return;
    };
    let out = Path::new(&out);
    let k = key(1);

    let mut core = sample_core(Mode::Bound, PassphraseKind::Words);
    write(
        out,
        "header_parse",
        "bound",
        &Header::build(&core, &sample_bound_slots(true), &k).unwrap(),
    );
    core.add_cleanup(cleanup(0x0180_0001, true)).unwrap();
    core.add_cleanup(cleanup(0x0180_0002, false)).unwrap();
    write(
        out,
        "header_parse",
        "bound-cleanup",
        &Header::build(&core, &sample_bound_slots(false), &k).unwrap(),
    );
    let portable = sample_core(Mode::Portable, PassphraseKind::Custom);
    let slots = SlotFields::Portable(PortableSlots {
        slot_nonce: [1; 24],
        slot_ct: [2; 96],
        duress_tag: None,
    });
    write(
        out,
        "header_parse",
        "portable",
        &Header::build(&portable, &slots, &k).unwrap(),
    );

    let new = key(2);
    let p = prepared(Mode::Bound);
    let tc = advance(p.clone(), TransitionPhase::TargetCreated);
    let cm = advance(tc.clone(), TransitionPhase::Committing);
    let tr = advance(cm.clone(), TransitionPhase::TrackingCreated);
    let rt = advance(tr.clone(), TransitionPhase::RollbackTracking);
    for (name, r) in [
        ("prepared", p),
        ("target_created", tc),
        ("committing", cm),
        ("tracking_created", tr),
        ("rollback_tracking", rt),
    ] {
        write(out, "journal_parse", name, &sealed(r, &k, &new));
    }
    write(
        out,
        "journal_parse",
        "portable",
        &sealed(prepared(Mode::Portable), &k, &new),
    );
    let mut init = Record::Init(InitRecord {
        phase: InitPhase::Prepared,
        vault_id: [1; 16],
        setup_id: [2; 16],
        mode: Mode::Portable,
        salt: [3; 32],
        argon2: crate::crypto::kdf::Argon2Params::DEFAULT,
        passphrase_kind: PassphraseKind::Words,
        idx: None,
        keytable_id: None,
        keytable_digest: None,
        new_core_digest: None,
        header_id: None,
        mac: [0; 64],
    });
    init.seal(&k, None).unwrap();
    write(out, "journal_parse", "init", &init.encode());

    let table = sample().encode().unwrap();
    write(out, "keytable_parse", "sample", table.expose_secret());
    // Multi-byte paths, including four-byte components ending inside a
    // character (the reserved-name check once sliced those by bytes).
    let unicode = KeyTable::from_entries(vec![
        dir("caf\u{e9}"),
        file("caf\u{e9}/ab\u{e9}", 4),
        file("caf\u{e9}/x\u{20ac}", 5),
        dir("na\u{ef}ve \u{1f600}"),
    ])
    .unwrap()
    .encode()
    .unwrap();
    write(out, "keytable_parse", "unicode", unicode.expose_secret());

    let keys = StreamKeys::new(
        SecretBytes::take_from(&mut [1; 32]).unwrap(),
        SecretBytes::take_from(&mut [2; 32]).unwrap(),
    );
    for (name, len) in [("empty", 0usize), ("small", 100), ("two-chunks", 70_000)] {
        let plain = vec![0x5a; len];
        let header = StreamHeader {
            kind: StreamKind::Object,
            stream_id: [3; 16],
            context: 0,
            plain_size: len as u64,
        };
        let mut ct = Vec::new();
        cascade::encrypt(&keys, &header, &plain[..], &mut ct).unwrap();
        write(out, "stream_parse", name, &ct);
    }
}
