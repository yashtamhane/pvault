use super::*;
use crate::platform::fs::tests::tempdir;

fn settings() -> (PathBuf, Settings) {
    let tmp = tempdir();
    let s = Settings::open_at(&tmp.join("settings")).unwrap();
    (tmp, s)
}

fn recorded(dir: &Path, name: &str) -> (RecordedFile, File) {
    let d = Dir::open(dir).unwrap();
    let f = d.create_new(name).unwrap();
    let id = fs::record_identity(&f).unwrap();
    (
        RecordedFile {
            path: native_path(&dir.join(name)).unwrap(),
            id,
        },
        f,
    )
}

#[test]
fn rollback_record() {
    let (tmp, s) = settings();
    let v = [7u8; 16];
    assert_eq!(s.rollback_observe(&v, 5), RollbackOutcome::Recorded);
    assert_eq!(s.rollback_observe(&v, 6), RollbackOutcome::Recorded);
    assert_eq!(
        s.rollback_observe(&v, 4),
        RollbackOutcome::Older { recorded: 6 }
    );
    assert_eq!(s.rollback_recorded(&v).unwrap(), Some(6));
    // A damaged record is reported and never overwritten.
    std::fs::write(s.path().join("rollback.cbor"), b"\xa0junk").unwrap();
    assert!(matches!(
        s.rollback_observe(&v, 9),
        RollbackOutcome::Unavailable(_)
    ));
    assert_eq!(
        std::fs::read(s.path().join("rollback.cbor")).unwrap(),
        b"\xa0junk"
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn partial_records_round_trip_and_strictness() {
    let (tmp, s) = settings();
    let (file, _f) = recorded(&tmp, "x.pvpartial");
    let entry = PartialEntry {
        transfer_id: [1; 16],
        vault_id: [2; 16],
        created_at: 3,
        file,
    };
    s.register_partial(entry.clone()).unwrap();
    let bytes = std::fs::read(s.path().join("partials.cbor")).unwrap();
    assert_eq!(
        decode::<PartialEntry>(RecordKind::Partials, &bytes).unwrap(),
        vec![entry.clone()]
    );
    // Foreign kind, newer version, trailing bytes and an oversized file.
    let foreign = encode(RecordKind::Cards, &Vec::<CardEntry>::new());
    assert!(decode::<PartialEntry>(RecordKind::Partials, &foreign).is_err());
    let mut v2 = bytes.clone();
    let last = v2.len() - 1;
    v2[last] = 0x02; // version 2
    assert!(decode::<PartialEntry>(RecordKind::Partials, &v2).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode::<PartialEntry>(RecordKind::Partials, &trailing).is_err());
    std::fs::write(s.path().join("partials.cbor"), vec![0u8; (2 << 20) + 1]).unwrap();
    assert!(matches!(
        s.register_partial(entry.clone()),
        Err(Error::RecordDamaged(_))
    ));
    std::fs::write(s.path().join("partials.cbor"), &bytes).unwrap();
    s.unregister_partial(&[1; 16]).unwrap();
    let bytes = std::fs::read(s.path().join("partials.cbor")).unwrap();
    assert!(
        decode::<PartialEntry>(RecordKind::Partials, &bytes)
            .unwrap()
            .is_empty()
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// A registration flush failure is reported as not registered.
#[test]
fn registration_flush_failure() {
    let (tmp, s) = settings();
    let (file, _f) = recorded(&tmp, "y.pvpartial");
    let entry = PartialEntry {
        transfer_id: [9; 16],
        vault_id: [2; 16],
        created_at: 3,
        file,
    };
    crate::failpoints::inject("records.flush-file");
    assert!(matches!(
        s.register_partial(entry.clone()),
        Err(Error::NotRegistered("export"))
    ));
    crate::failpoints::inject("records.flush-dir");
    assert!(matches!(
        s.register_partial(entry),
        Err(Error::NotRegistered("export"))
    ));
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// Entries of a live operation are skipped; after its lock is released
/// (a crash), they are stale.
#[test]
fn stale_partials_follow_the_transfer_lock() {
    let (tmp, s) = settings();
    let lock = s.begin_operation(OpKind::Transfer).unwrap();
    let (file, _f) = recorded(&tmp, "z.pvpartial");
    s.register_partial(PartialEntry {
        transfer_id: lock.id(),
        vault_id: [2; 16],
        created_at: 3,
        file,
    })
    .unwrap();
    assert!(
        s.stale_partials(None).unwrap().is_empty(),
        "live export skipped"
    );
    drop(lock); // the OS releases the lock, as on a crash
    let stale = s.stale_partials(Some(&[2; 16])).unwrap();
    assert_eq!(stale.len(), 1);
    assert!(s.stale_partials(Some(&[3; 16])).unwrap().is_empty());
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// The after-restart identity rule (7.2).
#[test]
fn delete_recorded_identity_rule() {
    let tmp = tempdir();
    let (file, f) = recorded(&tmp, "a");
    drop(f);
    if file.id.btime.is_some() {
        // Replaced by another file: never deleted.
        std::fs::remove_file(tmp.join("a")).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(tmp.join("a"), b"other").unwrap();
        assert_eq!(delete_recorded(&file).unwrap(), StaleOutcome::Mismatch);
        assert!(tmp.join("a").exists());
        let (file, f) = recorded(&tmp, "b");
        drop(f);
        assert_eq!(delete_recorded(&file).unwrap(), StaleOutcome::Deleted);
        assert!(!tmp.join("b").exists());
        assert_eq!(delete_recorded(&file).unwrap(), StaleOutcome::Missing);
    }
    // No birth time recorded: never deleted after a restart.
    let (mut file, f) = recorded(&tmp, "c");
    drop(f);
    file.id.btime = None;
    assert_eq!(delete_recorded(&file).unwrap(), StaleOutcome::Unprovable);
    assert!(tmp.join("c").exists());
    // Same inode number but another device (a remount): never deleted.
    let (mut file, f) = recorded(&tmp, "d");
    drop(f);
    file.id.dev ^= 1;
    assert_ne!(delete_recorded(&file).unwrap(), StaleOutcome::Deleted);
    assert!(tmp.join("d").exists());
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[cfg(unix)]
#[test]
fn settings_folder_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempdir();
    let p = tmp.join("s");
    Settings::open_at(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Settings::open_at(&p),
        Err(Error::SettingsNotPrivate(_))
    ));
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// 7.7: concurrent writers, each with its own handles, never lose an entry.
#[test]
fn concurrent_writers_never_lose_an_entry() {
    let (tmp, s) = settings();
    let (file, _f) = recorded(&tmp, "c.pvpartial");
    let path = s.path().to_path_buf();
    std::thread::scope(|scope| {
        for t in 0..8u8 {
            let (path, file) = (path.clone(), file.clone());
            scope.spawn(move || {
                let own = Settings::open_at(&path).unwrap();
                for i in 0..10u8 {
                    let mut transfer_id = [0u8; 16];
                    transfer_id[0] = t;
                    transfer_id[1] = i;
                    own.register_partial(PartialEntry {
                        transfer_id,
                        vault_id: [4; 16],
                        created_at: 1,
                        file: file.clone(),
                    })
                    .unwrap();
                }
            });
        }
    });
    let all = {
        let _r = s.record_lock(RecordKind::Partials.lock(), false).unwrap();
        s.load::<PartialEntry>(RecordKind::Partials).unwrap()
    };
    assert_eq!(all.len(), 80);
    std::fs::remove_dir_all(&tmp).unwrap();
}

/// 7.1 on Windows: the owner-only DACL pvault creates reads back as private;
/// an access-allowed entry for Everyone makes the folder refused.
#[cfg(windows)]
#[test]
fn settings_folder_dacl_is_read_back() {
    let tmp = tempdir();
    let p = tmp.join("s");
    Settings::open_at(&p).unwrap();
    Settings::open_at(&p).expect("the DACL pvault created reads back as private");
    // Everyone by SID (S-1-1-0), independent of the system language.
    let st = std::process::Command::new("icacls")
        .arg(&p)
        .args(["/grant", "*S-1-1-0:(R)"])
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "icacls failed");
    assert!(matches!(
        Settings::open_at(&p),
        Err(Error::SettingsNotPrivate(_))
    ));
    std::fs::remove_dir_all(&tmp).unwrap();
}
