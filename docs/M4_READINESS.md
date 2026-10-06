# Milestone 4 readiness report

Prepared 2026-10-05, after Milestone 3 was accepted (commit `ff7c6ab`, which
records acceptance of `afa6a3f`; CI runs 37391563815 and 37401188580). Revised
the same day with the author's approved directions and the concrete designs.
**A1 to A7 were approved on 2026-10-05** (`docs/SPEC_ISSUES.md` 10.14);
Milestone 4 is implemented against them. Companion: `docs/CLI.md`.

Sources: `CLAUDE.md`, `PVAULT_BUILD_SPEC.md` (every section Milestone 4
touches), `docs/SPEC_ISSUES.md` (issue table; SI-09 to SI-11, SI-19, SI-30,
SI-33, SI-34, SI-38, SI-40, SI-46 to SI-51; sections 4 and 10.4 to 10.12) and
`docs/M3_READINESS.md`. Accepted decisions and documented limitations are
preserved; nothing settled is reopened without a stated defect.

**Contents:** 1 scope · 2 reuse · 3 approved directions · 4 sequence ·
5 contradictions · 6 tests and validation · 7 per-user records · 8 vault paths
at input · 9 `add`/`rm` (SI-40) · 10 source files · 11 card files (SI-10) ·
12 dependencies · 13 Q1 investigation · 14 Windows console checklist ·
15 decisions still open · 16 preserved decisions.

## 1. Scope, dependencies and acceptance

### 1.1 Scope (spec 13, row 4)

> Cards (7.4a to 7.4c: payload, Base32, SVG QR, PNG input, card files,
> published vectors). Portable mode: init (with full card verification),
> add, list, get, rm with crash-safe ordering and secure `.pvpartial`;
> `docs/CLI.md` approved first.

| Area | Spec | Content |
| --- | --- | --- |
| Card payload | 7.4a | 135-byte `PVC1` payload, `check`, field and combination rules; Crockford Base32 |
| Card rendering and input | 7.4a, 7.4c | SVG QR (byte mode, level M); PNG input under the 7.4c limits, wiped pixel buffers; `rqrr` |
| Card files | 7.4b, SI-10 | Section 11 |
| Published vectors | 7.4a | Payload, QR and Base32 vectors in `docs/FORMAT.md` before portable `init` relies on cards |
| Portable `init` | 8.3, 6.4, SI-51 | Bootstrap and preflight, four-phase init journal, cards with delivery verification, type-back, resume and residue rules |
| Portable unlock | 5.3, 5.7, 9.7 | Lock → header → Argon2 limits → passphrase and word check → Argon2id → duress check → journal check; slot unwrap; MACs; rollback check; key table |
| `add`, `rm` | 7.7, 7.8, 8.3, SI-40 | Sections 8 to 10 |
| `list`, `get` | 5.7, 7.9 | Shared lock after unlock; `.pvpartial` protocol; stale-export cleanup |
| `status`, `clean-partials` | 5.7, 7.9 | `docs/CLI.md` 6.6, 6.7 |

Out of scope (unchanged): bound mode and every TPM operation (5), duress setup
(5), recovery, `verify-card`, `convert`, `fsck` (6), strict memory mode and
timing (7), every `destructive/` feature (9), K2 (10), mount (11).

### 1.2 Acceptance tests

| Test | Milestone 4 part |
| --- | --- |
| F4 | One portable card cannot decrypt |
| F15, F16 | Copied portable vault unlocks; wrong passphrase gives `Unlock failed.` |
| F20 | Per-file `rm` |
| F26 | Crash at every step of `init`, `add`, `rm` (section 9.6 for `add`/`rm`) |
| F33, F72 | The `get` halves (their `fsck` halves are Milestone 6) |
| F50, F51, F67 | `.pvpartial` refusals, owner-only permissions, crash at each creation step |
| F61, F65 | Portable card payload and combination rules |
| F64 | Fresh IDs and keys; `--replace` |
| F70 | `clean-partials` during an export and after a kill; the card half after SI-10 approval |
| F73 | Input part (section 8) |
| F74 | Mutations refused on an unsupported file system; read-only commands work; a portable duress match modifies nothing |
| F75 | Normalization and word hint with no Argon2id run |
| F78 | Card files (section 11) |
| F79 | Secret input rules |
| Also | F92 (N5 limit at `add`), F89 (proposed with SI-40), F17 portable part, the SI-51 section 9 remainder (10.5) |

## 2. Existing implementation to reuse

| Need | Already built (accepted) | Gap |
| --- | --- | --- |
| Bundle, IDs, randomness | `crypto::random`, `SecretBytes`, `StreamKeys::generate` | None |
| Derivation, memory | `kdf::*` (wiped Argon2 memory), `resources::check_argon2` | None |
| Passphrases, input | `generate`, `handle_words` (`H_w_v1`), `check_word_list`, `handle_custom`, `duress_collides`, estimator child, `input`, `terminal` | CLI flows; Windows console validation (section 14) |
| Shamir, wraps, streams | `split_2_of_2`, `combine`, `wrap`, `cascade::encrypt` (exact length, refuses extra input), `decrypt` | Object and export plumbing |
| Header, key table, journal | `Header`, `CoreFields`, `PortableSlots`, `KeyTable` (N5, two-pass decode), init records, `promote_init` | `update` records (section 9) |
| Storage | `Owned`, `write_journal`, `load_journal`, `remove_journal`, `read_header`, `commit_header` (F58, failure boundary) | First-header commit with a no-replace rename; `update` restart |
| File system | `Dir` (handle-relative on Unix and Windows; refuses reparse points), identity, `remove_if_owned` (Windows deletes the verified handle), `preflight`, `same_volume`, Q1–Q4 | Destination folders outside the vault; owner-only Windows ACLs (M3-F5); ancestor check for "inside the vault" |
| Locks | `VaultLock` (G + L), once-per-process registry | Record, transfer and card-operation locks |
| Unicode | pvault-owned NFC buffer; `ucd17` (17.0.0 assigned set, NFKC, full case folding, `White_Space`) | Canonical caseless key (section 8) |
| Failpoints, fuzzing | `failpoint!`, `fail_io!`, F85; `fuzz/` | CLI feature forwarding; `pvault-tests`; `card_parse` |

## 3. Approved directions (author, 2026-10-05)

| Topic | Direction | Detail in |
| --- | --- | --- |
| Card text | No terminal display of recovery-card secrets. Hidden Base32 input is allowed. Secrets are never command-line arguments | CLI 2, section 11 |
| Paths | Vendored Unicode 17.0.0 canonical caseless matching for collisions; NFC normalization of input; refusal of unassigned characters. The approved Unicode-independent decoding of existing paths is unchanged | Section 8 |
| Duress | No duress setup in Milestone 4. A duress match fails without mutation. This is a temporary milestone limitation, documented | CLI 9 (K6) |
| `add` sources | Regular files only; `created_at` = time added; `modified_at` from the source | Section 10 |
| `--force` | Refused throughout Milestone 4 | CLI 6.4 |
| QR photos | Synthetic distortion tests in CI plus a manual printed-card photo check | Section 6 |
| Windows console | A manual checklist as an acceptance gate (result outstanding until performed) | Section 14 |
| Documentation | Stale text corrected; Q1 investigated without weakening Q2–Q4 or reopening the Windows assumptions | Sections 5.2, 13 |

The manual gates (Windows console, printed-card photos) are accepted as gates;
their results remain outstanding.

## 4. Proposed implementation sequence

Each step ends with its tests passing locally; native CI runs only after an
authorized push.

0. Approvals of section 15; `docs/CLI.md` approved; decisions recorded in the spec and SPEC_ISSUES.
1. **Cards, no I/O** (`card.rs`): payload, `check`, field and combination checks; Base32; QR matrix (forced byte mode, level M) and SVG; PNG decoding under 7.4c into a wiped grayscale buffer; `rqrr`. Independent Python vectors (payload, Base32, QR module matrix) published in `docs/FORMAT.md`. `card_parse` fuzz target. Heap hygiene for share, text and pixel buffers.
2. **Paths at input** (section 8). F73 input part.
3. **Per-user records** (section 7): settings folder, locks, record I/O, rollback record.
4. **Portable unlock** (5.3, 5.7): including the duress tag check with no action on a match, and the `update` journal check (section 9).
5. **Card files** (section 11).
6. **Portable `init`** (8.3, CLI 6.1), including the first-header commit by no-replace rename and the init restart table.
7. **`add` and `rm`** (sections 9, 10), with F92.
8. **`list` and `get`** (7.9), `--force` refused.
9. **`status` and `clean-partials`.**
10. **Scenario and crash tests** in `crates/pvault-tests` (`tests/failure_scenarios.rs`), CLI child processes built with `fault-injection`.
11. **Platform validation** (section 6.3), the Q1 probe (section 13), documentation (`docs/FORMAT.md`, `docs/FAILURE_MODES.md` drafts).

## 5. Contradictions and missing requirements

### 5.1 Resolved by the drafts (for approval)

| # | Where | Case | Resolution |
| --- | --- | --- | --- |
| C1 | 9.7 vs 4.4 | `rollback.cbor` was a map keyed by 16-byte `vault_id`; 4.4 allows only fixed text keys | Section 7.4: an entry list |
| C2 | 7.9, 7.4b vs 8.1 | Record fields had no types, caps, path encoding or identity encoding; destinations may lack birth time | Section 7 |
| C3 | 8.3 vs 6.10 | `init` lists "optional duress"; duress setup is Milestone 5 | Approved direction; spec note added (section 5.2) |
| C4 | 7.8, 7.7 | No rules for `add` sources | Section 10 |
| C5 | SI-40 | Journal-free `add`/`rm` cannot bind cleanup to a transaction: a MAC or AEAD check alone cannot distinguish our leftover from a copy of a file placed at the same name | Section 9: an `update` journal (a schema addition, for approval) |
| C6 | 7.8 | "Equal after NFC and default case folding" is not closed under canonical equivalence | Approved direction: canonical caseless matching (section 8) |
| C7 | 8.3 | The Milestone 3 commit checks an existing header's generation; `init` has none | First commit by no-replace rename (routine) |
| C8 | 8.4 | "Any operation that finds an existing journal must stop" | Section 9.5: `update` journals resolved by ordinary-unlock commands (for approval) |
| C9 | 7.9, 7.4b | "Durably record" was not tied to any storage policy; an atomic rename on a network or unsupported file system is not durable | Section 7.1: tracking records need the 8.5 identification and preflight; secret bytes only after registration; refusal otherwise |
| C10 | 7.9, 7.4b, SI-10 | Device and inode equality was the whole identity check; it does not survive remounts or inode renumbering | Section 7.2: same-process deletion through the held handle; after a restart only with a matching recorded birth time; otherwise never |
| C11 | Earlier draft of 9 | Deleting the old key table before the journal could record that cleanup was done left a restart unable to derive the removed set | Section 9.3: the `cleaned` phase |
| C12 | 10.6 vs printed cards | One secret per line vs a card printed on 7 lines; non-interactive `init` needs card text produced during the run | `docs/CLI.md` 2 and 6.1 |
| C13 | Output | Paths can carry terminal control and bidirectional characters | `docs/CLI.md` 1.1 and 1.2 |

### 5.2 Documentation corrected in this revision

| # | Where | Correction |
| --- | --- | --- |
| N-a | Spec preamble | "Spec version: 7.4" → 7.5 |
| N-b | Spec 7.3 | H_w steps replaced by the approved and implemented `H_w_v1` steps |
| N-c | Spec 8.5 | Q1–Q4 evidence updated with run 37391563815 (UNC and mapped SMB refused by Q2; `subst` accepted; Q1 non-discriminating); remaining coverage: ReFS, mounted VHD, real remote SMB |
| N-d | Spec 4 | `vault.gate` added to the layout |
| N-e | Spec 13 | F33 and F72: `get` parts in Milestone 4, `fsck` parts in Milestone 6; F70 card half with SI-10 |
| N-f | SPEC_ISSUES 4 | "Before Milestone 4" now lists SI-40, the record schemas and the approved directions |
| N-g | SPEC_ISSUES SI-50 | Rollback-record format marked as refined (section 7.4) |
| N-h | Spec 7.4b, 7.8, 8.3 | Approved directions recorded: no card-text display; the path direction; no duress setup in Milestone 4 |

## 6. Tests and platform validation

### 6.1 Automated

- Every row of section 1.2.
- Independent Python vectors for cards (payload, Base32, QR module matrix).
- Crash tests: the CLI in a child process with `fault-injection`, aborting at every failpoint of `init`, `add` (with and without `--replace`), `rm` (including `--recursive`), `.pvpartial` creation (E1 to E6) and card writing (W1 to W8). For `add`/`rm` every row of the 9.6 table is a test, including: `rm` writing `staged`; a partial and a complete `cleaned` temp; a crash after the old key table was unlinked with `cleaned` canonical; and the outside-the-protocol case (old key table removed while `committing`). Each restart checks the exact authenticated state and that nothing was deleted without proven ownership.
- Record tests: section 7.7, including injected flush failures before any secret byte, mocked unsupported settings-folder types, and identity cases (same `dev`/`ino` with another `btime`; no `btime`; changed `dev`).
- Source-change tests (section 10): truncation and growth that persist to a check point; modification with changed times; symlink, FIFO, device and directory sources. A transient change restored before the second check is documented as undetectable, and a test demonstrates that limit rather than claiming detection.
- Input tests: every non-interactive `init` branch of `docs/CLI.md` 6.1 (each line count from 3 to 5; mismatched confirmation; medium estimate without a terminal; card mismatch with one attempt; end of input at each line), with the harness supplying card lines only after the cards are written; multi-line hidden card entry (7 lines, more than 216 symbols, more than 8 lines, an empty line) in a pty.
- Name-length tests: a destination name whose `.pvpartial` form exceeds the limit on ext4 (bytes), APFS (bytes) and NTFS (UTF-16 units), and on FAT/exFAT images; refused before any file exists.
- Card-input boundary tests (terminal, in a pty; and `--secrets-stdin`):
  - exactly 216 symbols on one line, with and without separators: accepted only after the terminator is read;
  - 216 symbols as printed on 7 lines: accepted after line 7; no eighth line is read;
  - a final line taking the count from 200 to 217: rejected as a whole, including when the 217th symbol follows the 216th on the same line;
  - 215 symbols then an empty line; 216 symbols spread over 9 lines; an invalid character in an otherwise valid final line: rejected;
  - end of input right after the 216th symbol with no terminator (`--secrets-stdin`): rejected ("Input ended before all secrets were read.");
  - `--secrets-stdin` card line with 215 or 217 symbols: rejected; the following lines are not read;
  - queued input (Unix pty tests; Windows manual gate item 7c): lines queued before a hidden prompt is displayed (a card followed by two extra lines; lines typed while Argon2id runs) are discarded before the prompt appears and never read; the tests do not claim to catch input written after the flush.
- Export publication tests (section 7.5): failure injected at each of E3, E4, E5a (rename not done), E5a (rename done but reported as failed), E5b and E6. Unpublished: nothing at `<destination>`, exit 1. Published: `<destination>` kept and complete, exit 5, entry removed or left naming only the `.pvpartial` path. A later cleaner never deletes the published file.
- Unresolved-cleanup test: delete `keytable.<old_gen>.pv` while the journal is `committing` and the header is new. The journal is retained unchanged; no object is deleted; the report lists the unreferenced objects; `list` and `get` work; `add` and `rm` exit 5; `CLOSE UNFINISHED CLEANUP` removes only the journal, after which the objects appear as 9.7 candidates.
- Rendering tests: C0, C1 (for example U+009B), bidirectional controls, U+FEFF, unassigned code points, backslashes, invalid UTF-8 (Unix) and unpaired surrogates (Windows) in source, destination, card-folder and stored vault paths; output contains only the escaped forms.
- QR: synthetic distortions (scale 0.5× to 4×, rotation up to 30°, perspective skew, Gaussian blur, noise, low contrast, JPEG-like blocking) on PNGs built from the module matrix with the approved `png` encoder.
- Heap hygiene for card, Base32, pixel, share and slot buffers. Fuzzing: `card_parse`.

### 6.2 Test performance

Scenario tests create vaults with `--kdf-memory 256 --kdf-iterations 3
--kdf-parallelism 1` (the hard-cap minimum).

### 6.3 Platform validation

| Item | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Unit, scenario, crash tests | CI | CI | CI |
| Export and card destinations that cannot be verified as owner-only (O3): refused before any secret or file | Loopback FAT/exFAT and `exfat-fuse` (`fuseblk`) images in CI (`fat_exfat_images`); `/proc` (`unverifiable_destinations_are_refused`) | `hdiutil` FAT/exFAT images in CI and locally (passed 2026-10-06); `/dev` (passed locally) | `diskpart` VHDX FAT/exFAT and the loopback share `\\localhost\C$` in CI (not yet run) |
| F74 on a real FAT/exFAT vault | Loopback image in CI | `hdiutil` image in CI and locally (passed) | `diskpart` VHDX in CI (not yet run); mocked type in unit tests |
| Owner-only permissions and ACLs | Mode bits | Mode bits | DACL read back in CI |
| Interactive console | pty tests | pty tests | **Manual gate** (section 14) |
| PNG verification with the terminal acknowledgment (O1) | pty scenario (real CLI) | pty scenario (real CLI; passed locally) | **Manual gate** (section 14, steps 13 and 14) |
| Printed-card photos | Manual gate | Manual gate | Manual gate (one platform suffices) |
| Q1 probe | n/a | n/a | CI (section 13) |
| Outstanding from Milestone 3 | | | ReFS, mounted VHD, real remote SMB; W1/WO unverified |

## 7. Per-user records

### 7.1 Settings folder and storage policy

- **Location:** `directories::ProjectDirs::from("", "", "pvault")`, using
  `config_local_dir()`: Linux `$XDG_CONFIG_HOME/pvault` or
  `~/.config/pvault`; macOS `~/Library/Application Support/pvault`;
  Windows `%LOCALAPPDATA%\pvault\config`. The *local* variant keeps records
  (machine-specific paths and file identities) from roaming to other
  computers.
- **Layout:**

  ```text
  <settings>/                      0700 / owner-only DACL
    rollback.cbor   rollback.lock
    partials.cbor   partials.lock
    cards.cbor      cards.lock
    transfers/<transfer_id hex>.lock      0700 folder
    cards/<op_id hex>.lock                0700 folder
    <record>.cbor.tmp                     transient
  ```

- **Creation:** missing folders are created owner-only, one component at a
  time, relative to an opened parent handle; the final component of each is
  opened without following a symlink or reparse point.
- **Privacy check on every open:** a directory, owned by the current user,
  granting no access to anyone else. Unix: `st_uid == geteuid()` and
  `mode & 0o077 == 0`. Windows: owner SID equals the process user's SID, and
  the DACL is protected and grants access only to that user (pvault creates
  exactly that DACL; extra entries for `SYSTEM` and `Administrators` are
  tolerated, because they can read everything anyway). Otherwise:
  "The pvault settings folder <path> is not private to you." (exit 6).
- **Names inside the settings folder.** The folder is pvault-private (checked
  above). Inside it, pvault manages its own fixed-name record, lock and temp
  files by name, under the record lock. This is the only place where a name is
  enough, and only because the folder is verified private; vault folders and
  destination folders never follow this rule.

**Two storage policies.** Atomic replacement (a reader sees the old or the
new record) is not the same as durable registration (the new record survives
a crash or power loss). The records are therefore split:

| Record | Policy | Requirement | If the requirement is not met |
| --- | --- | --- | --- |
| `partials.cbor`, `cards.cbor` (tracking) | **Registration.** An entry counts as registered only when the 7.3 update completed with every flush call reporting success. That is the strongest durability pvault can request; see the qualification below the table | The settings folder passes the 8.5 identification (Linux ext4, XFS, Btrfs; macOS APFS, HFS+; Windows local NTFS or ReFS by Q1 to Q4) and the 8.5 durability preflight on its handle, in this process | `get` and card-writing refuse **before creating any destination file**: "Exports and card files need a settings folder on a supported local drive (<type>)." (exit 6). Network file systems, FAT, exFAT, FUSE and unknown types are refused; atomic rename alone is not accepted as durability |
| `rollback.cbor` (advisory) | **Atomic replacement, best-effort durability** | Locks work and a same-folder rename replaces atomically | Updates are skipped with "Rollback detection is unavailable: <reason>."; unlock is never blocked |

- **What "registered" does and does not establish.** A successful flush
  establishes durability only as far as the storage device honors the
  platform flush primitive (8.5), and on Windows only under the unverified
  WO-1 to WO-3 and W1 assumptions (N1). pvault's tests inject process
  crashes, not power loss. Registration is therefore an ordering guarantee
  against process crashes plus a best request for durability; it is **not**
  verified power-loss safety, on any platform, and the documentation must not
  call it that.
- **Flush failure during registration** (any flush call reports failure, or
  the platform reports it unsupported): the entry is **not** registered. No
  secret byte is written. pvault deletes the empty destination file it just
  created through its still-open handle (7.2), removes the entry (best
  effort, under R), and fails: "The export could not be registered durably;
  nothing was exported." or "The card files could not be registered durably;
  no card was written." (exit 1). If the process dies during that cleanup, the
  entry may remain and point to an empty file; the stale cleaner (7.5, 11.3)
  handles it.
- **Windows** has no unprivileged directory flush. Registration there rests on
  the write-through temp, `FlushFileBuffers` and the write-through
  handle-relative rename, under the same **unverified** ordering assumptions as
  WO-1 and W1 (8.5, N1).

### 7.2 Common record format

Every record is one 4.4 map:

```text
{ "kind": text, "entries": array, "version": u64 }
```

- `kind` is exactly `"pvault-rollback"`, `"pvault-partials"` or `"pvault-cards"`; `version` is exactly 1.
- Entries are sorted by their key (per record below) bytewise and unique.
- A record parses only if the whole file passes 4.4, its `kind` matches the file name, its `version` is 1, every entry passes its schema, and both caps hold. **Size is checked before reading**: a larger file is not read.

**Native path encoding** (field `path`, bytes 1 to 4,096):
- Unix: the raw bytes of the absolute path (`OsStr::as_bytes`); no NUL.
- Windows: the UTF-16 code units of the absolute path, little-endian; even length; no NUL unit. A path longer than 2,048 code units cannot be recorded, so the operation refuses ("This path is too long to track safely.").
- Paths are compared byte for byte, never normalized, and printed only through the CLI's safe rendering (`docs/CLI.md` 1.2).

**File identity:**

| Field | Unix | Windows |
| --- | --- | --- |
| `id_kind` | `"unix"` | `"windows"` |
| `dev` | `st_dev` (u64) | volume serial number (u64 from `FILE_ID_INFO`, or the zero-extended 32-bit serial from `GetFileInformationByHandle` with the fallback below) |
| `ino` | bytes(8): `u64_be(st_ino)` | bytes(16): `FILE_ID_128`, or the zero-extended 64-bit index from `GetFileInformationByHandle` where `FileIdInfo` is unsupported |
| `btime` | optional bytes(12): `i64_be(sec) ‖ u32_be(nsec)` when `statx` (`STATX_BTIME` in the mask) or `st_birthtimespec` (non-zero) provides it | optional bytes(8): `u64_be(CreationTime)` when non-zero |

**When an identity may authorize a deletion.** Device and inode numbers alone
do not prove that a later file is the recorded one: device numbers of
removable media change between mounts, Linux FAT assigns inode numbers per
cached inode (they can change even without a remount), and freed numbers are
reused. Therefore:

| Situation | Deletion allowed when | Why it is safe |
| --- | --- | --- |
| **Same process, file still open** (export failure cleanup, card deletion after verification) | The handle pvault created is still open. Windows: the delete disposition is set **on that handle**. Unix: `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` equals `fstat(fd)` in `st_dev` and `st_ino`, then `unlinkat` | An open file cannot be freed, so its inode number cannot be reused while the handle is held; the folder handle is the one the file was created in |
| **After a restart** (stale cleaner, with the owner's confirmation) | A `btime` was recorded **and** `id_kind`, `dev`, `ino` and `btime` all match on a no-follow reopen of a regular file | Birth time distinguishes a reused number from the original file (to its resolution; see below) |
| **After a restart, no `btime` recorded** | **Never.** The entry is reported ("pvault cannot prove that <path> is the file it created; delete it yourself if it is.") and dropped only after the owner confirms that it was handled | Identity stability cannot be established |

Birth time has a resolution (one second on HFS+, 10 ms or 2 s on FAT) and can
be set by programs with write access (8.1). This is the same residual risk the
Milestone 3 artifact identity accepts and documents; it is never a defense
against a local adversary.

Consequence: on destinations without birth time (for example FAT on Linux),
an export or card file left by a crash is never deleted by pvault; the owner
is told where it is. For an export that file holds plaintext, so the message
says so.

### 7.3 Locks and atomic update

| Lock | File | Held |
| --- | --- | --- |
| R (record) | `<record>.lock` | Exclusive for read-modify-write; shared for reading. Never held while waiting for anything |
| T (transfer) | `transfers/<id>.lock` | Exclusive for a whole export (7.9) |
| C (card operation) | `cards/<id>.lock` | Exclusive for a whole card-writing operation (section 11) |

- Lock files are zero-length, created without following links, owner-only. R files are never deleted. T and C files are deleted by their owner after its entries are removed.
- **Order:** vault lock L → T or C → R. Nothing waits while holding R. A holder of T or C may wait up to 2 s for R (bounded retries); every other attempt is non-blocking. No wait cycle is possible.
- **Update** (under R exclusive):
  1. read and validate the current record (absent = empty);
  2. compute the new record and check the caps;
  3. open `<record>.cbor.tmp` without following links (create or truncate; it must be a regular file), write, flush the file;
  4. rename over `<record>.cbor` (handle-relative replace);
  5. flush the folder.

  For a tracking record, the entry is **registered** only when steps 3 to 5 all reported success (7.1, with its qualification). For the advisory record, a failure at step 5 is a warning.
- **Crash:** before step 4 the old record stands; a leftover `.tmp` is overwritten by the next update. After step 4 either the old or the new record stands, both consistent. Because secret bytes follow only a completed step 5, a **process** crash can lose an entry only for a file that holds no secret bytes yet. Under power loss the same holds only if the device and platform honored the flushes (7.1 qualification).

### 7.4 `rollback.cbor` (advisory)

```text
entry = { "vault_id": bytes(16), "generation": u64 }      sorted by vault_id
caps: ≤ 4,096 entries; file ≤ 256 KiB
```

- **Check** (every ordinary unlock, after the MACs verify): if the recorded generation is greater than `core.generation`, warn "This vault is older than a copy opened on this computer before (generation <g> < <r>). It may be an old copy." Never a block.
- **Update** (after every successful ordinary unlock and after every commit): `generation = max(recorded, core.generation)`; never decreases. Verification-only paths never update it (Milestone 6).
- **Full record:** a vault not yet recorded is not added; warning "The rollback record is full; this vault is not tracked." No eviction.
- **Missing:** treated as empty, created on the first update. **Damaged or a newer `version`:** warning "Rollback detection is unavailable: the record is damaged."; never overwritten; deleting it is the owner's choice.

### 7.5 `partials.cbor` (tracking)

```text
entry = { "path": bytes, "dev": u64, "ino": bytes, "btime"?: bytes,
          "id_kind": text, "vault_id": bytes(16), "created_at": u64,
          "transfer_id": bytes(16) }                           sorted by transfer_id
caps: ≤ 256 entries; file ≤ 2 MiB
```

**Export order** (7.9, with the registration rule):

| Step | Action | Crash here leaves | Handled by |
| --- | --- | --- | --- |
| E1 | Check the settings-folder policy (7.1); take T | Nothing, or an empty T file | Cleaner: no entry; deletes the T file |
| E2 | Create `<destination>.pvpartial` empty, exclusively, without following links, owner-only, relative to the parent handle; keep the handle open; capture the identity | An empty, unrecorded file (no plaintext) | 7.9: a later `get` that collides with it may delete it only if it is a regular file of size 0, after confirmation |
| E3 | Register the entry (7.3 steps 1 to 5 all succeed) | An entry pointing to an empty file | Stale cleaner (below) |
| E4 | Only now: decrypt and write verified plaintext through the open handle; flush | An entry pointing to partial plaintext | Stale cleaner |
| E5a | **Publish:** rename without replacing `<destination>.pvpartial` → `<destination>` (handle-relative) | Before the rename: the complete partial at the recorded path. After it: the complete file at `<destination>`, entry still naming the `.pvpartial` path | Before: stale cleaner (the file matches the record; deleted only after confirmation and only under the 7.2 restart rule). After: stale cleaner finds the recorded path absent and drops the entry; **the published file is never a cleanup target**, because the entry names only the `.pvpartial` path |
| E5b | Flush the parent folder | Published file; entry present | As E5a (after) |
| E6 | Remove the entry (under R); release T; delete its file | Entry gone; T file left | Cleaner deletes T file |

**Failures in the running process:**

| Failure | Published? | Action | Result |
| --- | --- | --- | --- |
| E3 to E4 (registration, decryption, verification, writing, flushing the partial) | No | Delete the partial through its open handle (7.2); flush; E6 | Exit 1; nothing at `<destination>` |
| E5a reports failure | Decided by the names, not the error: `fstatat(dirfd, "<destination>")` equal to the held handle's identity (Windows: the handle's current name, via `GetFinalPathNameByHandleW`, is `<destination>`) means published; the `.pvpartial` name still equal to the handle means not published | Not published: as the row above. Published: as E5b failure. Neither: delete nothing, keep the entry, report | Exit 1, exit 5, or exit 5 ("The export's outcome could not be determined; check <destination>.") |
| E5b (parent flush) | Yes | **Keep** `<destination>`; remove the entry (E6) | Exit 5: "Exported … to <destination>, but the export could not be confirmed as durable." |
| E6 record update fails after publication | Yes | Keep `<destination>`; leave the entry (it names only the `.pvpartial` path, now absent) | Exit 5 with the same message; a later cleaner drops the entry without deleting anything |

After publication pvault never deletes or overwrites `<destination>`. 7.9
already allows plaintext at the requested destination.

- **Full record:** `get` refuses before E2: "Too many unfinished exports are recorded. Run pvault clean-partials." (exit 4).
- **Stale entry:** its T can be taken without blocking. The cleaner (`get` for the same vault, `clean-partials`, `fsck` in Milestone 6) holds that T, lists the entry, asks for confirmation and applies the 7.2 after-restart rule. A mismatch, a missing file or no `btime`: nothing is deleted; the entry is dropped after the owner confirms, and reported.
- **Missing record:** empty. **Damaged or newer version:** "The export record <path> is damaged; pvault will not change it. Move it aside to continue." `get` refuses (exit 6); nothing is deleted. Moving the record aside makes any partial it tracked untracked; the message says so.

### 7.6 `cards.cbor` (tracking)

```text
entry = { "dev": u64, "ino": bytes, "path": bytes, "role": text, "btime"?: bytes,
          "op_id": bytes(16), "set_id": bytes(8), "id_kind": text,
          "vault_id": bytes(16), "created_at": u64 }   sorted by (op_id, role)
role ∈ { "card-a", "card-b", "bound" }      ("bound" reserved for Milestone 5)
caps: ≤ 256 entries; file ≤ 2 MiB
```

Lifecycle, stale and damaged handling: section 11.

### 7.7 Record tests

- Concurrent writers never lose an entry.
- Crash between steps 3 and 4 leaves the old record.
- An injected flush failure at step 3 or 5 writes no secret byte, removes the empty destination file through its handle, and fails with the registration message.
- A settings folder on a mocked unsupported type (network, FAT) refuses `get` and card writing before any destination file exists; `rollback.cbor` then only warns.
- Damaged, foreign-`kind`, newer-version and oversized records are refused without modification.
- A settings folder with group or other permissions (Unix) or a foreign DACL entry (Windows) is refused.
- Identity: a recorded file replaced by another file with the same `dev` and `ino` but a different `btime` is never deleted; an entry without `btime` is never deleted after a restart; a simulated remount (changed `dev`) is never deleted.

## 8. Vault paths at input (approved direction)

1. **Decode** the argument from the OS: Unix bytes must be valid UTF-8; Windows UTF-16 must have no unpaired surrogate.
2. **Refuse unassigned** code points (not in the Unicode 17.0.0 assigned set of `ucd17`; noncharacters and private use follow the H_c rules).
3. **NFC** with the pvault-owned buffer; tell the owner when it changed ("Stored as: …").
4. **Syntax:** the decode-time rules of 7.8 (`paths::is_valid_decoded`, unchanged and Unicode-independent).
5. **Collision key:** Unicode canonical caseless matching (D145), `NFD(toCasefold(NFD(x)))`, with the vendored 17.0.0 full case folding (statuses C and F) and NFD from the same tables. Two paths collide when their keys are equal. A file and a directory may not share a key. `--replace` must name exactly the stored path of the entry it replaces.
6. **Parents:** each missing parent becomes a `dir` entry with the same timestamps as the operation.
7. **Decode of existing paths** is unchanged: the Milestone 3 rules only, no Unicode-dependent checks.

## 9. `add` and `rm` (SI-40 completion; for approval)

### 9.1 Why a journal is needed

SI-40's journal-free proposal relied on authenticated decryption to own
leftovers. A MAC or AEAD check proves that a file was made with this vault's
keys; it does not prove that **this transaction** left it there. A copy of
`keytable.<g+1>.pv` from a synced or backed-up copy of the same vault would
pass and be deleted. Binding each automatic deletion to the vault, the role
and the transaction needs the 8.1 rule: create empty, capture identity,
journal it, then write. That needs a journal record, a schema addition to
8.1, presented here for approval.

### 9.2 Ownership rules

| Artifact | Deleted automatically only when |
| --- | --- |
| `keytable.<new_gen>.pv(.tmp)`, `objects/<oid>.pv(.tmp)`, `vault.hdr.tmp` created by the transaction | An authenticated `update` journal records its identity, and a no-follow reopen under the held folder handle yields a regular file with that identity (8.1 rule; these are vault artifacts on an 8.5-supported file system, where the identity includes birth time) |
| `keytable.<old_gen>.pv` after a commit | Phase `cleaned` is durable (9.3), its journaled identity matches, **and** its SHA-512 equals `old_keytable_digest` |
| `objects/<oid>.pv` of a removed entry after a commit | The commit is proven (header = `new_core_digest`); `oid` is in the authenticated old key table and not in the committed new one; a no-follow reopen gives a regular file whose stream header has `stream_id = oid`, `context = 0` and `plain_size` = the old entry's size, and whose first record authenticates under that entry's `fk_aes`/`fk_chacha`; the identity of the verified handle is rechecked immediately before deletion (Windows deletes that same handle) |
| Anything else | Never automatic. Reported with name, identity and size |

Removed objects existed before the transaction, so their identity cannot be
journaled at creation. Their binding is role (the removed entry's protocol
name), transaction (old and new tables, bound by the journal and the committed
header) and expected content (the entry's unique random keys and size). A
byte-identical copy of that same object at that name is treated as that
object, which is what the owner asked to remove.

### 9.3 The `update` journal record (schema addition to 8.1)

Single `mac` under `journal_key(current bundle)` (the bundle does not change).
New field names are marked ★; the others already exist in the 8.1 key union.

| Field | Type | Present |
| --- | --- | --- |
| `op` | text `"update"` | always |
| `phase` | text: `"staged"`, `"committing"` or `"cleaned"` | always |
| `vault_id` | bytes(16) | always |
| `old_gen`, `new_gen` | u64; `new_gen = old_gen + 1` (checked add) | always |
| `old_core_digest`, `old_keytable_digest` | bytes(64) | always |
| `old_kt_id_kind` ★, `old_kt_file_id` ★ | identity of `keytable.<old_gen>.pv`, captured from an open handle | always |
| `target_kt_id_kind`, `target_kt_file_id` | identity of the empty `keytable.<new_gen>.pv.tmp` | always |
| `header_id_kind`, `header_file_id` | identity of the empty `vault.hdr.tmp` | always |
| `new_object_id` ★ | bytes(16): the new `file_id` | `add` only (absent for `rm`) |
| `object_id_kind` ★, `object_file_id` ★ | identity of the empty `objects/<new_object_id>.pv.tmp` | `add` only (absent for `rm`) |
| `new_core_digest` | bytes(64) | `committing` and `cleaned` |
| `mac` | bytes(64) | always |

- **`staged`:** every artifact the transaction will write exists, empty, with its identity recorded. Nothing is written into any of them yet.
- **`committing`:** the new key table and object are final and durable; `new_core_digest` names the exact new core. Written before any header byte.
- **`cleaned`:** the header is the new core and every removed object has been deleted or reported; only `keytable.<old_gen>.pv` and the journal remain. It has exactly the `committing` fields with a different phase. It exists so that a restart never needs the old key table after that table may have been deleted.

About 700 bytes, well under 16 KiB. Exact presence is enforced by re-encoding.

### 9.4 Protocol

Both commands run every step below, except the object-specific parts marked
**add**. `rm` creates no object temp at U4, writes no `new_object_id`,
`object_id_kind` or `object_file_id` into its records, and skips U7. A plain
`add` (no `--replace`) usually removes no object at U10a; `add --replace` and
`rm` do.

| Step | Action |
| --- | --- |
| U1 | Ordinary unlock (5.7), exclusive lock; journal check and restart (9.5); leftover check (9.7) |
| U2 | Path rules (section 8); N5 count. **add:** open and snapshot the source (section 10); generate `file_id` and keys (regenerate on collision) |
| U3 | **add:** create `objects/` if missing (same-mount check, preflight on its handle). Open `keytable.<old_gen>.pv` and capture its identity |
| U4 | Create empty, exclusively: `keytable.<new_gen>.pv.tmp`, `vault.hdr.tmp`, and **add:** `objects/<oid>.pv.tmp`; capture identities |
| U5 | Write `staged` (journal temp, flush, replace, folder flush) |
| U6 | Write the new key table into its temp (`context = new_gen`), flush, rename no-replace to `keytable.<new_gen>.pv`, flush the folder |
| U7 | **add:** encrypt the source into the object temp (section 10 checks), flush, rename no-replace to `objects/<oid>.pv`, flush `objects/` |
| U8 | Build the new core and header; write `committing` with `new_core_digest` |
| U9 | `commit_header`: write the temp, F58 generation check, replace, post-replacement flush (8.5 failure boundary) |
| U10a | Derive the removed set from the old and new key tables (both present); delete each removed object under 9.2; flush `objects/` |
| U10b | Write `cleaned` (journal temp, flush, replace, folder flush) |
| U10c | Delete `keytable.<old_gen>.pv` under 9.2; flush the vault folder |
| U11 | Remove the journal and flush; update `rollback.cbor` (advisory) |

### 9.5 Restart (amendment to 8.4, for approval)

8.4 says any operation that finds a journal stops and directs the owner to
`fsck`. Proposed exception: an authenticated `update` journal is resolved by
the ordinary-unlock commands (`add`, `rm`, `list`, `get`) at step 7 of 5.7,
under the exclusive lock, before the command continues (`list` and `get`
before they downgrade). Any other journal still stops the command (exit 4).

**Journal temp first** (as 8.2): the permitted transitions are
`staged` → `committing` and `committing` → `cleaned`. The header condition is:
for a `committing` temp, the old core or the temp's new core (the Windows WO-1
case); for a `cleaned` temp, the new core. Both records must authenticate,
the temp must preserve every field of the canonical record and add only its
phase's fields. Anything else is residue (9.7).

| Journal | Header after unlock | Action |
| --- | --- | --- |
| `staged` or `committing` | `old_core_digest` | **Roll back:** delete the identity-owned staged artifacts at their temp or final names; flush; remove the journal. The interrupted change did not happen; the command continues |
| `committing` | `new_core_digest` | **Roll forward from U10a:** repeat the post-replacement flush; U10a (the old key table is guaranteed present in this phase, see below); U10b; U10c; U11 |
| `cleaned` | `new_core_digest` | **Finish:** U10c (an absent old key table is already done); U11 |
| `committing` | `new_core_digest`, but `keytable.<old_gen>.pv` absent | See "Unresolved cleanup" below |
| any | neither | **Indeterminate:** nothing deleted, journal kept, exit 5 |
| fails to parse or authenticate | n/a | Stop (exit 4); nothing deleted |

**Unresolved cleanup** (`committing`, header = `new_core_digest`, old key
table absent). The protocol deletes the old key table only after `cleaned`
is durable, so this state is outside the expected sequence. **pvault infers
no cause.** A Windows ordering failure (WO-3 is unverified), an external
change or restore, a file-system fault and other causes all remain possible.
- **No removed-object cleanup.** The removed set is defined by the old key table; without it, no object is deleted, now or later in this restart.
- **The journal is retained unchanged.** It is the record that this commit's cleanup is unresolved. `cleaned` is not written, and the journal is not removed automatically.
- **Reported:** "This vault's last change was saved, but its cleanup could not be finished because a file it needs is missing. Nothing was deleted. Run fsck." with the objects not referenced by the current key table (names and sizes; they include any objects the change removed) and the missing file's name.
- **Reads continue.** The committed header and its key table are authenticated, so `list` and `get` proceed after the report (exit 0, with the warning on standard error). `add` and `rm` stop with exit 5.
- **Resolution:** `fsck` (Milestone 6). Until then, after an ordinary unlock, the owner may close it explicitly with the terminal confirmation `CLOSE UNFINISHED CLEANUP <first 8 hex of vault_id>`. That removes the journal only and deletes nothing. The unreferenced objects stay, and from then on they are listed as 9.7 candidates whenever the owner is offered leftover removal, so the information remains visible.

### 9.6 Crash table

| Crash during or after | State left | Restart |
| --- | --- | --- |
| U1–U3 | Nothing written (except possibly an empty `objects/`, never deleted) | Nothing to do |
| U4, before `staged` is durable | Empty unowned temps, no journal | Reported; they block the names the next change needs; owner confirmation (9.7) |
| U5, journal temp partial or complete, no canonical record | Residue | Blocks; owner confirmation (9.7). (`staged` has no canonical predecessor, so even a complete temp has no ownership root) |
| U5, renamed but folder flush not done | `staged`, or nothing if the rename did not persist | `staged`: roll back. Nothing: as U4 |
| U6, U7 (any point) | `staged`; header old | Roll back |
| U8, journal temp partial | `staged` canonical; residue temp | Roll back (it removes the journal and needs no rewrite). The residue stays and blocks the next change's journal write until the owner confirms its removal (9.7, no journal pending by then) |
| U8, temp complete, or renamed | `committing` (promoted if needed); header old | Roll back |
| U9 before the replacement | `committing`; header old | Roll back |
| U9 after the replacement, during the flush | `committing`; header new | Roll forward from U10a |
| U10a (any point) | `committing`; header new; some removed objects deleted | Roll forward from U10a; already deleted objects are absent, which is expected; the old key table is still present |
| U10b, journal temp partial | `committing` canonical; residue temp; header new | U10a repeats (nothing left to delete); writing `cleaned` is blocked by the residue; owner confirmation for `vault.journal.tmp`; then U10b |
| U10b, temp complete | Promotable `cleaned` temp (header new) | Promote; continue at U10c |
| U10b, renamed but folder flush not done | `cleaned`, or `committing` | `cleaned`: U10c. `committing`: roll forward from U10a (the old key table is still present, because U10c had not run) |
| U10c, after the unlink, before or during the folder flush | `cleaned`; old key table absent, or present again if the unlink did not persist | Finish: absent means done; present means delete it again under 9.2 |
| U11, journal unlinked but flush not done | No journal, or a stale `cleaned` journal | Stale `cleaned`: finish (U10c finds nothing), remove it |
| U11, before `rollback.cbor` is updated | Committed; record not updated | The next unlock updates it |

### 9.7 When ownership cannot be proved

- Never deleted automatically, never overwritten.
- If an unowned file occupies a name the command needs (`vault.hdr.tmp`, `vault.journal.tmp`, `keytable.<g+1>.pv`, `keytable.<g+1>.pv.tmp`), the command stops: "Files pvault cannot prove it created block this change: <names>. Nothing was deleted." (exit 4).
- After a successful ordinary unlock, the owner may remove exactly the listed candidates, regular files only, by the terminal confirmation `DELETE VAULT LEFTOVERS <first 8 hex of vault_id>`:
  - with **no journal pending:** the names above, plus `objects/<hex>.pv.tmp` and `objects/<hex>.pv` not referenced by the current key table;
  - with an authenticated `update` journal pending: **only** `vault.journal.tmp`, and only when it is residue blocking the journal rewrite the restart needs (9.6, row U10b journal temp partial).
- Immediately before each unlink the file is reopened without following links and must still have the displayed identity and size. Without a terminal, nothing is offered.
- Directories, symlinks, special files and any other name are reported only.

## 10. `add` source files (approved direction; exact rules for approval)

### 10.1 Opening

| | Unix | Windows |
| --- | --- | --- |
| Open | `open(path, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK \| O_NOCTTY \| O_CLOEXEC)`; then clear `O_NONBLOCK` | `CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_SEQUENTIAL_SCAN)` |
| Final component is a link | `ELOOP` → "The source is a symbolic link or reparse point; give the file itself." | `FILE_ATTRIBUTE_REPARSE_POINT` on the handle → the same message |
| Type check on the handle | `fstat`: `S_ISREG`, else "The source is not a regular file." (`O_NONBLOCK` keeps a FIFO from blocking the open) | `GetFileType == FILE_TYPE_DISK` and not a directory, else the same message |
| Concurrent writers | Not prevented (advisory locks do not bind other programs) | `FILE_SHARE_READ` only: the open fails if another handle has write or delete access ("The source file is in use by another program."), and no new writer can open it while pvault reads |

The path's earlier components may be links: the owner names the path, and
only the final component is checked.

### 10.2 Snapshot and reading

- Before reading, from the open handle: size, modification time, change time
  (Unix `st_ctim`; Windows `ChangeTime`), device and inode / file ID.
- `plain_size` = that size. The stream encrypts exactly `plain_size` bytes read
  through the handle; a short read fails ("changed"), and one extra readable
  byte at the end fails (the existing stream check).
- After reading, the same metadata is read again from the handle; any
  difference fails.
- On any failure the transaction rolls back (9.5): "The source file changed
  while it was being added; the vault was not changed."

### 10.3 Timestamps

- `created_at` = the time of `add` (UTC seconds; a clock before 1970 is an error).
- `modified_at` = the source's modification time in UTC seconds, truncated; a time before 1970 is stored as 0.

### 10.4 What this does not guarantee

A regular file read through one handle is **not** a consistent snapshot, and
the checks are detection, not prevention:

- They compare metadata at two points (before and after reading) and check
  the length while reading. A change is detected only if it is still visible
  at a check point: a short read, a final size or time that differs from the
  snapshot, or extra bytes at the end.
- A **transient** change can evade them: for example, data rewritten in place,
  or a truncation followed by re-extension to the original size, with the
  times restored or still equal at the second check. Such a change can make
  pvault encrypt a mixture of old and new bytes.
- Times do not always move: their resolution can hide a change (for example
  FAT's 2 s modification time, or a change time that advances only with a
  coarse kernel clock); a process with write access can set them back
  (`utimensat`, `SetFileTime`, and on Windows `SetFileInformationByHandle`
  can set `ChangeTime`); writes through memory mappings can update them late.
- Windows' sharing mode blocks new ordinary writers while pvault reads, but not
  every writer (kernel-mode, backup-semantics or already-mapped access).

Owners should close programs that write the file before adding it.
`docs/FAILURE_MODES.md` will state this.

## 11. Card files (SI-10 completion; for approval)

### 11.1 Destination

- `--cards-dir` is opened as a folder handle; its final component must not be a link or reparse point. The handle stays open until the operation ends.
- **Inside-the-vault check:** refused if the destination is the vault folder or any descendant of it. Unix: walk from the destination handle through `..` (handle-relative), comparing `(st_dev, st_ino)` with the vault folder's, until the root. Windows: compare `GetFinalPathNameByHandleW(VOLUME_NAME_GUID)` of both handles; refused if the destination path equals the vault path or starts with it followed by `\`.
- File names: `pvault-<vault_id first 8 hex>-<set_id first 8 hex>-card-a.svg` and `…-card-b.svg` (44 ASCII characters). Exclusive creation; an existing name refuses ("A file named <name> already exists in <dir>; nothing was written."); a name the destination file system rejects as too long refuses the same way as `get` (`docs/CLI.md` 6.4).
- The settings folder must allow durable registration (7.1); otherwise card writing refuses before W1.
- The card folder must be on a supported destination file system (`docs/CLI.md` 1.3): anything pvault cannot verify as enforcing owner-only access is refused (exit 6) before anything is created and before any secret is read (decided 2026-10-06, O3; section 17).

### 11.2 Writer lifecycle (`init` in Milestone 4)

Card files hold shares, so **no card byte is written before its entry is
durably registered** (7.1), and the files are deleted in the same process
through the handles kept open since creation (7.2).

| Step | Action | Crash here leaves | Handled by |
| --- | --- | --- | --- |
| W1 | Check the settings-folder policy; random `op_id`; create `cards/<op_id>.lock` (no-follow, owner-only) and lock it exclusively (C) | At most a zero-length lock file with no entries | Any cleaner: takes C, finds no entries, deletes the lock file |
| W2 | For each card: create the file empty, exclusively, owner-only, relative to the destination handle, **with delete access**; keep the handle open; capture its identity (7.2) | An empty, unrecorded card file (no share bytes) | Not tracked and not reported: no record exists. It holds no secret; the owner may delete it by hand. `docs/FAILURE_MODES.md` documents this window |
| W3 | Register both entries in one update (7.3 steps 1 to 5 all succeed). On any flush failure: no card byte is written; the empty files are deleted through their handles; the command fails with the registration message (7.1) | Entries pointing to empty files | Stale cleaner (11.3) |
| W4 | Only now write each SVG through its handle; flush each file; flush the destination folder | Recorded files, empty, partly or completely written | Stale cleaner |
| W5 | Printing acknowledgment; delivery verification (6.4); passphrase type-back | Recorded files holding complete, unverified cards | Stale cleaner |
| W6 | `init` commits (8.3) | Recorded files holding the vault's **current** cards | Stale cleaner, which labels them "current cards of vault <id>" when it can tell (11.3) |
| W7 | Delete each card file through its open handle (Windows: delete disposition on that handle; Unix: `fstatat` of the name equals `fstat` of the handle, then `unlinkat`); flush the destination folder. A name that no longer matches its handle (moved, replaced): not deleted, reported | Some files deleted, entries remaining | Stale cleaner drops entries whose files are gone |
| W8 | Under R: remove the operation's entries; close the handles; release C; delete `cards/<op_id>.lock` | Entries gone, lock file left | Cleaner: no entries; deletes the lock file |

Abort and rollback (failed verification, end of input, cancellation) run W7
and W8 at once, in the same process. Card files are never deleted by name or
pattern.

### 11.3 Cleaner (`clean-partials`; `init` resume for its own vault; `fsck` in Milestone 6)

1. Take R shared, snapshot the `op_id`s, release R. A damaged record: reported, never used.
2. For each `op_id`, try C without blocking. Held: skip its entries entirely (not listed, offered or deleted). Acquired: keep it.
3. Take R (bounded wait), re-read that operation's entries, release R.
4. List them (path, role, vault ID, set ID, created time; "current cards of vault <id>" only where the cleaner has authenticated that vault and its `card_set_id` equals the entry's `set_id`, which in Milestone 4 only `init` resume can do) and ask for confirmation.
5. For each confirmed entry apply the 7.2 after-restart rule: delete only if a `btime` was recorded and `id_kind`, `dev`, `ino` and `btime` all match on a no-follow reopen of a regular file. Otherwise nothing is deleted: "pvault cannot prove that <path> is the file it created; delete it yourself if it is." (for card files: "…; it may hold a recovery card").
6. Under R: remove the handled entries; release C; delete the stale lock file.

`init` resume offers this cleanup for entries whose `vault_id` is the
interrupted setup's (the cards of a rolled-back setup are invalid; 7.4a).

### 11.4 Card-record limits

The 7.6 caps apply. A full record refuses a new card-writing operation before
W1: "Too many unfinished card files are recorded. Run pvault clean-partials."

## 12. Dependencies (for approval; nothing changed yet)

### 12.1 Direct

| Crate | Pin | Features | Use | Scope |
| --- | --- | --- | --- | --- |
| `qrcode` | `=0.14.1` | `default-features = false`, `["svg"]` | QR matrix (byte mode via `Bits::push_byte_data`, level M) and SVG | `pvault-core` |
| `rqrr` | `=0.11.0` | `default-features = false` (no `image`) | QR decoding from a grayscale buffer (`PreparedImage::prepare_from_greyscale`) | `pvault-core` |
| `png` | `=0.18.1` | none (no default features) | PNG decoding under 7.4c; PNG encoding of test fixtures | `pvault-core` |
| `directories` | `=6.0.0` | default | Settings folder | `pvault-core` |
| `tempfile` | `3.27.0` | default | Scenario tests only | dev, `pvault-tests` (already in `Cargo.lock` through test tooling) |

All resolve and build with Rust 1.89 (checked in a scratch crate outside the
repository). `windows-sys` gains features for owner-only security descriptors
(`Win32_System_Threading` for the process token; others as needed): additions
to an existing dependency, listed in the implementation report.

### 12.2 New crates compiled into the binary (Linux, macOS and Windows alike)

| Crate | Version | License | Exception needed |
| --- | --- | --- | --- |
| `qrcode` | 0.14.1 | MIT OR Apache-2.0 | no |
| `rqrr` | 0.11.0 | (MIT OR Apache-2.0) AND **ISC** (code derived from quirc, © 2010-2012 Daniel Beer) | **yes** |
| `g2p`, `g2poly` | 1.2.2 | MIT/Apache-2.0 | no |
| `g2gen` (proc macro, build only) | 1.2.2 | MIT/Apache-2.0 | no |
| `lru` | 0.18.5 | MIT | no |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 | no |
| `foldhash` | 0.2.0 | **Zlib** | **yes** |
| `png` | 0.18.1 | MIT OR Apache-2.0 | no |
| `fdeflate` | 0.3.7 | MIT OR Apache-2.0 | no |
| `flate2` | 1.1.10 | MIT OR Apache-2.0 | no |
| `miniz_oxide` | 0.8.9 and 0.9.1 | MIT OR Zlib OR Apache-2.0 | no (MIT chosen); two versions give a `multiple-versions` warning |
| `crc32fast` | 1.5.2 | MIT OR Apache-2.0 | no |
| `adler2` | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | no |
| `simd-adler32` | 0.3.10 | MIT | no |
| `directories` | 6.0.0 | MIT OR Apache-2.0 | no |
| `dirs-sys` | 0.5.0 | MIT OR Apache-2.0 | no |
| `option-ext` | 0.2.0 | **MPL-2.0** (no Exhibit B notice in its sources; checked) | **yes** |

### 12.3 Proposed `deny.toml` exceptions (narrow; not applied)

```toml
exceptions = [
    { allow = ["GPL-3.0-only"], crate = "pvault-core" },
    { allow = ["GPL-3.0-only"], crate = "pvault-cli" },
    # Milestone 4 (proposed): quirc-derived code in rqrr (ISC).
    { allow = ["ISC"], crate = "rqrr" },
    # Milestone 4 (proposed): hasher used by rqrr's LRU cache (Zlib).
    { allow = ["Zlib"], crate = "foldhash" },
    # Milestone 4 (proposed): Option helpers used by directories (MPL-2.0).
    { allow = ["MPL-2.0"], crate = "option-ext" },
]
```

The global allowlist is unchanged. All three licenses are compatible with
GPL-3.0-only (MPL-2.0 through its Secondary License clause, which applies
because no Exhibit B notice is attached).

### 12.4 Notices

Until release notice tooling exists (SI-04, Milestone 13),
`THIRD_PARTY_NOTICES.md` gains, when the dependencies are added:
- `rqrr`: the MIT text and the **ISC notice of quirc** (copyright Daniel Beer), which must accompany copies;
- `option-ext`: the MPL-2.0 notice and where its source is available (crates.io, version 0.2.0); MPL-2.0 requires that recipients of a binary can obtain the covered source;
- `foldhash`: the Zlib notice (attribution in binaries is optional under Zlib; included anyway);
- the MIT-only crates (`lru`, `simd-adler32`): their copyright and permission notices.

## 13. Q1 investigation

**Evidence.** Run 37391563815 (`windows_native_locality_probe`):
`FileRemoteProtocolInfo` returned error 998 (`ERROR_NOACCESS`) for the local
NTFS temp folder, the `subst` drive, the loopback UNC path and the
loopback-mapped SMB drive. The SMB paths were refused by Q2 (error 3), so the
decision held.

**Analysis (not yet proven).** Error 998 is the Win32 translation of
`STATUS_ACCESS_VIOLATION` and of `STATUS_DATATYPE_MISALIGNMENT`. Both are
raised while the I/O manager validates the caller's buffer, **before** the
request reaches a file system or the SMB redirector. Getting the same error
for a remote handle, where the redirector should answer, is therefore
consistent with the query never reaching the protocol layer. The likeliest
causes are the output buffer's alignment (the probe passes a stack value of a
type whose alignment is 4 bytes) or size, not the volume. This is a
hypothesis; nothing is changed until evidence confirms it.

**Plan (Milestone 4, step 11; diagnostics only):**
1. Extend the native probe to record, for each path, the raw NTSTATUS of `NtQueryInformationFile(FileRemoteProtocolInformation)` with buffers aligned to 4, 8 and 16 bytes, and the result of `GetFileInformationByHandleEx` with an 8-byte-aligned buffer.
2. Run it on local NTFS, `subst`, loopback UNC and mapped SMB in CI.
3. Report the results. If an aligned buffer makes Q1 succeed for SMB and fail with one consistent error for local volumes, propose (for your decision) fixing the buffer and accepting only that local result; Q2–Q4 stay exactly as they are. If not, record Q1 as non-discriminating.

The decision logic and the accepted results are not changed by the
investigation itself.

## 14. Windows console checklist (manual acceptance gate; prepared, not performed)

Run on a real Windows 10 or 11 console (`conhost` and Windows Terminal, both),
with a release-mode build of the Milestone 4 binary and a test vault in a
scratch folder. Record the Windows version, terminal and result of each step.

| # | Step | Expected |
| --- | --- | --- |
| 1 | `pvault init` with a generated passphrase; at the type-back prompt type the words | No characters echo; the prompt line ends cleanly; the next shell prompt echoes normally |
| 2 | Same, but press Ctrl-C at a hidden prompt | The console mode is restored, then the process ends through the default Ctrl-C handling (`echo %ERRORLEVEL%` shows -1073741510, `STATUS_CONTROL_C_EXIT`; not exit 7, see 17, O2); echo is normal in the shell |
| 3 | Same, but press Ctrl-Break | As step 2 (native termination, not exit 7) |
| 4 | Same, but close the terminal window at a hidden prompt; open a new one | No pvault process remains (Task Manager); the new terminal behaves normally |
| 5 | A custom passphrase with leading and trailing spaces, typed twice | Accepted with the whitespace warnings; unlock with the same text works |
| 6 | A custom passphrase containing a non-BMP character (for example 😀) and an accented character typed with a dead key | Accepted; unlock with the same input works; a different combining form is treated as equal after NFC |
| 7 | At the hidden card prompt, paste the card text as printed (7 lines, with spaces and line breaks) | Accepted after the 7th line; nothing echoed |
| 7a | At the hidden card prompt, type all 216 symbols on one line | Accepted; nothing echoed |
| 7b | At the hidden card prompt, paste the text followed by one extra symbol | Refused ("The card text has more than 216 symbols."); echo restored |
| 7c | At the hidden card prompt, paste the card text followed by two extra lines of text; wait for the next hidden prompt | The card is accepted; the extra lines are not used as the next answer (they were discarded before that prompt appeared); only input typed after the prompt appeared is read |
| 8 | Type 1,025 characters at a hidden prompt | Refused with the length message; echo restored |
| 9 | Redirect input from a file without `--secrets-stdin` | Refused (exit 6) |
| 10 | Use `--secrets-stdin` from a console (no redirection) | Refused |
| 11 | Use `--secrets-stdin` with custom-mode lines supplied by a small script that writes lines 1 and 2, waits for "Card files written", then writes the two card lines (one line each) and the type-back line | The vault is created; the printing acknowledgment comes from the console; nothing else is read |
| 12 | Check that no passphrase or card text appears in the console history (Up arrow, `doskey /history`) | Absent |
| 13 | As step 11, with `--card-a-png <a.png>` (four lines: two passphrase lines, Card B's line, the type-back line). When the console shows "Print both cards and save the PNG photos at the paths you gave, then press Enter.", only then save a PNG photo of the printed Card A at `<a.png>` and press Enter in the console | The photo is read only after Enter; the vault is created; standard input supplied exactly four lines |
| 14 | Run step 13's command where no console exists: a scheduled task running as you, with standard input from a file and output to files | Refused with "Verifying a card from a PNG photo needs a terminal …" (exit 6); neither the vault folder nor the settings folder was created |
| 15 | Run `pvault list <vault>` in the console (no `--secrets-stdin`); at the hidden passphrase prompt press Ctrl-Z then Enter | Not a cancellation: the console delivers U+001A as a character, which is refused as input (exit 1, not 7); echo is restored. (Exit 7 at a hidden prompt is Unix end of input, Ctrl-D, tested in CI.) |

The gate passes only when you record every step as expected. Until then,
`docs/SPEC_ISSUES.md` keeps the Windows console marked unvalidated.

Build the binary for the gate with `cargo build --release --locked -p
pvault-cli` (never with `fault-injection`). Use a scratch settings folder by
setting `PVAULT_CONFIG_DIR` to an empty folder, and a scratch card folder.
Record for each step: Windows build number, terminal (`conhost` or Windows
Terminal), what you typed or pasted, what was shown, and the exit code.

### 14a. Printed-card photo check (manual acceptance gate; prepared, not performed)

Synthetic distortions are tested in CI (section 6.1); this gate checks real
prints and real cameras. One platform suffices.

1. Build a release binary (`cargo build --release --locked -p pvault-cli`)
   and set `PVAULT_CONFIG_DIR` to an empty scratch folder.
2. Run `pvault init <scratch>/vault --mode portable --cards-dir
   <scratch>/cards` in a terminal (generated passphrase; interactive, so the
   printing acknowledgment pauses the run). The cards are generated during the
   run: do not press Enter at "Press Enter after printing." until step 4 is
   done.
3. Print both SVG files at 100 % scale on plain paper (note the printer and
   paper).
4. Photograph each printed card with a phone and convert each photo to PNG
   (at most 4,096 pixels per side and 16 MiB; note the conversion tool).
   Take at least: (a) straight on in daylight; (b) rotated about 15°; (c)
   tilted about 30° (perspective); (d) indoor low light; (e) one photo
   showing both cards.
5. Press Enter. At "Card A: enter the path of a PNG photo …" give photo (a)
   of Card A; at Card B give photo (a) of Card B. Then type the passphrase
   back. Expected: both accepted and the vault is created.
6. Second run (a new vault folder; repeat steps 2 to 4 with the new prints; each card allows
   three attempts). Card A: attempt 1, Card B's photo (expected "Card A does
   not match what was printed."); attempt 2, photo (e) (expected "More than
   one QR code was found in the image."); attempt 3, photo (b) (expected:
   accepted). Card B: photo (c). Third run: photo (d) for both cards.
7. For one card, choose Enter instead of a path and type the 7 printed lines
   by hand (expected: accepted after the 7th line).

Record every photo: card, conditions, resolution, result and message. The
gate passes if every straight photo (a) is accepted, no photo of a wrong card
is ever accepted, and the results for (b) to (e) are recorded (a rejection of
a hard photo is a measured limit, not a failure, but it is reported). Shred
the prints and delete the scratch folders afterwards; they hold recovery
cards of a scratch vault.

## 15. Decisions (all approved 2026-10-05; `docs/SPEC_ISSUES.md` 10.14)

| # | Decision | Section |
| --- | --- | --- |
| A1 | `docs/CLI.md` as drafted: exit codes (5 also covers an export published without confirmed durability); message wording; the output and rendering rules (1.1, 1.2); whole-line card entry (exactly 216 symbols after a complete final line); discarding pending terminal input at every hidden prompt (Unix `TCSAFLUSH`; **Windows `FlushConsoleInputBuffer`, an addition to the 7.6a terminal scope**); one-line card input under `--secrets-stdin`; export publication and its failure classes; the non-interactive `init` branch table; `--kdf-*`; `--card-*-png` read at verification time; required `--mode portable` (K1); generated mode only with a terminal (K2); strong-only non-interactive custom passphrases (K3); `status` content (K5); the name-length rule (K7) | CLI |
| A2 | The per-user record design: location, privacy check, name-based management inside the private settings folder, schemas and caps; the two storage policies (durable registration for tracking records on 8.5-supported local settings folders, otherwise refusal; best effort for the rollback record); the identity rule (held-handle deletion in process; after a restart only with matching birth time; otherwise never) | 7 |
| A3 | The `update` journal record (schema addition to 8.1: op `update`, phases `staged`, `committing`, `cleaned`, five new field names), the `add`/`rm` protocol and crash table, the ownership rules, the unresolved-cleanup handling (journal retained, reads continue, mutations stop, `CLOSE UNFINISHED CLEANUP` as the only Milestone 4 closure), and the 8.4 amendment that lets ordinary-unlock commands resolve `update` journals | 9 |
| A4 | The leftover confirmation `DELETE VAULT LEFTOVERS <8 hex>`, its candidate sets, and the journal-temp exception while a journal is pending | 9.7 |
| A5 | Source-file opening, change detection and the stated limits | 10 |
| A6 | The card-file lifecycle (registration before share bytes; held-handle deletion), cleaner and destination rules (SI-10 completion), including the documented empty-unrecorded-file window | 11 |
| A7 | Dependency pins and features, the three crate-specific license exceptions, and the notices | 12 |

Routine work that needs no further decision: the module layout and
`pvault-tests`; the first-header commit by no-replace rename; owner-only
Windows ACLs; PNG test fixtures; failpoint forwarding; the Python card
vectors and the `card_parse` target; the Q1 diagnostics.

## 16. Preserved decisions and limitations

- W1, P1, N1 to N5. Windows power loss can break a vault; WO-1 to WO-3 are unverified.
- Milestone 3 approvals (D1 to D8, audit corrections) and the 2026-10-05 decisions (missing tracking temp block, handle-relative Windows operations, failure-boundary messages, `libfuzzer-sys` for fuzzing only).
- Process-crash tests only; no power-loss claim on any platform.
- Outstanding Windows coverage: ReFS, mounted VHD, real remote SMB; Q1 did not discriminate in the observed tests (section 13).
- Milestone 2 limitations: Job Object limits deferred; Windows console unvalidated until section 14 passes; the RFC/IETF excerpt question (SI-04).
- Third-party notices were unchanged at readiness-review time; the Milestone 4
  implementation adds the section 12.4 notices when it adds the dependencies.

## 17. Implementation status and open items (2026-10-06)

Milestone 4 is implemented and unaccepted. Acceptance needs the native CI
jobs on Linux, macOS and Windows and both manual gates (14, 14a).

**Decided 2026-10-06:**

| # | Decision | Implementation and tests |
| --- | --- | --- |
| O1 | PNG card verification during `init` needs the terminal device, also with `--secrets-stdin`; without one it is refused before anything is written; photos are opened only after the terminal printing acknowledgment; the documented line counts (3 to 5) are unchanged | `init` and the CLI refuse first (exit 6; neither the vault nor the settings folder is created). The test-only synchronization marker is removed. `png_verification_waits_for_terminal_acknowledgment` runs the real CLI with a pseudo-terminal (Unix): the photos are written only after the acknowledgment prompt appears and Enter is pressed after they are complete (3-line and 4-line branches, wrong photo, missing photo). A mutation that stops the CLI waiting makes the test fail. Windows: manual gate 14, steps 13 and 14 |
| O3 | Owner-only access stays required, **fail closed**: exported plaintext and card files go only to file systems pvault identifies as local and enforcing owner-only access in their kernel driver (table below); everything else is refused (exit 6, explanation, suggested destination) before any destination file, record entry or secret; vaults elsewhere stay readable. No permission-setting call is taken as proof | `platform::fs::is_private_destination_type` and `check_private_destination` (an unidentifiable volume is refused); called by the CLI before the unlock (`export::check_destination`), again in `get` on the handle it writes through, and in `init` before the bootstrap and again on the card-folder handle. Tests: `private_destinations_required_for_exports_and_cards` (mocked: FAT/exFAT names, `fuseblk`, `fuse.*`, network, `zfs`, `overlay`, unknown, empty, unidentifiable), `windows_destinations_fail_closed` (local NTFS passes; the same folder through `\\localhost\C$` is refused), `unverifiable_destinations_are_refused` (real CLI with empty standard input: Linux `/proc`, macOS `/dev`, Windows loopback share), `fat_exfat_images` (real FAT, exFAT and Linux `fuseblk` images) |
| O2 | The signal and console handlers stay as accepted (restore, then default action). Native termination is not cancellation | `docs/CLI.md` 3 separates native termination (Unix: killed by the signal; Windows: `STATUS_CONTROL_C_EXIT`) from exit 7 (declined prompt; Unix end of input at a hidden prompt). `native_termination_and_cancellation` (real CLI, pseudo-terminal): Ctrl-D gives exit 7, Ctrl-C ends the process by SIGINT; echo restoration is covered by the terminal module's pty tests. Windows: checklist steps 2, 3 and 15 (Ctrl-Z is a character there, not end of input) |

**Native names (checked against the approved design, 2026-10-06).** The
approved design (7.2, `docs/CLI.md` 1.2) records native paths: Unix bytes,
Windows UTF-16. The implementation had narrowed handle-relative names to
valid Unicode; that restriction is removed. Every folder-relative operation
takes a native name (`OsStr`): `get` destinations and their `.pvpartial`, the
vault folder at `init`, recorded export and card paths in the cleaner.
Vault paths stay strict Unicode (7.8; section 8). What remains is imposed by
the platform, not by pvault:

- Windows: `\` separates components in the native namespace, so a name
  cannot contain it; unpaired surrogates are allowed.
- Unix: `/` and NUL cannot occur in a name.
- File systems may reject names themselves: APFS refuses invalid UTF-8
  (`EILSEQ`), so the non-UTF-8 tests skip on APFS and run on Linux CI
  (ext4); FAT and exFAT have their own character rules.

Tests: `non_unicode_native_names_export_record_and_cleanup` (export,
native recording, confirmed cleanup, `init` into such a folder; Unix byte
0xFF, Windows unpaired surrogate) and the Linux part of
`native_paths_are_rendered_safely` (real CLI: export, crash, listing with
`\xFE`, terminal-confirmed cleanup).

**Real-destination results (macOS 27, 2026-10-06, after O3):** disposable `hdiutil` images, and `/dev` (`devfs`) as an unknown type.

| Check | FAT32 (`msdos`) | exFAT |
| --- | --- | --- |
| `init` with the vault on the image | Refused (8.5 message, exit 6), nothing created | Same |
| Copied vault on the image | `list`, `get` to a private destination, `status` work; `add`, `rm` refused (exit 6); vault files unchanged | Same |
| `get` to the image (normal and over-long names) | Refused (exit 6, O3 message); no destination file or partial; nothing recorded | Same |
| `init --cards-dir` on the image | Refused (exit 6, O3 message); no card file, no vault folder, nothing recorded | Same |

`/dev` (`devfs`, an unknown type for destinations): `get` and `init
--cards-dir` refused with exit 6 through the real CLI with empty standard
input (no secret read), no destination file, no settings or vault folder.

Before O3, the same images showed the reasons for the decision: an export to
FAT was published with mode `0700` set by the mount; macOS exFAT has no
no-replace rename; stale exports and card files there could only be kept and
reported, never proven and deleted.

Found and fixed by these tests (before O3): a refused no-replace flag
(`ENOTSUP` on macOS exFAT, `EINVAL` on Linux) was reported as a generic I/O
error (exit 1) instead of the approved refusal (exit 6); the fix still
applies to other destinations without that primitive. macOS stores extended attributes
(`com.apple.provenance`) of new files on FAT/exFAT in `._<name>` AppleDouble
sidecars; they hold no file content, and none remained after pvault deleted
its files in these runs.

Linux (loopback `vfat`/`exfat`, mounted `uid`/`gid`/`umask=077`) and Windows
(`diskpart` VHDX, FAT32 and exFAT) run the same `fat_exfat_images` scenario in
native CI with `PVAULT_TEST_REQUIRE_IMAGES` (a missing image fails). Neither
has run yet; the Windows step is unverified until CI runs it. On Windows the
terminal-confirmed cleanup parts are reported as skipped (no pseudo-terminal).

**Supported destinations for exported plaintext and card files (O3, fail closed):**

| Platform | Supported types | Why these | Refused, and why |
| --- | --- | --- | --- |
| Linux | `ext4`, `xfs`, `btrfs`, `tmpfs` | Local kernel file systems that store owner and mode bits and enforce them in the kernel; `tmpfs` in memory (allowed for destinations, not for vaults, which need durability) | `vfat`, `msdos`, `exfat` (no owner or mode storage; the mount decides); `fuseblk`, `fuse.*` (a user-space server decides); `nfs`, `cifs`, `smb3`, `9p` (the server decides); `zfs`, `overlay` and every other or unknown type (not verified; can be added only by a recorded decision) |
| macOS | `apfs`, `hfs` | Local file systems that store and enforce owner and mode bits | `msdos`, `exfat`; `smbfs`, `nfs`, `afpfs`, `webdav`; FUSE; `devfs` and every other type |
| Windows | `NTFS`, `ReFS` on a local volume | Store and enforce the owner-only DACL pvault sets; locality by the 8.5 Q1 to Q4 checks | `FAT`, `FAT32`, `exFAT` (no ACLs); network shares and mapped drives (unidentifiable as local, the server decides); every other type |

Any folder whose file system cannot be identified is refused. Types are
compared exactly as the platform reports them.

**Native-name coverage:** the dedicated CI step "Native-name coverage (no
skips)" runs `non_unicode_native_names_export_record_and_cleanup` and
`native_paths_are_rendered_safely` on Linux (byte 0xFF) and Windows
(unpaired surrogate) with `PVAULT_TEST_REQUIRE_NATIVE_NAMES`; a skip, or a
filter that runs no test, fails the step. On macOS APFS the in-process case
skips with an explicit message (APFS refuses invalid UTF-8); with the
variable set it fails there, as verified locally.

**Validation not performed locally:**

- Linux-only and Windows-only tests (non-UTF-8 names on ext4, the Windows
  DACL readback, Q1 probe, console flush, the Linux and Windows image steps):
  type-checked locally, run only in native CI.
- Name-length behavior on ext4 and NTFS: native CI only (locally APFS, FAT,
  exFAT).
- Windows console behavior: manual gate 14. Printed-card photos: manual
  gate 14a.
