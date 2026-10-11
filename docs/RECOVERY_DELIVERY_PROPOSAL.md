# Paper and digital recovery cards: design revision

**Status:** revision 4 (2026-10-06; SI-52), approved in direction by the
author with corrections, and implemented in Milestone 4 (uncommitted;
Milestone 4 not accepted). G1 (section 3) is implemented. R5 is implemented
as an optional check after the commit (6.5, decided 2026-10-06). Q2 is
superseded (9). Not implemented: R6 (optional). The governing spec
(7.4d), `docs/CLI.md` (6.1, 6.7, 6.8), `docs/FORMAT.md` (card-file format 1)
and `docs/M4_READINESS.md` (7.6, 11.5, 17) describe the implementation; where
a message below differs from those documents, they are authoritative.

Revision 4 applies the author's corrections to revision 3:

- **L1 revised:** card-file input replaces manual card entry only where cards
  are already accepted. Everyday commands (`list`, `get`, `add`, `rm`) keep
  the passphrase; passphrase-free access stays with the Milestone 6
  `recover` path. Section 6.3 lists the authentication of every command.
- **Pair validation separated** from the per-file format check (6.1, 6.2).
- **`discard-card --vault`** compares unauthenticated metadata only, says so,
  and keeps the stronger confirmation (8.3).
- **Q2 superseded** (section 9; decided 2026-10-06): `card_set_id` is not
  added to the init journal; the accepted schema is kept.
- **R5 after the commit** (6.5; decided 2026-10-06): an optional check of
  the kept files once every handle is released; it never rolls back or
  deletes.

## 1. Purpose and summary

pvault currently assumes the owner can print: card files are temporary print
artifacts, deleted after the printed cards are verified. This revision adds
an explicit choice at `init`:

- **Paper mode**, as accepted: print, verify each printout (photo or typed
  text), delete the card files after the commit.
- **Digital mode:** the card files are the deliverable. pvault writes Card A
  and Card B to two owner-chosen folders, verifies them through the same
  reader that recovery (Milestone 6) will use, rehearses a recovery from them, and
  never deletes them after a restart or a commit.

The cryptography does not change: the same 2-of-2 split of the same 96-byte
bundle, the same 135-byte payload, Base32 text, QR code and SVG card file
(7.4, 7.4a, 7.4b). Digital card files can be printed later.

## 2. Decisions

| # | Decision (2026-10-06) | Section |
| --- | --- | --- |
| R1 | Explicit `--cards paper` or `--cards digital`, required for every new vault | 12 |
| R2 | Same folder refused; same volume needs an acknowledgment; separate volumes are not proof of separate devices | 5, 7 |
| R3 | Owner-only protection kept (O3, G1); no FAT/exFAT exception | 7 |
| R4 | Cloud-sync warning for well-known sync folders, explicitly not exhaustive | 7 |
| R5 | Optional re-insertion check **after the commit**, handles released first; a failure changes nothing; interactive `init` only (revised 2026-10-06) | 6.5 |
| R6 | Optional real-drive measurement (not a gate) | 14 |
| R7 | `cards.cbor` version 2 with migration and refusal rules | 9 |
| Q1 | Recovery rehearsal in both modes | 6.4 |
| Q2 | Init journal records `card_set_id`: **superseded** (2026-10-06); the accepted init-journal schema is kept | 9 |
| Q3 | `--accept-risk` also accepted when a terminal is present | 5 |
| Q4 | The card-file reader accepts only the documented pvault card-file format (format 1); no promise of editor compatibility | 6.1 |
| L1 | Card files replace manual card entry only where cards are already accepted; no passphrase-free everyday commands (revised) | 6.3 |
| L2 | Digital cards are never deleted automatically after a restart; cleanup is owner-directed | 8 |

## 3. G1: mounts with ownership ignored (approved, implemented)

On macOS a volume mounted with ownership ignored (Finder's "Ignore ownership
on this volume"; `noowners`; common for external drives) reports `apfs` or
`hfs`, and its folders show the current user and mode `0700`, but nothing is
enforced. Milestone 4 refuses export destinations and card folders there
(exit 6) before any secret is read or written, and treats a settings folder
there as not private. Digital cards on an external drive therefore need that
setting turned off for the drive.

## 4. Modes

| | Paper | Digital |
| --- | --- | --- |
| Card files | Temporary print artifacts in `--cards-dir` | The deliverable, one in `--card-a-dir`, one in `--card-b-dir` |
| Printing acknowledgment | Yes (terminal; required for PNG verification, O1) | None |
| Delivery evidence | PNG photo or typed text of each printout | The saved files, read back through the card-file reader |
| Recovery rehearsal (6.4) | From the photographed or typed cards | From the read-back files |
| After the commit | Card files deleted through the held handles | Card files kept; record entries released |
| Risk acknowledgment | None | `digital-cards`, and `same-volume` when applicable (5) |
| Non-interactive lines (`--custom`) | 3 to 5 (unchanged) | Exactly 3 |

## 5. Acknowledging the digital-storage risks

Acknowledgments are consent, not secrets; they authorize nothing that a
secret protects, so the rule "no secrets in arguments or environment
variables" (F79) is kept. No environment variable can give one.

| Acknowledgment | Required when | Given by |
| --- | --- | --- |
| `digital-cards` | Always in digital mode | `--accept-risk digital-cards`; or, when the option is absent and a terminal exists, the typed phrase `STORE CARDS DIGITALLY` on the terminal device (Q3: the option is accepted with or without a terminal) |
| `same-volume` | Card A's and Card B's folders are on the same volume | `--accept-risk same-volume`; or the typed phrase `SAME DRIVE` |

- Without the option and without a terminal, `init` stops with exit 4 before
  any secret is read or anything is created.
- The risk text (section 10) is printed to standard error in every case,
  including when the option is given.
- `--accept-risk` takes exact tokens; an unknown token, or the option outside
  digital mode, is a usage error (exit 2).
- **Separate volumes are not separate devices.** The same-volume check
  compares volume identities (8.5). Partitions and APFS volumes of one disk,
  several volumes on one USB stick, a disk image stored on the same disk, two
  shares of one server and two synced folders of one account are different
  volumes on one device or account. Physical and account separation is the
  owner's responsibility, and the documentation says so.
- A card folder on the vault's own volume gets a warning without an
  acknowledgment.

## 6. Card files: format, reader, pairs, authentication, rehearsal

### 6.1 Card-file format 1 and the reader (Q4)

**Format 1** is the exact byte output of pvault's card renderer (7.4b) for a
given payload and creation date: an XML declaration, one `svg` element with
fixed attributes, a white background, one QR path, four label lines (role,
vault ID, card set, creation date) and seven Base32 lines, LF line endings,
no byte-order mark. `docs/FORMAT.md` publishes it with a byte-exact vector
(fixed payload and date), generated independently by
`tools/vectors/gen_vectors.py`. The creation date is a label outside the
payload: it is not authenticated, and another well-formed date is another
valid rendering of the same card. Any future change to the renderer is a new format
number; readers keep every earlier format.

**The reader** accepts only format 1, unmodified:

1. Open the file without following links; it must be a regular file of at
   most 64 KiB; read it into wiped memory.
2. Locate the date label and the seven Base32 lines by fixed byte patterns of
   format 1 (bounded scans). No XML parser, no rendering, no QR decoding, no
   entity expansion, no fonts, no external resources of any kind.
3. Decode the Base32 text (exactly 216 symbols) and parse the payload
   (`Card::parse`: magic, version, `check`, mode, `share_x`).
4. Render format 1 again from that payload and date, and require that the
   whole file equals the rendering byte for byte.

The reader validates **one file**. It knows nothing about the other card;
pair rules are a separate step (6.2a).

Step 4 is what rejects ambiguous, duplicate and conflicting content within a
file: a
second card, an extra or missing element, a QR code that encodes another
payload, labels that disagree with the payload (role, vault ID, card set), a
changed date format, CRLF line endings, a byte-order mark or any editor
re-save. The single message is "This is not an unmodified pvault card file
(format 1)."; exit 1. pvault makes no promise about files changed by other
programs. An owner whose file no longer reads can still type its Base32 text
(or use a PNG of a printout) wherever typed text is accepted.

### 6.2 Where card files are accepted

| Command | Milestone | Card-file options | Other card input |
| --- | --- | --- | --- |
| `init`, digital: delivery and rehearsal | 4 | The two saved files, read back (6.4) | None |
| `init`, paper: delivery and rehearsal | 4 | Not accepted: a file is not evidence of a printout | PNG photo or typed text (unchanged) |
| `verify-card` | 6 | `--card-a-file`, `--card-b-file` (portable), `--card-file` (bound) | PNG, typed text |
| `recover` | 6 | As `verify-card` | PNG, typed text |
| `convert` delivery verification | 6 | As `init` for the chosen delivery mode, under `--new-*` option names (M6-K4) | As `init` |

Paths are not secrets; file contents are handled like typed card text.

**Decided 2026-10-11 (`docs/SPEC_ISSUES.md`, M6-K3 and M6-K4):** a PNG photo
of an **old** card that exists before the command (`verify-card`,
`recover`) needs no terminal; O1 still applies to photos of **new**
printouts checked during delivery. The new cards of `recover` and `convert`
are delivered through `--new-*` options (`--new-cards`, `--new-cards-dir`,
`--new-card-a-png`, …), each with the meaning and rules of its `init`
counterpart.

### 6.2a Pair validation

Wherever two cards are used together (digital delivery, the rehearsal, and
in Milestone 6 `verify-card` and `recover`), after each card passed its own
check (6.1 for files, `Card::parse` for typed text and photos), the pair is
checked before any Shamir operation:

| Check | Refusal |
| --- | --- |
| Same `share_x` (two Card A, two Card B, or one card given twice) | "These two cards are both Card A." / "… both Card B." |
| Roles: portable needs one `share_x` = 1 and one = 2, and each in its expected position when the command names roles (`--card-a-*`, `--card-b-*`) | "This is Card B, not Card A." (and the reverse) |
| `vault_id` differs between the cards | "These two cards belong to different vaults." |
| `set_id` differs | "These two cards are from different card sets." |
| `mode` differs, or is not the vault's | "This card is for a vault of the other mode." |
| Against the expected vault (the candidate core at `init`; the vault's header in Milestone 6) | "This card belongs to another vault." / "This is an old card." |

These are public-field checks (5.8): specific messages are allowed. Only
after them may Shamir combine run.

### 6.3 Authentication of every command (L1, revised)

Card-file input replaces manual card entry where cards are already
accepted; it adds no new way to unlock. Everyday commands keep the
passphrase.

| Command | Authentication | Card input accepted | Milestone |
| --- | --- | --- | --- |
| `init` (new vault) | None; creates the vault | Paper: PNG or typed text of each printout. Digital: the saved files, read back (6.4). Both: used only for delivery and rehearsal | 4 |
| `init` (resume) | Path A or init-journal MAC (5.5, 8.3), as now | None | 4 |
| `list`, `get`, `add`, `rm` | Ordinary unlock with the **passphrase** (5.3, 5.7), duress check, as now | **None.** `--card-*-file` is not an option of these commands (exit 2) | 4 |
| `status`, `clean-partials` | None, as now | None | 4 |
| `discard-card` (new, 8.3) | None: it reads one card file's public fields and deletes only that file after a terminal confirmation; it unlocks nothing | The one file being discarded | 4 |
| `verify-card` | Path B (5.5) | `--card-a-file`/`--card-b-file` (portable), `--card-file` (bound), alongside PNG and typed text | 6 |
| `recover` (passphrase-free recovery) | Path B (6.1) | As `verify-card` | 6 |
| `convert`, `fsck`, `duress`, Revoke, Erase | As spec 5.7 | As spec | 6 to 9 |

### 6.3a (withdrawn) Card unlock for everyday commands

Revision 3 proposed passphrase-free `list`, `get`, `add` and `rm` with two
card files. Withdrawn in revision 4 (L1): it would have added a new way to
unlock that bypasses the passphrase and duress for everyday use.

### 6.4 Recovery rehearsal at `init` (Q1)

Before the commit, after delivery verification and before the type-back:

1. **Shares from the delivered cards only.** Digital: reopen each saved file
   by name without following links, require the identity of the handle
   pvault created, and read it through the reader (6.1). Paper: the payloads
   decoded from the PNG photos or typed text that verified each printout.
   The in-memory original shares and bundle are not consulted in steps 2
   and 3.
2. **Recovery path.** `Card::parse`; `check_for_vault` against the candidate
   core (`vault_id`, `card_set_id`, mode); `check_pair`; Shamir `combine`;
   bundle from the 96 bytes.
3. **Against the candidate header.** The candidate header is the exact
   header that the commit would write (already built, not yet written).
   Its `core_mac` and `slots_mac` must verify under the recovered `K_mac`,
   and `keytable.1.pv` (whose digest the candidate core names) must
   authenticate and decrypt under the recovered key-table keys.

Any failure rolls the setup back (8.1). Passing proves that this pvault can
open this exact header and key table from these exact delivered cards. It
does not prove that the media will keep the files, that the owner stores the
cards apart, or that printouts stay readable. `verify-card` (Milestone 6)
checks stored cards later.

### 6.5 Optional card check after the commit (R5; decided 2026-10-06)

An earlier text placed this check before the commit, where it conflicted with
the held-handle rule (an open handle prevents ejecting a drive, and 8.1
deletes through those handles). As decided, it runs **after** the commit:

1. `init` finishes completely: commit, card entries released (D7), card-file
   handles closed, card-operation lock and vault lock released, "Vault
   created: …" printed.
2. Only for an **interactive** digital `init` (a terminal and no
   `--secrets-stdin`): "The vault has already been created. Optional check:
   pvault has closed the card files, so you can now eject the drives that
   hold them, insert them again, and let pvault check that both cards read
   back and recover the vault. A failed check changes nothing: the vault
   stays, and no card file is deleted." Then the confirmation "Type CHECK
   after re-inserting the drives to check the card files, or press Enter to
   skip:" on the terminal device. Anything but `CHECK` skips. A
   non-interactive `init` omits the check.
3. With `CHECK`: each saved path is opened afresh without following links,
   read through the strict reader (6.1), and the two cards go through the
   recovery rehearsal (6.4) against the header and key table as stored now,
   under a shared vault lock. File identity is not compared (a re-inserted
   drive may present new identities); content is checked by the reader and
   the rehearsal, which proves the files are this vault's current Card A
   and Card B. No copy of the cards is kept in memory while the owner
   re-inserts the drives.
4. Passed: "Card check passed: <A> (Card A) and <B> (Card B) read back and
   recover this vault." (exit 0). Failed: "The vault was created, but the
   card check failed: <reason> The vault is unchanged and no card file was
   deleted. Check the drives and the card files before relying on them."
   (exit 1). Nothing is rolled back, deleted or unregistered either way.

This narrows, but does not close, the gap that a read-back may come from the
operating system's cache; it proves nothing about the drive's future.

## 7. Destinations (R2, R3, R4)

- Both digital folders: exist, are not links, are not inside the vault, are
  not the same folder (exit 2), pass O3 and G1. Removable drives need a
  supported, ownership-enforcing file system (APFS or HFS+ with ownership
  enabled on macOS; ext4, XFS or Btrfs on Linux; NTFS on Windows), which may
  not be readable on other systems.
- Same volume: acknowledgment (5). Vault's volume: warning.
- Cloud syncing: a best-effort warning for well-known sync roots (iCloud
  Drive `~/Library/Mobile Documents`; `~/Library/CloudStorage/*`; Windows
  `%OneDrive%`, `%OneDriveConsumer%`, `%OneDriveCommercial%`; `~/Dropbox`).
  The warning says that other sync tools, NAS replication, backups and
  folder redirection are not detected, so no warning does not mean not
  synced.

## 8. Deletion and cleanup of digital cards (L2)

### 8.1 Automatic deletion: only inside the running `init`, before `committing`

| Failure point | Action |
| --- | --- |
| Before the `committing` journal record is written (delivery, rehearsal, type-back, end of input, cancellation, any error) | The process knows the commit has not started. Delete both files **through the handles it created** (7.2), flush, remove the entries: "The setup was rolled back. The card files (card set `<id>`) are invalid; if you copied them anywhere, delete those copies." |
| After the `committing` record was written, whatever happens next | **Retain** files and entries; report that they may be the vault's current cards |
| After the commit | Release (8.2) |

### 8.2 After a restart: never automatic

After a restart pvault **never deletes a digital card file automatically**,
in any command. Authenticated evidence available then is not enough: an
authenticated init journal in a pre-commit phase may be an old copy restored
from a backup or snapshot, so it does not establish that the setup never
completed; a missing header, an inaccessible or moved vault folder, or a
wrong passphrase prove nothing either. pvault retains the files and
reports them.

| Situation | Action (no deletion) |
| --- | --- |
| End of a successful `init` | Remove the entries; keep the files |
| `init` resume with an authenticated header whose `vault_id` and `card_set_id` equal the entry's | Remove the entries; "Your recovery card files are …" |
| `init` resume of a setup without a header | Roll back the vault folder as now (8.3); the card entries stay; the message names the card files and their card set as **probably invalid**, and points to 8.3 |
| `clean-partials` | Lists digital entries (path, role, vault folder, card set, created time). `FORGET <n> CARD RECORDS` removes the entries only, keeping the files |
| `fsck` (Milestone 6) | Reports; never deletes |

### 8.3 Owner-directed cleanup: `pvault discard-card`

```text
pvault discard-card <card-file> [--vault <vault-dir>]
```

The owner names one file to destroy; pvault never chooses files.

1. Open the file without following links and read it through the reader
   (6.1); anything but an unmodified card file is refused (nothing deleted).
2. Show its public fields: role, vault ID, card set, and the creation date
   as a label ("labeled as created <date>"; not authenticated, 6.1).
3. With `--vault`: read that vault's **public** header (no secret, shared
   lock) and compare its `vault_id` and `card_set_id` with the card's. This
   is an **unauthenticated metadata comparison**: the header fields are not
   verified (no secret is used), so anyone who can write the vault folder
   could make them say anything. The output says so in every case: "Not
   verified: the header of <vault-dir> names this card's set as its current
   card set." (or "… names a different card set as current (this card may be
   old)", or "… names a different vault"), followed by "These header fields
   were read without any secret; anyone who can write that folder could have
   changed them." pvault never claims
   that a card is or is not current: verified membership needs both cards
   and Path B (`verify-card`, Milestone 6), which `discard-card` does not do.
4. Because membership is never verified here, the confirmation is always the
   stronger one: `DISCARD RECOVERY CARD <first 8 hex of the card set>` on the
   terminal device, after "pvault cannot verify whether this is a current
   card. Destroying a current card leaves the vault recoverable only with the
   passphrase or another copy of this card." Without a terminal: refused
   (exit 4). No option replaces this phrase.
5. Delete through the handle opened in step 1 (7.2, same-process rule;
   Windows deletes that handle); flush the folder; remove any matching
   `cards.cbor` entry.
6. Print the remnants warning (section 10).

`discard-card` is the only way pvault deletes a digital card after its
`init` process ended.

## 9. Schema changes (R7, Q2)

| Item | Change |
| --- | --- |
| `cards.cbor` | Version 2: each entry gains `delivery` (text `"paper"` or `"digital"`) and `vault_path` (bytes, 7.2 native path encoding of the vault folder) |
| Init journal (8.1, `op: "init"`) | **Unchanged (Q2 superseded, decided 2026-10-06).** The init-journal schema, including the exact field presence per phase, was accepted in Milestone 3, and `testdata/pvault_journal.txt` publishes independently generated init records (`init-portable-prepared`, `init-bound-committing`). A new field would either invalidate those vectors or need an optional-field exception to the accepted presence rules. Why it is no longer needed: the field was proposed so that a restart could prove which card set an interrupted setup had written, and delete files of a set that never committed. Under L2 nothing is deleted after a restart, so no such proof is required. What a restart still does needs no journal field: each `cards.cbor` entry records its own `vault_id` (fresh for every setup) and `set_id`, and `init` resume compares that `set_id` with the `card_set_id` of the authenticated header to release current cards and label the others probably invalid |
| Card-file format | Format 1 frozen and published in `docs/FORMAT.md` with a byte-exact vector |
| Header, key table, objects, `partials.cbor`, `rollback.cbor`, card payload | Unchanged |

`cards.cbor` compatibility:

- **Reading:** versions 1 and 2. A version 1 entry is a paper entry (only
  paper mode wrote version 1) with no vault path.
- **Writing and migration:** every update writes version 2; a version 1
  record is migrated by the first update under the record lock with the 7.3
  atomic replacement. Reading never rewrites.
- **Refusal:** an unknown or newer version, or a schema failure: never
  changed and never used for any decision; card writing, `discard-card`'s
  record step and `clean-partials` report the record path (exit 6).
- **Downgrade:** a version-1-only pvault sees version 2 as newer and refuses
  to touch it; nothing is deleted.
- **Paper entries in version 2** carry `delivery: "paper"`; `vault_path` is
  present in entries this version writes and absent in entries migrated
  from version 1 (the path was never recorded). Digital entries always carry
  it.

## 10. What the owner is told

Printed with the `digital-cards` acknowledgment (summary) and in the user
documentation (full):

- **Separate storage.** Card A and Card B together open the vault without the
  passphrase. Different media, different places; never one drive, one cloud
  account, one backup set or one bag. Ideally neither is on the vault's
  computer; never both. Copies of the same card may be kept together.
- **Device loss.** The medium holding a card is that card. With the
  passphrase forgotten and one card lost, the vault cannot be recovered.
  Keep at least two copies of each card; flash storage left unpowered can
  lose data; check cards later (`verify-card`, Milestone 6).
- **Cloud syncing.** A synced card is copied to the provider, every device on
  the account, version history and trash.
- **Deleting does not erase.** Flash cells, snapshots (APFS, Time Machine,
  shadow copies, Btrfs), backups, cloud history and trash, other synced
  devices, thumbnails (which can show the QR code), search indexes and recent
  files lists can keep a deleted card. Destroy a medium that held a card, or
  replace the card set.
- **Both cards are full recovery.** Anyone with both files can recover the
  vault without the passphrase (Milestone 6 `recover`), and recovery does
  not involve duress.
- **What pvault deletes.** Only invalid card files of a setup that failed
  before its commit, inside that same run; otherwise only the file the owner
  names to `discard-card`.

## 11. Digital lifecycle

| Step | Action | Crash here leaves | Handled by |
| --- | --- | --- | --- |
| D0 | Before any secret: options (R1); folders (7); acknowledgments (5); settings registration; record room and version (9) | Nothing | n/a |
| D1 | Card-operation lock C | Empty lock file | Any cleaner |
| D2 | Create both files empty, exclusively, owner-only, no-follow; keep the handles | Empty, unrecorded files | Not tracked; the resume message names both folders |
| D3 | Register both entries (version 2) | Recorded empty files | 8.2, 8.3 |
| D4 | Write each SVG through its handle; flush files and folders | Recorded card files of an uncommitted set | 8.2, 8.3 |
| D5 | Delivery read-back, rehearsal (6.4), type-back | As D4 | 8.1 in process; 8.2, 8.3 after |
| D6 | `committing` record, header commit | Possibly current cards | Retained (8.1, 8.2) |
| D7 | Release: close handles, remove entries, release C | Current cards, entries possibly left | 8.2 |
| D8 | Optional card check after the commit (6.5), interactive only, nothing held | Current cards, nothing pending | n/a (read only) |

## 12. Exact CLI changes

| Command | Change |
| --- | --- |
| `init` | New required `--cards <paper\|digital>` for a new vault. Paper: `--cards-dir` and `--card-a-png`/`--card-b-png` as now. Digital: new `--card-a-dir <dir>`, `--card-b-dir <dir>` (both required), `--accept-risk <digital-cards\|same-volume>` (repeatable). Mixing mode options: exit 2. Resume (`pvault init <vault>`) takes no card options |
| `init`, digital, interactive | After "Vault created", the optional card check (6.5): `CHECK` or Enter to skip; exit 1 if the check fails, with nothing rolled back |
| `list`, `get`, `add`, `rm` | **Unchanged** (passphrase; L1 revised) |
| `discard-card` | New command (8.3): `pvault discard-card <card-file> [--vault <vault-dir>]`; terminal confirmation required |
| `clean-partials` | Lists digital entries without deleting them; new confirmation `FORGET <n> CARD RECORDS` (entries only). Paper entries unchanged |
| `status` | Unchanged (shows the card set, used by 8.3) |
| `verify-card`, `recover` | Milestone 6: the card-file options of 6.2 and 6.3 |

New messages: "This is not an unmodified pvault card file (format 1)."; "Card
A and Card B cannot be saved in the same folder."; the same-volume and
vault-volume warnings; the sync warning; the risk text; the pair messages
(6.2a); the rollback message (8.1); the resume
message for retained cards (8.2); the `discard-card` texts (8.3). Exit codes
are unchanged in meaning: 2 usage, 4 a missing acknowledgment or declined
confirmation, 6 a refused destination or record, 1 a card or unlock failure.

## 13. Acceptance tests (F93 to F102)

| Test | Content |
| --- | --- |
| F93 | Card-file reader, format 1, per file: generated files accepted (both roles; byte-exact vector in `docs/FORMAT.md`); rejected with nothing used: one changed byte anywhere (text, QR path, labels, date), a second card appended, a missing line, CRLF, a BOM, a `DOCTYPE` or entity, a file over 64 KiB, a symlink, a directory |
| F94 | Pair validation: one file given twice, two Card A, two Card B, roles swapped against `--card-a-*`/`--card-b-*`, different `vault_id`, different `set_id`: each refused with its message before any Shamir operation |
| F95 | Digital `init`: `--secrets-stdin` reads exactly 3 lines; no printing acknowledgment, also with a terminal; both files remain byte-identical afterwards and are never deleted; entries released |
| F96 | Rehearsal from delivered cards only: replacing a saved file with a valid card of another set, swapping the two files, or substituting another vault's card makes delivery or the rehearsal fail and roll back although the in-memory originals are intact; paper mode: a photo or typed text of another card fails the same way; the candidate header's MACs and `keytable.1.pv` are what is checked |
| F97 | In-process rollback before `committing` deletes both digital files through the held handles; any failure after the `committing` attempt retains them |
| F98 | After a restart nothing deletes a digital card: crash at every D step, then `init` resume and `clean-partials` (also with `FORGET`): files always retained; resume releases current cards and labels probably invalid ones |
| F99 | `discard-card`: refused without a terminal and for a non-card or modified file; `--vault` output labeled unverified; always the stronger phrase; deletes only the opened file (a file swapped after opening is not deleted); entry removed; remnants warning |
| F100 | Acknowledgments: `digital-cards` and `same-volume` by option (with and without a terminal) and by typed phrase; missing without a terminal: exit 4, nothing read or created; no environment variable accepted. Everyday commands reject `--card-*-file` (exit 2) |
| F101 | Destinations and records: same folder exit 2; FAT/exFAT and an ownership-ignored APFS image refused (exit 6) for each digital folder; two images accepted; sync warning under a listed sync root. `cards.cbor` v1 read and migrated to v2 by the first update; newer version refused unchanged; a version-1-only reader refuses v2 (the same newer-version rule, tested as version 3 against this reader; the version-1-only decoder of commit `4ae2254` accepts only version 1 and treats anything else as damaged, never changed) |
| F102 | Card check after the commit (R5): not offered without an interactive terminal; Enter skips; `CHECK` after the card folder was removed and recreated (an eject and re-insertion) passes, which also shows no `init` handle is open; a changed, swapped or missing file fails with exit 1 and "The vault was created", the vault unchanged and no file deleted |

Existing tests stay, including every paper-mode test and the G1 and O3
refusal tests.

## 14. Gates

| Gate | Applies to | Status |
| --- | --- | --- |
| Printed-card photo check (readiness 14a) | Paper mode only; not evidence for digital mode | Outstanding (first attempt cancelled; no result) |
| Windows console checklist (readiness 14) | Terminal behavior; digital mode adds the typed acknowledgments, the 3-line branch, `discard-card` and the card check after the commit (steps 16 to 20b) | Outstanding |
| Real-drive measurement (R6) | Digital mode, optional; not a gate | Optional |
| Native CI | Both modes | Not yet run for the SI-52 implementation (uncommitted); the last green run (commit `4ae2254`) predates it |

## 15. Out of scope

- Encrypting card files with a password (changes the cryptography).
- Mixed delivery (one paper card, one digital card).
- Editor-modified card files and other file formats (a later format number).
- Automatic copying to several destinations or to cloud services.
