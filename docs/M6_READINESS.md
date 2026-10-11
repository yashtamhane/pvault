# Milestone 6 readiness review

Prepared 2026-10-11 as a **documentation-only review**. No Milestone 6 code,
dependency, CI change or spec decision is made here. Except where a decision
is recorded as made by the author (P1), every proposal below, including the
CLI drafts in Appendix A, is for the author's approval. Acceptance criteria
are quoted, not changed.

**Status when this was written:**

- **Milestone 4:** implemented and **not accepted**. Both manual gates are
  outstanding: the Windows console checklist (`docs/M4_READINESS.md` 14,
  including digital steps 16 to 20b) and the printed-card photo check (14a).
- **Milestone 5:** **accepted on 2026-10-11 as emulator-tested work only**
  under exception E2 (`docs/SPEC_ISSUES.md`): not real-TPM validation, not
  complete secret-memory wiping, not release readiness. Real-hardware
  validation stays required before any bound-mode release.
- **Open items carried forward:** E1 (a timing failure observed under
  concurrent emulated load), V3's unknown original cause, the isolated-test
  runner's single process-start window, the accepted `tpm2-tss` memory
  limitation, and the licensing questions in `THIRD_PARTY_NOTICES.md`
  (`docs/M5_READINESS.md` 14 and 15).

Sources: `CLAUDE.md`; `PVAULT_BUILD_SPEC.md` sections 0, 4, 5.5 to 5.8, 6,
7.4, 8.1 to 8.5, 9.2, 9.3, 9.6, 11, 13 and 16; `docs/SPEC_ISSUES.md` (SI-29,
SI-31, SI-35, SI-36, SI-37, SI-40, SI-41, SI-52, the "Before Milestone 6"
list, E2); `docs/CLI.md`; `docs/RECOVERY_DELIVERY_PROPOSAL.md`;
`docs/M4_READINESS.md`; `docs/M5_READINESS.md`; the code at `b047a75`.

## 1. Sequencing: decided E0 (author, 2026-10-11)

Spec 0 item 1: "Do not start the next milestone until the current one's
acceptance criteria pass." Exception E2 covered Milestone 5 only. Milestone 4
is still unaccepted, so Milestone 6 needs either Milestone 4 acceptance or a
new, explicit exception.

**Decision (P1): E0.** Milestone 6 work is limited to documentation and
decisions (sections 4 and 5, Appendix A) until both Milestone 4 gates pass.
No Milestone 6 code is written and **no new sequencing exception is
granted**. Both Milestone 4 gates stay outstanding and unchanged.

Why it matters more than for Milestone 5: `recover`, `verify-card` and
`convert` take recovery cards as typed Base32 text, PNG photos and card
files, which is the card-entry and card-reading code the two gates exercise.
A gate finding could change code that Milestone 6 builds on.

The alternatives considered and not chosen were E3a (Milestone 6 work that
takes no card input: `fsck`, the recovery and `convert` state machines,
rotation) and E3b (all of Milestone 6 while Milestone 4 stays unaccepted, as
E2 did). Either would need a new, explicit authorization.

### 1.1 What completing the two Milestone 4 gates requires in practice

Neither gate is passed, and neither may be removed or weakened without an
explicit, recorded author decision. Both are written in
`docs/M4_READINESS.md` 14 and 14a.

**Windows console checklist (14).**

| Need | Detail |
| --- | --- |
| A real Windows 10 or 11 console | Both `conhost` and Windows Terminal. A Windows virtual machine is a real console for this purpose, but the checklist records the Windows build and terminal, so note it if a VM is used |
| A Windows build of the binary | `cargo build --release --locked -p pvault-cli` on Windows needs Rust (rustup, the 1.89+ toolchain) and the Visual Studio C++ Build Tools. No CI job publishes a Windows binary today; publishing one as a CI artifact would be a CI change needing approval (and artifacts of a public repository are publicly downloadable) |
| Which commit | The gate was written for the Milestone 4 binary (`b6baa13`). The current `main` also contains Milestone 5: interactive `init` now offers "Type SET DURESS to create a duress passphrase now, or press Enter to skip", which the checklist does not list. Choose one before starting: `b6baa13` exactly, or current `main` with that extra prompt answered by Enter (recommended: current `main`, recording the commit and the extra prompt, because that is the code that will ship) |
| Scratch data only | `PVAULT_CONFIG_DIR` set to an empty folder; scratch vault and card folders; never real data |
| A USB drive formatted NTFS | Steps 20a and 20b (eject and re-insert) |
| Task Manager, Notepad, Task Scheduler | Steps 4, 20b, and 14 and 19 (a scheduled task with no console) |
| **A printed card** | Step 13 photographs "the printed Card A". This step needs a printer (or a print service) like the photo check. Steps 7 to 7c need the card text, which the card SVG file contains; they need no printer |
| Time | About 2 to 3 hours including setup; every step is recorded (build number, terminal, input, output, exit code) |

**Printed-card photo check (14a).**

| Need | Detail |
| --- | --- |
| A printer, plain paper, 100 % scale | Three runs, each printing a fresh pair of scratch cards (6 printouts) |
| A phone camera and a PNG conversion tool | Photos (a) to (e) per run; at most 4,096 pixels per side and 16 MiB |
| One platform | macOS is enough ("One platform suffices") |
| Afterwards | Shred the prints and delete the scratch folders |

**No printer available (2026-10-11).** Options, none of which passes or
removes the gate by itself:

1. **Print elsewhere** (a library, a copy shop, an office or a friend's
   printer). The cards belong to a disposable scratch vault, so printing them
   outside reveals nothing of value; still, never print a card of a real
   vault this way, check that the output is at 100 % scale, and shred the
   prints afterwards. This keeps the gate exactly as written.
2. **Borrow or buy a printer.** Same gate, no change.
3. **Ask for a recorded amendment** (author's decision only), for example
   photographing cards shown on a screen. That would test the QR reader and
   the camera path but not paper prints, so it would be a weaker, different
   gate and must be recorded as such, never as the original gate passing.

Option 1 also covers step 13 of the Windows checklist if the Windows session
happens where a printer is available.

## 2. Scope (spec 13, row 6)

> Recovery (both modes, and directly to portable), bundle rotation,
> write-ahead journal, dual-MAC transition records, full-share card
> verification, duress choices, `fsck`, `convert`

Carried into Milestone 6 by earlier milestones:

- the `fsck` halves of F33 and F72 (Milestone 4 delivered the `get` halves);
- the `fsck` half of F88 (unknown `NV_DefineSpace` outcome; Milestone 5
  delivered the `init` half);
- card-file input for `verify-card`, `recover` and `convert` (spec 7.4d;
  `docs/RECOVERY_DELIVERY_PROPOSAL.md` 6.2 and 6.3; `docs/CLI.md` 5);
- recovery-time card mode checks (a bound card offered for a portable vault
  and the reverse, `docs/M5_READINESS.md` 14, F17 note);
- replacing the Milestone 4 interim `CLOSE UNFINISHED CLEANUP` closure with
  `fsck` (`docs/M4_READINESS.md` 9.5);
- the rule that verification-only paths never update the local generation
  record (`docs/M4_READINESS.md` 7.4; F66).

**Out of scope:** destructive features and the duress **trigger action**
(Milestone 9, behind the Milestone 8 review gate; duress stays **inactive**:
a match is a generic failure with no mutation); K2 (Milestone 10); mounting
(Milestone 11); `recover --rekey-files` (SI-37, deferred; rotation does not
rotate object keys, 6.11); real TPM hardware (no access is authorized);
bound mode outside Linux (Milestone 17).

## 3. Acceptance tests (spec 13 row 6 and section 11)

| Area | Tests |
| --- | --- |
| Recovery, both modes, and to portable | F21 (bound, index missing: new index, bundle rotated), F22 (portable A + B after Revoke), F23 (old card fails after recovery), F55 (old `slots_mac` fails: old index never deleted), F80 (`recover --to-portable` without a TPM) |
| Crash safety and journal | F25 (crash after every recovery step a to q, every journal phase, the post-header flush), F26 (`convert` part), F44 (crash after the commit m), F45 (crash after `committing`, before m), F54 (crash after defining the new index, before writing S2'), F69 (`init` re-run with recovery or convert journals among the residue) |
| Index ownership (9.2b) | F27, F28, F29a, F29b (decoy may be deleted, documented), F53 (unknown owner-range index reported, never deleted), F83 (identical definition on another TPM, second `swtpm`) |
| Card verification | F24, F47 (partial Base32, one wrong character, truncated QR: rejected), F68 (delivery verification in recovery and `convert`), F63 (duress passphrase on `verify-card` and recovery paths; portable Path B has no duress check) |
| Duress across recovery | F46, F57, F82 |
| `fsck` | F31 (without unlock: reports only), the `fsck` halves of F33, F72 and F88, F53 |
| `convert` | F32, F26, F68, F82 |
| Other | F8 (slots corrupted: daily unlock fails, recovery succeeds), F18 (rollback warning), F66 (verification-only paths: no TPM needed, generation record never updated) |

Proposed, needing approval: **F86** (P2) and the further tests named in
section 5.

## 4. What already exists, and what is missing

| Component | Where | Milestone 6 use |
| --- | --- | --- |
| Transition journal (`op: recover/convert`; phases `prepared`, `target_created`, `committing`, `tracking_created`, `rollback_tracking`), dual MACs, scope-3 tokens | `journal.rs` (Milestone 3) | The write-ahead journal itself; Milestone 6 writes it |
| Header commit with the generation check; remote-rollback tracking; old-side and new-side restart | `store.rs` (`commit_header`, `start_tracking`, `resume_old_side`, `resume_new_side`; Milestone 3 crash tests) | Executes recovery and `convert` commits; the rollback decision is Milestone 6 |
| Header core with `generation`, `card_set_id`, `tpm_cleanup`; TPM identity tokens (scopes 1, 2, 3 and 5) | `header.rs`, `tpmid.rs` | Rotation, cleanup tracking, cross-machine rules |
| Cards: payload, Base32, QR, PNG reader, card-file format 1, pair and mode checks, delivery and rehearsal | `card.rs`, `card/`, `vault/init.rs` (Milestone 4) | Reading old cards (Path B); phase 2 delivery verification of new cards |
| Bound layer: define, write, read, undefine, 9.2a reads, 9.2b removal, handle allocation, salted sessions | `tpm/`, `vault/bound.rs` (Milestone 5) | New index, retiring old indexes, F27 to F29b, F53, F83 |
| Duress: tag computation, new duress words, set and disable | `vault/duress.rs` (Milestone 5) | The three recovery choices (6.7) |
| Per-user records and the partials cleaner | `records.rs`, `vault/discard.rs`, `clean-partials` (Milestone 4) | `fsck`, F33, F66 |
| Pending-journal detection | `vault/mod.rs` (`pending`) | A recovery or conversion journal is reported today; Milestone 6 resolves it |
| Test support: failpoints, CLI crash scenarios, `swtpm` per test, the isolated test process | `failpoints.rs`, `tests/failure_scenarios.rs`, `tpm/testing.rs`, `test_process.rs` | F25 and F26 matrices; a second `swtpm` for F83 |

**Missing:** the `recover`, `verify-card`, `convert` and `fsck` commands
(drafted in Appendix A); Path B as an entry point; bundle rotation and
new-card delivery inside recovery; the duress choices during recovery;
`fsck`'s report and repair rules.

## 5. Pending decisions P1 to P10

Summary (details below):

| # | Decision | Proposed resolution |
| --- | --- | --- |
| P1 | Sequencing | **Decided: E0** (section 1) |
| P2 | `recover --use-tpm` (SI-29, F86) | Approve as an explicit, never automatic, bound-only option |
| P3 | `convert` (SI-31, spec 6.9) and its phrases | Confirm the draft; phrases with the vault-ID prefix |
| P4 | CLI sections for the four commands | Approve Appendix A after review |
| P5 | Recovery details left open in SI-35 | Argon2 defaults with optional `--kdf-*`; checked generation; capacity reserved |
| P6 | Remaining SI-36 parts | Confirm as specified; remote re-entry of a bound old duress passphrase through the old token |
| P7 | `fsck` scope and SI-40 deletion rules | Report-only by default; `--repair` after an unlock; authenticated deletion only |
| P8 | Duress during recovery (6.7) | Approve the three choices; non-interactive rules as below |
| P9 | Test environment | Reuse the Milestone 5 setup; pin the TPM CI runners; F83 with two emulators |
| P10 | Real-hardware validation | Not needed for Milestone 6 acceptance; still required before release |

### P1. Sequencing

Decided E0 (section 1). Not repeated here.

### P2. `recover --use-tpm`: recovery with S2 + S3 when `s1_*` is damaged (SI-29)

- **Proposed resolution:** approve `recover --use-tpm` for bound vaults
  only, as an explicit owner choice, never an automatic fallback. It needs a
  header that parses, a core whose `core_mac` verifies, the slots fields
  `tpm_nv_index`, `tpm_nv_name`, `tpm_policy_nonce` and `s2_nonce`, the
  index present on this TPM, the passphrase and the bound card. It derives
  `k_s2wrap` and `tpm_auth`, makes a provisional read under 9.2a, unwraps
  S2, combines S2 (x = 2) with S3 (x = 3), verifies `core_mac`, then checks
  the old `slots_mac`, which normally fails, so `old_slots_authenticated` is
  false. Recovery then continues from 6.2. The old index is kept and
  reported (F55 rule), and duress choice 1 is not offered.
- **Alternatives:** (b) defer and record that a bound vault with damaged
  `s1_*` cannot be recovered (the current 6.1 limitation), with backups as
  the only remedy; (c) an automatic fallback when the S1 path fails,
  rejected because every failed recovery would then also make a TPM read
  that counts against the dictionary-attack limit, and the owner would not
  know which path ran.
- **Security:** no new capability: the path needs the passphrase, the TPM
  and the card, which is more than an ordinary unlock (passphrase and TPM).
  The TPM read uses provisional, unauthenticated slot fields, as the
  ordinary unlock already does, so the 9.2a checks (exact public area and
  post-write Name before `NV_Read`) apply unchanged. A wrong passphrase costs
  one dictionary-attack count, as an unlock does.
- **Usability:** rescues one specific damage case, which is rare. A rarely
  used option must be documented clearly; the failure message stays
  `Unlock failed.` for secret-dependent failures.
- **Schema impact:** none. It uses existing slots and the existing
  `recover` journal.
- **Tests:** F86 (corrupt `s1_ct`; passphrase + TPM + card recovers; the old
  index is reported); a wrong passphrase with `--use-tpm` counts one
  dictionary-attack failure and changes nothing; refused when the index is
  absent (`Unlock failed.` or a public-state message, per 5.8); never chosen
  without the option.

### P3. `convert` (SI-31, spec 6.9) and its confirmation phrases

- **Proposed resolution:** confirm 6.9 as drafted: ordinary unlock with the
  duress check; a typed confirmation; a new bundle, salt, `set_id` and card
  set; a newly generated passphrase for bound to portable; for portable to
  bound, the owner's passphrase, the identity measurement (N2) and the
  write-ahead index creation; delivery verification; the dual-MAC commit;
  retirement of the old index only under 9.2b. Phrases: `CONVERT TO
  PORTABLE <8 hex>` and `CONVERT TO BOUND <8 hex>`, where the hex is the
  first 8 hex characters of the vault ID, like `DELETE INIT LEFTOVERS
  <8 hex>`.
- **Alternatives:** the spec's phrases without the vault-ID suffix (shorter,
  but a habitual phrase could convert the wrong vault); a `--yes` option
  (rejected: confirmations come only from the terminal, `docs/CLI.md` 2).
- **Security:** bound to portable removes the TPM factor, so the new
  passphrase becomes the only barrier besides the cards; generating it (not
  letting the owner type a weak one) keeps that barrier strong. Old cards
  stop working at the commit. An old index on another TPM cannot be removed
  from here (remote old-index limitation, 6.8).
- **Usability:** a full card delivery and, for bound to portable, a new
  passphrase to learn. Needs a terminal (confirmation; generated
  passphrase).
- **Schema impact:** none (`op: "convert"` exists since Milestone 3).
- **Tests:** F32, F26 (`convert` part), F68, F82; refused on file systems
  that fail 8.5; portable to bound refused before any write when the TPM
  identity cannot be measured; a wrong confirmation changes nothing (exit
  4); delivery of cards with the new mode byte.

### P4. CLI sections for `recover`, `verify-card`, `convert` and `fsck`

- **Proposed resolution:** review and approve Appendix A, then fold it into
  `docs/CLI.md` before any code (as for Milestones 4 and 5).
- **Open choices inside the drafts:**
  - option names for the **old** cards (`--card-a-file`, `--card-a-png`, as
    the delivery proposal names them) versus the **new** cards delivered
    during `recover` and `convert` (proposed: `--new-cards`,
    `--new-cards-dir`, `--new-card-a-dir` and so on, so old and new can
    never be confused);
  - whether portable `recover` may take `--custom` for the new passphrase
    (proposed: no; 6.3 b generates it, and recovery is when a strong
    passphrase matters most);
  - `fsck` as report-only by default with a separate `--repair` (P7).
- **Security:** card text stays a secret (hidden or one standard-input
  line); file and photo paths are not secrets; confirmations come only from
  the terminal; no new environment variables.
- **Usability:** the commands mirror `init`'s delivery options, so owners
  meet the same prompts.
- **Schema impact:** none.
- **Tests:** the usage errors (mixed or missing options, exit 2), the
  `--secrets-stdin` line orders, and the messages, as for Milestone 4.

### P5. Recovery details left open in SI-35

Already decided for Milestone 5 (D3) and reused: handle allocation, the
`TPM_RC_NV_DEFINED` restart and the unknown-outcome rule.

- **Proposed resolution:**
  - **Argon2 parameters** for the new salt: the current defaults, which must
    pass 4.3 on this machine (6.3 b), with the same optional `--kdf-memory`,
    `--kdf-iterations` and `--kdf-parallelism` as `init` (same bounds, same
    low-memory warning) for a machine where the defaults fail;
  - **`new_gen`** = `old_gen + 1` with a checked add; at `u64::MAX` the
    operation is refused before any write ("generation limit reached");
  - **cleanup capacity** reserved before the journal is written: an
    operation that may add a `tpm_cleanup` entry refuses at 32 unresolved
    entries, never evicting one.
- **Alternatives:** keep the old Argon2 parameters (rejected: it would
  carry a weak setting forward through every recovery); defaults only, no
  options (simpler, but a recovery on a small machine would then be
  impossible).
- **Security:** recovery re-tunes the key derivation to current defaults;
  lowering it is explicit and warned.
- **Usability:** recovery works on smaller machines with an explicit
  choice.
- **Schema impact:** none (the core already records Argon2 parameters,
  `generation` and `tpm_cleanup`).
- **Tests:** recovery records the defaults in the new core; refused, before
  any write, where the defaults fail 4.3 and no option is given; generation
  overflow refusal (a synthetic header at `u64::MAX`); the 33rd cleanup
  entry is refused without eviction.

### P6. Remaining SI-36 parts: cross-machine and TPM-less recovery

The token format (scopes 1, 2, 3 and 5), the H-2 identity (D4) and the
same-TPM deletion rule are already implemented (Milestones 3 and 5).

- **Proposed resolution:** confirm as specified:
  - on every rotation, every authenticated old cleanup token is decrypted
    and re-encrypted under the new `K_mac` (scope 5, fresh nonce) before
    any new file is created; a failure aborts before side effects;
  - duress choice 1 for a **bound** old tag verifies the re-entered
    passphrase with the old `ek_digest` obtained by opening the old slots'
    scope-1 token, so no old TPM is needed;
  - the remote old-index limitation (6.8) stays documented: an old index on
    another machine is reported, never deleted from here.
- **Alternatives:** offer duress re-entry only when the old TPM is present
  (simpler, but a recovery on another machine would always lose the old
  duress passphrase).
- **Security:** a token's AAD, scope or AEAD failure is corruption and never
  authorizes deletion; deletion still needs the live TPM measurement and
  every 9.2b check.
- **Usability:** a vault recovered elsewhere can keep its duress passphrase.
- **Schema impact:** none new; the fields exist since Milestone 3.
- **Tests:** F80, F83, F25; cleanup entries survive two rotations and still
  authorize deletion only on their own TPM; bound duress re-entry during a
  recovery with no TPM present.

### P7. `fsck`: scope and the SI-40 deletion rules

- **Proposed resolution:**
  - **`pvault fsck <vault>` reports only**, with no secrets and the exclusive
    lock (spec 5.7, 8.2 rule 1): the header's structural state, a pending
    journal (operation and phase, labeled unauthenticated), journal-temp
    residue, files that are not part of the vault layout, and stale partial
    exports recorded for this vault. It deletes nothing and touches no TPM
    index.
  - **`pvault fsck <vault> --repair`** first unlocks: with the passphrase
    (ordinary unlock, duress check), or with recovery material (Path B;
    `--recovery`) when only cards are available. It then applies the 8.2
    restart tables, resolves the F88 unknown define outcome by Name, works
    through `tpm_cleanup` under 9.2b, and removes files only on the SI-40
    authenticated basis (a key table that decrypts under the current
    bundle, an object listed in an authenticated key table or journal, a
    temp named by an authenticated journal). Everything else is reported,
    and deleted only after the owner confirms an exact list by a typed
    phrase, for regular files opened without following links, never
    directories.
  - It replaces the Milestone 4 interim `CLOSE UNFINISHED CLEANUP` closure
    and includes the stale-partials cleanup of `clean-partials` for this
    vault.
- **Alternatives:** a single `fsck` that repairs whenever it can unlock
  (spec text allows it, but the owner then cannot look before acting);
  deleting unauthenticated leftovers by name pattern (rejected by 8.2
  rule 4).
- **Security:** nothing is deleted on a file name or pattern alone; every
  index deletion passes 9.2b including the same-TPM rule; an owner-range
  index no authenticated record mentions is never touched (F53).
- **Usability:** a safe first look, then an explicit repair.
- **Schema impact:** none for `fsck` itself. SI-40's rules need the author's
  approval (spec 8.2 rule 4 is still marked PENDING); approving them makes
  that rule concrete without a format change.
- **Tests:** F31, the `fsck` halves of F33, F72 and F88, F44, F45, F53,
  F54, F27 to F29b; report-only `fsck` on every crash state of F25 deletes
  nothing; the confirmation list removes exactly the listed files.

### P8. Duress during recovery (spec 6.7)

- **Proposed resolution:** approve 6.7 as drafted: (1) re-enter the existing
  duress passphrase, offered only when the old slots authenticated and hold
  a tag, verified against the old tag before a new tag is written; (2)
  generate a new one, shown once and typed back; (3) disable, confirmed with
  `DISABLE DURESS`. When the old tag is unavailable, only 2 and 3; when
  bound duress is unavailable on this TPM (9.3), only 3, with the reason. The
  N3 notice (D7) applies when a duress passphrase results. The trigger stays
  inactive until Milestone 9.
  - **Without a terminal** (`--secrets-stdin`): choice 1 by a `--duress
    reenter` option, its passphrase as one standard-input line; choices 2
    and 3 need the terminal (a shown secret; a confirmation), so a
    non-interactive recovery of a vault with a duress tag stops (exit 4)
    unless `--duress reenter` is given.
- **Alternatives:** silently drop duress on recovery (rejected: a stale or
  missing tag would surprise the owner); carry the old tag (rejected by
  6.7: it would stop working without notice).
- **Security:** no stale tag is ever written; a re-entered passphrase is
  verified against the authenticated old tag, never by typing it twice.
- **Usability:** owners keep their duress passphrase when possible.
- **Schema impact:** none (`duress_tag` in the slots exists).
- **Tests:** F46, F57, F82, F63; the non-interactive refusal.

### P9. Test environment

- **Proposed resolution:**
  - reuse the Milestone 5 setup: `swtpm` with fresh state per test, short
    lockout settings where a test drives failures, the local container
    recipe, native Linux CI with `PVAULT_TEST_REQUIRE_SWTPM`;
  - every recovery and `convert` test that starts `swtpm` or another process
    runs in the isolated test process (`test_process.rs`, V2);
  - F83 with two emulators in one test;
  - failpoints named after the recovery steps (`recover.a` to `recover.q`,
    plus every journal phase and the post-header flush) for the F25 and F26
    matrices, run both in process and through the real CLI;
  - pin the Linux TPM jobs to `ubuntu-24.04` (instead of `ubuntu-latest`,
    which moves to Ubuntu 26 from 2026-10-19), and test the newer image
    separately when wanted, so a package change cannot hide inside a
    Milestone 6 result.
- **Alternatives:** keep `ubuntu-latest` (fewer CI changes, but the
  `tpm2-tss` and `swtpm` versions would change under the milestone).
- **Security:** none to the product; tests never touch a real TPM.
- **Usability:** longer Linux test jobs, since the crash matrices run one
  test at a time in the isolated process.
- **Schema impact:** none.
- **Tests:** not applicable; this decision sets where the other tests run.

### P10. Real-hardware validation

- **Proposed resolution:** not part of Milestone 6 acceptance, which stays
  on `swtpm`. It remains required before any bound-mode release. A future
  authorization would name the device, how owner authorization is supplied,
  that no destructive TPM operation (clear, hierarchy changes) is run, which
  handles may be used, and how test indexes are removed afterwards. **No real
  TPM access is authorized now.**
- **Alternatives:** validating on hardware during Milestone 6 (needs an
  explicit authorization first).
- **Security:** keeps development away from real owner hierarchies.
- **Usability:** none until release.
- **Schema impact:** none.
- **Tests:** the Milestone 5 and 6 bound tests, rerun on hardware when
  authorized.

## 6. Interaction with open items

- **Milestone 4 gates:** section 1. Recovery card input on Windows uses the
  console path that the Windows checklist has not yet validated.
- **Milestone 5 limitations:** bound recovery and `convert` use the same TPM
  stack, so the accepted `tpm2-tss` memory limitation applies unchanged, and
  the CLI's logging override covers them.
- **Test runtime:** the crash matrices multiply process starts; under the V2
  isolation they run one at a time, which lengthens the Linux jobs.

## 7. Proposed sequence (once Milestone 4 is accepted or an exception is granted)

1. Approve P2 to P10 and Appendix A in one decision record, as D1 to D12
   were for Milestone 5; fold the CLI sections into `docs/CLI.md`.
2. `fsck` report-only, then `--repair`.
3. Path B entry and portable recovery (A + B), with bundle rotation and
   phase 2 delivery verification; `verify-card`.
4. Bound recovery, the new index, old-index retirement under 9.2b;
   `--to-portable`; `--use-tpm` if approved.
5. Duress choices across recovery.
6. `convert` both ways.
7. Crash matrices, index-ownership tests, the remaining F-rows, native CI and
   the acceptance record.

## Appendix A. Proposed CLI sections (draft; not approved; not implemented)

**PROPOSAL for review (P4).** Nothing here is part of `docs/CLI.md` until
the author approves it. Conventions, exit codes, global options and message
rules are those of `docs/CLI.md` 1 to 4 and 7: secrets are never arguments
or environment variables; card text is a hidden prompt or one
standard-input line under `--secrets-stdin`; confirmations and shown secrets
use only the terminal; every secret-dependent failure is `Unlock failed.`
(exit 1).

### A.1 `pvault verify-card` (Path B; verification only)

```text
pvault verify-card <vault-dir>                    (portable: Card A and Card B)
            [--card-a-file <file> | --card-a-png <file>]
            [--card-b-file <file> | --card-b-png <file>]

pvault verify-card <vault-dir>                    (bound: passphrase and the bound card)
            [--card-file <file> | --card-png <file>]
```

- **Authentication:** Path B (spec 5.5), shared lock, **no writes**, no TPM,
  no duress check. A portable vault needs both cards together (spec 7.4a
  note: one portable card proves nothing alone).
- **Flow:** preflight and shared lock; parse the header (structural errors:
  `Unlock failed.`); bound: the hidden passphrase prompt; each card from its
  file, its PNG photo, or the hidden card prompt; the per-card and pair
  checks (`docs/RECOVERY_DELIVERY_PROPOSAL.md` 6.1 and 6.2a, public-field
  messages allowed); combine; verify `core_mac`; read and decrypt the key
  table.
- **Rollback record:** if the vault's generation is older than recorded, the
  rollback warning is shown; the record is **never updated** (F66).
- **Output:** "The cards recover this vault (card set <8 hex>)." (portable)
  or "The passphrase and this card recover this vault (card set <8 hex>)."
  (bound), exit 0. A duress passphrase entered here fails like any wrong
  passphrase.
- **`--secrets-stdin` line order:** bound: passphrase, then the card text
  (unless a file or photo is given); portable: Card A text, then Card B text
  (each only when no file or photo is given).
- **Exit codes:** 0, 1 (`Unlock failed.` or a card refusal), 2, 3, 6.

### A.2 `pvault recover` (Path B; rotates the bundle)

```text
pvault recover <vault-dir>                         (portable: Card A + Card B)
            [old cards: --card-a-file|--card-a-png <file>] [--card-b-file|--card-b-png <file>]
            --new-cards paper --new-cards-dir <dir> [--new-card-a-png <file>] [--new-card-b-png <file>]
          | --new-cards digital --new-card-a-dir <dir> --new-card-b-dir <dir> [--accept-risk ...]
            [--words <10-16>] [kdf options] [--duress reenter]

pvault recover <vault-dir>                         (bound: passphrase + bound card)
            [old card: --card-file|--card-png <file>] [--use-tpm]
            --new-cards paper --new-cards-dir <dir> [--new-card-png <file>]
          | --new-cards digital --new-card-dir <dir> [--accept-risk digital-cards]
            [kdf options] [--duress reenter] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]

pvault recover <vault-dir> --to-portable           (bound vault; no TPM needed)
            [old card: --card-file|--card-png <file>]
            (new-card options as for a portable recovery) [--words <10-16>] [kdf options] [--duress reenter]
```

- **Authentication:** Path B, exclusive lock, no duress check (spec 5.7).
- **Flow:** (1) preflight, exclusive lock, header; (2) old material (bound:
  passphrase, then the old card; portable: Card A, Card B), pair checks,
  combine, `core_mac`, `old_slots_authenticated`; (3) key table (6.2);
  rollback warning; (4) the new passphrase: portable target, **generated
  and shown once on the terminal** (`--words`, default 12; no `--custom`,
  P4); bound target: the owner's passphrase is kept; (5) "Deriving keys…",
  the `prepared` journal, bound: the identity measurement (N2; refused with
  an offer of `--to-portable`), handle, index define and write (6.3 d to f),
  the new key table; (6) duress choice (P8); (7) the new cards rendered and
  delivered exactly as `init` (paper: print acknowledgment, photo or typed
  text; digital: files, risk acknowledgments, read-back), then the
  rehearsal of the new cards against the new header; portable: type-back of
  the new passphrase; (8) the dual-MAC `committing` record, the header
  commit, old-index retirement under 9.2b (or tracking in `tpm_cleanup`),
  old key-table removal by digest, journal removal; (9) "Recovery complete:
  <vault> (<mode>, generation <n>). Old cards no longer open this vault, but
  they still open older copies of it: shred them."
- **Phase 2 failure or abort:** nothing old is modified; the old passphrase,
  cards and index keep working (6.4 k); "Nothing was changed; the old cards
  and passphrase still work." (exit 1 or 7).
- **`--secrets-stdin` line order:** bound: passphrase; old card text (unless
  a file or photo); the TPM owner authorization (when declared); the
  re-entered duress passphrase (with `--duress reenter`); the new card text
  lines (paper, unless photos); portable target: the type-back of the new
  passphrase (the generated passphrase itself is shown only on the terminal,
  so a portable target needs the terminal device).
- **Exit codes:** 0; 1 (`Unlock failed.`, a card refusal, a failed
  delivery); 2; 3; 4 (a pending journal of another operation, a duress
  choice that needs the terminal, a declined confirmation); 5 (outcome
  uncertain: run `fsck`); 6 (file system, resources, TPM refusals); 7.

### A.3 `pvault convert` (ordinary unlock; rotates the bundle)

```text
pvault convert <vault-dir> --to portable
            --new-cards paper|digital (delivery options as A.2, portable)
            [--words <10-16>] [kdf options] [--tpm ...] [--tpm-owner-auth]

pvault convert <vault-dir> --to bound
            --new-cards paper|digital (delivery options as A.2, bound)
            [kdf options] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]
```

- **Authentication:** ordinary unlock with the duress check, exclusive lock.
- **Confirmation (terminal only):** `CONVERT TO PORTABLE <8 hex>` or
  `CONVERT TO BOUND <8 hex>` (P3); a wrong or missing confirmation:
  "Not confirmed. Nothing was changed." (exit 4).
- **Flow:** spec 6.9: unlock; confirmation; for a bound target, the identity
  measurement before any write; prepare (new bundle, salt, `set_id`, cards;
  bound to portable: a newly generated passphrase, shown once); duress
  choice (P8, with the old tag available because the unlock authenticated
  the slots); delivery and rehearsal of the new cards (mode byte = the
  target); type-back for a portable target; dual-MAC commit; retirement under
  9.2b; "Converted <vault> to <mode> (generation <n>). Old cards no longer
  open this vault: shred them."
- **Refusals:** a file system that fails 8.5 (exit 6); a bound target
  without TPM support or whose identity cannot be measured (exit 6, nothing
  written); `--to` equal to the current mode (exit 2).
- **`--secrets-stdin` line order:** the passphrase; the TPM owner
  authorization (when declared); the re-entered duress passphrase (with
  `--duress reenter`); the new card text lines; the type-back for a portable
  target. The confirmation needs the terminal, so `convert` needs it too.

### A.4 `pvault fsck`

```text
pvault fsck <vault-dir>                         (report only; no secrets)
pvault fsck <vault-dir> --repair                (after an ordinary unlock with the passphrase)
pvault fsck <vault-dir> --repair --recovery     (after Path B with the cards)
            [card options as A.1] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]
```

- **Report only (no options):** exclusive lock; no secrets; nothing deleted;
  no TPM index touched (spec 8.2 rule 1). It prints, from public state only
  (5.8, SI-41): the header's structural state, mode and generation (labeled
  unauthenticated), a pending journal's operation and phase (unauthenticated),
  journal-temp residue, files outside the vault layout, the recorded stale
  partial exports for this vault, and the number of `tpm_cleanup` entries
  (unauthenticated). Exit 0 when nothing needs action, 4 when the owner must
  act, 5 when a state is indeterminate.
- **`--repair`:** unlock (ordinary, with the duress check; or `--recovery`:
  Path B); verify the journal MAC with the matching bundle; apply the 8.2
  restart tables and the F88 resolution; resolve `tpm_cleanup` entries
  under 9.2b on the matching TPM (an entry for another TPM is reported and
  kept); remove files only on the SI-40 authenticated basis (P7); list
  everything else and, after the typed confirmation `DELETE LISTED FILES
  <8 hex>` (terminal only), remove exactly that list; clean this vault's
  stale partial exports with confirmation, as `clean-partials`. An index in
  the owner range that no authenticated record mentions is reported, never
  touched.
- **`--secrets-stdin` line order:** `--repair`: the passphrase; the TPM
  owner authorization (when declared). `--repair --recovery`: as A.1.
  Deletions of unauthenticated files need the terminal (confirmation);
  without it they are reported and left (exit 4).
- **Exit codes:** 0, 1, 2, 3, 4, 5, 6.
