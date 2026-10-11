# Milestone 6 readiness review

Prepared 2026-10-11 as a **documentation-only review**; section 5 and
Appendix A revised the same day after the author's review (findings 1 to
7). No Milestone 6 code,
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

Revised 2026-10-11 after the author's review (findings 1 to 7). Every item
remains a proposal; nothing here is approved or implemented. The questions
that would have changed accepted rules were decided by the author (5a,
M6-K1 to M6-K5), and the governing records are aligned with them.

Summary (details below):

| # | Decision | Proposed resolution |
| --- | --- | --- |
| P1 | Sequencing | **Decided: E0** (section 1) |
| P2 | `recover --use-tpm` (SI-29, F86) | Approve as an explicit, never automatic, bound-only option, with the check order below |
| P3 | `convert` (SI-31, spec 6.9) | Confirm the draft; public TPM preflight before any secret is read; phrases decided (M6-K5) |
| P4 | CLI sections for the four commands | Review Appendix A, aligned with M6-K1 to M6-K5 |
| P5 | Recovery details left open in SI-35 | Headroom of 2 generations before any transition write; Argon2 decided (M6-K2) |
| P6 | Remaining SI-36 parts | Confirm as specified |
| P7 | `fsck` scope and SI-40 deletion rules | Report-only by default; `--repair` after an unlock; deletion only against an authenticated live set; pruning by same-TPM re-verification |
| P8 | Duress during recovery (6.7) | The three choices; what each needs without a terminal |
| P9 | Test environment | Reuse the Milestone 5 setup; pin the TPM CI runners; F83 with two emulators |
| P10 | Real-hardware validation | Not needed for Milestone 6 acceptance; still required before release |

### 5a. Decisions M6-K1 to M6-K5 (author, 2026-10-11)

These questions would otherwise have changed or narrowed an accepted rule,
so they went to the author. They were called K1 to K5 in review; they are
recorded as **M6-K1 to M6-K5** because `docs/CLI.md` 9 already numbers its
conflicts K1, K2, … and spec 13 uses "K2" for the drive-type feature
(Milestone 10). The decisions settle these questions only: P2 to P10 and
Appendix A remain proposals, and no Milestone 6 work starts (E0).

| # | Question | Decision | Records aligned |
| --- | --- | --- | --- |
| M6-K1 | Kind of the replacement main passphrase (portable recovery, `recover --to-portable`, `convert` bound → portable). Spec 6.3 b, 6.8 and 6.9 said "generate"; the approved SI-51 lifecycle allows both kinds | **SI-51 applies:** generated (`--words`, default 12) or custom (`--custom`), with SI-51's creation rules exactly as at `init`: a custom passphrase entered twice, the character refusals and warnings, the NFC notice, the creation-time estimate (Strong continues; Medium needs the terminal confirmation `ACCEPT MEDIUM PASSPHRASE`; Weak or an estimator failure is refused). A generated passphrase is shown only on the terminal | Spec 6.3 b, 6.8 and 6.9 now say "create … generated or custom (SI-51)"; SI-51 unchanged |
| M6-K2 | Argon2 parameters for the new salt at recovery and conversion | **`init`'s bounded options:** the defaults (1,024 MiB, t = 4, p = 4) unless `--kdf-memory` (256 to 4,096), `--kdf-iterations` (3 to 16) or `--kdf-parallelism` (1 to 8) is given; the same 4.3 policy and resource checks, and the same warning below 1,024 MiB ("Lower memory makes passphrase guessing cheaper."). Checked before any write | Spec 6.3 b and 6.9; SI-35 item 2 |
| M6-K3 | PNG photos of **old** cards without a terminal | **No terminal requirement** for an old-card photo that exists before the command (`verify-card`, `recover`, `fsck --repair --recovery`). O1 is unchanged and still applies to photos of **new** printouts checked during delivery (`--new-card-*-png`), which are created during the run | `docs/RECOVERY_DELIVERY_PROPOSAL.md` 6.2; `docs/SPEC_ISSUES.md` |
| M6-K4 | Option names for the new cards | **`--new-*` consistently** in `recover` and `convert`: `--new-cards`, `--new-cards-dir`, `--new-card-a-png`, `--new-card-b-png`, `--new-card-png`, `--new-card-a-dir`, `--new-card-b-dir`, `--new-card-dir`, each with the meaning and rules of its `init` counterpart. `--accept-risk` keeps its name | `docs/RECOVERY_DELIVERY_PROPOSAL.md` 6.2 (`convert` row) |
| M6-K5 | `convert` confirmation phrases | **Vault-ID prefixed:** `CONVERT TO PORTABLE <8 hex>` and `CONVERT TO BOUND <8 hex>`, the hex being the first 8 hex characters of the vault ID as pvault prints it (like `DELETE INIT LEFTOVERS <8 hex>`) | Spec 6.9; SI-31 |

Additions that change no accepted rule: `fsck --repair` as a separate option
(spec 5.7 and 8.2 do not require repair on every unlock); `--duress
reenter` for non-interactive recovery (spec 6.7 defines no non-interactive
behavior).

### P1. Sequencing

Decided E0 (section 1). Not repeated here.

### P2. `recover --use-tpm`: recovery with S2 + S3 when `s1_*` is damaged (SI-29)

An earlier draft listed "a core whose `core_mac` verifies" as a prerequisite.
That was circular: `core_mac` can be checked only with the bundle that this
path reconstructs. The order below separates checks on public, still
unauthenticated data from the authentication that follows reconstruction.

- **Proposed resolution:** approve `recover --use-tpm` for bound vaults
  only, as an explicit owner choice, never an automatic fallback, with this
  order:
  1. **Structural checks (public data, before any secret is used and before
     any TPM access):** the header parses under 4.4 (canonical CBOR, field
     caps); the Argon2 parameters pass the hard caps (4.3); the core's `mode`
     is bound; the slots fields used here are present with exact types and
     lengths: `tpm_nv_index` in the owner range `0x01800000` to
     `0x01BFFFFF`, `tpm_nv_name` 34 bytes with the SHA-256 name-algorithm
     prefix, `tpm_policy_nonce` 32 bytes, `s2_nonce` 24 bytes. These values
     are **provisional**: nothing about them is trusted yet.
  2. **Card checks (public fields):** the bound card parses and its `check`
     field verifies (7.4a); its `mode` is bound, its `vault_id` equals the
     header's, its `set_id` equals the header's `card_set_id`, and its share
     index is 3. A mismatch is refused with the public-field message before
     any TPM access, so a wrong card never costs a dictionary-attack count.
  3. **TPM checks before the read (9.2a):** connect (`--tpm`); C2 and C3
     (storage hierarchy enabled, not in lockout); `NV_ReadPublic` at the
     provisional handle; the public area must be exactly pvault's
     (post-write attributes, data size 97, SHA-256, the `authPolicy` derived
     from the provisional policy nonce) and its computed Name must equal the
     provisional `tpm_nv_name` (constant-time). Any mismatch: no `NV_Read`;
     an absent index gets the public message "The TPM index named in this
     vault's header is not on this TPM." (TPM-reported state, 5.8); any
     other mismatch is `Unlock failed.`.
  4. **Derivation and the provisional read:** the passphrase (handled per
     the core's `passphrase_kind`) gives the master key; derive `k_s2wrap`
     and `tpm_auth`; `NV_Read` under the policy session (a wrong passphrase
     costs one dictionary-attack count, as an unlock does).
  5. **Reconstruction:** the data's first byte must be 2; unwrap S2 with
     `k_s2wrap` (AEAD; failure: `Unlock failed.`); combine S2 (x = 2) with S3
     (x = 3) into the candidate bundle.
  6. **Authentication after reconstruction:** verify `core_mac` with the
     candidate `K_mac` (failure: `Unlock failed.`); from here the core is
     authenticated. Open `keytable.<core.keytable_gen>.pv`, check its digest
     against the authenticated core, decrypt it (6.2). Then check the old
     `slots_mac`, which normally fails here, giving
     `old_slots_authenticated = false`: the old index is kept and reported
     (F55 rule), and duress choice 1 is not offered. (If it verifies, the
     slots are intact and the normal 6.1 rules for `true` apply.)
  7. Continue with 6.3 onward.
- **Alternatives:** (b) defer and record that a bound vault with damaged
  `s1_*` cannot be recovered (the current 6.1 limitation); (c) an automatic
  fallback when the S1 path fails, rejected because every failed recovery
  would then also make a TPM read that counts against the dictionary-attack
  limit, and the owner would not know which path ran.
- **Security:** no new capability: the path needs the passphrase, the TPM
  and the card, which is more than an ordinary unlock. The TPM read uses
  provisional slot fields exactly as the ordinary unlock does, behind the
  same 9.2a checks; the card is checked before the TPM is touched.
- **Usability:** rescues one rare damage case; documented as such.
- **Schema impact:** none.
- **Tests:** F86 (corrupt `s1_ct`; passphrase + TPM + card recovers; the old
  index is reported); a wrong card is refused with no dictionary-attack
  count; a wrong passphrase counts exactly one and changes nothing; an
  absent index gives the public message; a decoy public area at the handle
  (F52 shapes) gets no `NV_Read`; never chosen without the option.

### P3. `convert` (SI-31, spec 6.9)

- **Proposed resolution:** confirm 6.9 as drafted, with these orderings:
  - **Bound target (portable → bound):** the public TPM preflight (P4)
    runs before any secret is read and before any write, as bound `init`
    does (`docs/CLI.md` 6.1, bound flow). A failure leaves the vault
    unchanged.
  - Then the ordinary unlock with the duress check; the terminal
    confirmation (M6-K5); the Argon2 (M6-K2), cleanup-capacity and
    generation-headroom checks (P5); and only then the first write (the
    `prepared` journal). The owner authorization, if any, is verified by
    the TPM only when the new index is defined (P4).
  - **Bound → portable:** the unlock itself needs the TPM (S2); the
    replacement passphrase follows M6-K1; the old index is retired only
    under 9.2b after the commit.
- **Old-card warning (finding 7):** the final message names every remaining
  risk, not only the paper cards (Appendix A.3).
- **Alternatives:** measuring after the unlock (rejected: N2 requires it
  before any write, and measuring first also avoids an Argon2 run that
  cannot lead anywhere).
- **Security:** bound to portable removes the TPM factor; the replacement
  passphrase is then the only barrier besides the cards; under M6-K1 it may
  be custom, subject to SI-51's creation-time estimate (a Weak one is
  refused). Old cards stop opening this vault at the commit but not
  older copies of it (9.8).
- **Usability:** a full card delivery; needs a terminal (confirmation).
- **Schema impact:** none (`op: "convert"` exists since Milestone 3).
- **Tests:** F32, F26 (`convert` part), F68, F82; refused on file systems
  that fail 8.5; a bound target whose identity cannot be measured is refused
  before any secret is read and leaves no file; a wrong confirmation
  changes nothing (exit 4).

### P4. CLI sections

- **Proposed resolution:** review Appendix A (options, branch tables for
  `--secrets-stdin`, messages, exit codes) together with the conflicts in
  5a; fold the approved result into `docs/CLI.md` before any code.
- **Security:** card text, passphrases and owner authorization stay secrets
  (hidden prompts, or one standard-input line each); paths are not secrets;
  confirmations come only from the terminal device; no environment
  variables.
- **Usability:** the commands mirror `init`'s delivery options.
- **Schema impact:** none.
- **Tests:** every usage error (exit 2), every branch of each stdin table,
  and the messages.

**Owner authorization: old and new needs (all commands).** A run addresses
one TPM (`--tpm`), so at most one owner-authorization value is read. It is
needed only for owner-hierarchy commands on that TPM: defining a **new**
index (`NV_DefineSpace`) or undefining an **old** one (`NV_UndefineSpace`,
only under 9.2b). Reading an index never needs it.

| Command and case | New-index need (before the commit) | Old-index need (after the commit) |
| --- | --- | --- |
| `recover`, bound target, on the TPM that holds the old index | Yes | Yes, if the old slots authenticated and 9.2b passes |
| `recover`, bound target, on another machine | Yes | No: the old index is remote, tracked in `tpm_cleanup` and reported |
| `recover --use-tpm` | Yes | Normally no: the old slots do not authenticate, so the old index is not deleted (if they do, as the first row) |
| `recover --to-portable` | No | Yes, only if the old slots authenticated and the old index is on this TPM |
| `convert` portable → bound | Yes | No |
| `convert` bound → portable | No | Yes, on this TPM (the unlock authenticated the slots) |
| `verify-card` | No | No (no TPM is used; `--tpm-owner-auth` is a usage error) |
| `fsck` report-only | No | No (`--tpm-owner-auth` is a usage error) |
| `fsck --repair` | No | Yes, for journal targets and `tpm_cleanup` entries on this TPM |

**Public TPM preflight versus owner-authorization verification.** These are
different steps and happen at different times:

- **Public preflight** (no secret supplied, before any secret is read and
  before any write; as bound `init`): the TPM is reachable (`--tpm`); its
  identity can be measured (H-2 EK, C4; N2); the storage hierarchy is
  enabled (C2); the TPM is not in lockout (C3); whether owner authorization
  is **set** (C1, a public capability bit) and, if so, whether a value can
  be supplied (a terminal device, or `--tpm-owner-auth`; D9). The preflight
  learns only whether a value is needed, never whether a value is correct.
- **Verification** of the supplied value happens only inside the TPM, when
  the owner-hierarchy command runs: `NV_DefineSpace` for the new need (after
  the `prepared` journal, as bound `init` does today) or `NV_UndefineSpace`
  for the old need (after the commit). No separate test command is sent:
  that would be one more use of the secret, and bound `init` (Milestone 5)
  already verifies at definition time. A value the TPM rejects at
  definition ("The TPM owner authorization was not accepted.", exit 1)
  rolls the operation back under 6.6, so nothing new remains and the old
  vault is untouched.

- **New need not met** (owner authorization set, none declared under
  `--secrets-stdin`): refused with exit 4 **before any write** (D9).
- **Old need not met, or rejected** after the commit: the commit stands;
  the old index stays authenticated in `tpm_cleanup` and is reported ("The
  old TPM index could not be removed now; run pvault fsck --repair on this
  computer."); exit 5, which `docs/CLI.md` 3 already defines for an
  unresolved cleanup. It is never retried with another value in the same
  run.

### P5. Recovery details left open in SI-35, and generation overflow

Already decided for Milestone 5 (D3) and reused: handle allocation, the
`TPM_RC_NV_DEFINED` restart and the unknown-outcome rule.

- **Generation overflow (finding 6):**
  - **Ordinary commits** (`add`, `rm`, `duress set`, `duress disable`, and
    any commit that prunes `tpm_cleanup`): `new_gen = generation + 1`
    with a checked add; at `u64::MAX` the command is refused before any
    write ("generation limit reached"). The Milestone 4 and 5 commits already
    do this (`vault/edit.rs`).
  - **Transitions** (`recover`, `recover --to-portable`, `convert`):
    `new_gen = old_gen + 1`, and a remote rollback may later need
    `tracking_gen = old_gen + 2` (spec 8.1; the approved generation
    exception). That second step happens only after side effects, when
    `store::start_tracking` checks it today; failing there would leave the
    journal blocked. **Proposed:** require `old_gen + 2` to fit before the
    first write (`prepared` journal, index, key table, card files) of every
    transition, and refuse otherwise ("generation limit reached"). The
    check in `start_tracking` stays as defense in depth and becomes
    unreachable.
  - **Alternative:** require the +2 headroom only for bound targets (only
    they can need a remote rollback); a uniform rule is simpler and costs
    one value of an unreachable range.
- **Cleanup capacity:** an operation that may add a `tpm_cleanup` entry
  reserves capacity before its journal: at 32 unresolved entries it refuses,
  never evicting one (spec 8.1, approved for Milestone 3).
- **Argon2 parameters:** decided, M6-K2 (5a): the defaults, or `init`'s
  bounded options with the same checks and warning, all before any write.
- **Security:** no write can start that a later rollback could not finish.
- **Usability:** none in practice (the limit is unreachable).
- **Schema impact:** none.
- **Tests:** synthetic headers at `u64::MAX` (ordinary commit refused, no
  file written) and at `u64::MAX − 1` (transition refused before any write);
  the 33rd cleanup entry refused without eviction.

### P6. Remaining SI-36 parts

The token format (scopes 1, 2, 3 and 5), the H-2 identity (D4) and the
same-TPM deletion rule are already implemented (Milestones 3 and 5).

- **Proposed resolution:** confirm as specified: every rotation decrypts
  each authenticated old cleanup token and re-encrypts it under the new
  `K_mac` (scope 5, fresh nonce) before any new file is created, aborting
  before side effects on failure; duress choice 1 for a **bound** old tag
  uses the old `ek_digest` from the old slots' scope-1 token, opened only
  after the old slots authenticated, so no old TPM is needed; the remote
  old-index limitation (6.8) stays documented.
- **Alternatives:** duress re-entry only when the old TPM is present.
- **Security:** a token's AAD, scope or AEAD failure is corruption and never
  authorizes deletion; deletion still needs the live measurement and every
  9.2b check.
- **Schema impact:** none new.
- **Tests:** F80, F83, F25; cleanup entries survive two rotations and still
  authorize deletion only on their own TPM; bound duress re-entry during a
  recovery with no TPM present.

### P7. `fsck`: scope and deletion eligibility (SI-40)

Successful decryption or MAC verification shows that pvault wrote a file
under a known key; it does **not** show that the file is abandoned. An
earlier draft treated it as sufficient; this version defines eligibility by
reference and restart state as well.

- **Report-only `pvault fsck <vault>`:** exclusive lock, no secrets, nothing
  deleted, no TPM index touched (spec 8.2 rule 1). Everything it reports is
  labeled unauthenticated.
- **`--repair`** first unlocks (ordinary unlock with the duress check, or
  Path B with `--recovery`), then works in this order:
  1. **Restart first.** If a canonical journal or a journal temp exists,
     only the accepted restart rules act: spec 8.2 (transition table and
     temp promotion), 8.3 (init), and the approved `update` rules of
     `docs/M4_READINESS.md` 9. They delete only artifacts whose **file
     identity** the authenticated journal recorded before any bytes were
     written (`target_kt_*`, `header_*`, `track_kt_*`, `track_hdr_*`,
     `old_kt_id`, `new_object`), each opened through that identity, and the
     old key table only on a SHA-512 match with `old_keytable_digest`. A
     journal that does not authenticate, or an indeterminate state, deletes
     nothing. **No other deletion runs while any journal or journal temp
     exists**, so `fsck` can never remove something a restart still needs.
  2. **The authenticated live set.** Orphan deletion (steps 3 and 4) runs
     only when every one of these holds, re-checked under the exclusive
     lock immediately before the first removal:
     - **no journal:** no canonical journal and no journal temp exists;
     - **authenticated core:** the header's `core_mac` verified with the
       bundle obtained by this run (ordinary unlock; or Path B, which also
       authenticates the core); the header read again now must still have
       exactly that core digest (as the commit-time generation check does);
     - **authenticated current key table:**
       `keytable.<core.keytable_gen>.pv` exists, `keytable_gen` equals
       `generation`, its SHA-512 equals the core's `keytable_digest`, and it
       decrypts and verifies under the bundle with its generation as
       context;
     - **live objects:** the file IDs listed in that decrypted table.
     The live set is the header, that key table, those objects, `vault.gate`
     and `vault.lock`; none of it is ever eligible. If any requirement
     fails, the live set is unknown and **nothing is deleted** (report
     only).
  3. **Eligible without a name list (ownership and abandonment both
     shown):**
     - an **object** `objects/<id>.pv` not listed in the current key table,
       whose `id` is listed in another key table present in the folder that
       authenticates under the current bundle with its own generation as
       context, **and** whose own content authenticates under that entry's
       file key and the file-ID binding of its AAD (7.7). Not listed in the
       current table plus no journal means unreferenced; the content check
       ties the file to the listing, not just its name;
     - a **key table** `keytable.<g>.pv` with `g ≠ core.keytable_gen` that
       authenticates under the current bundle with context `g`, once no
       object eligible above still depends on it as its only authentication
       (objects are removed first, then key tables, as SI-40's `rm` order).
     These are still listed and removed only after one terminal
     confirmation (`DELETE LISTED FILES <8 hex>`), because they hold data the
     owner may want to recover.
  4. **Everything else** (temps no journal names, key tables of an older
     bundle, unknown names): reported only; the owner may confirm an exact
     list (same phrase), and only regular files opened without following
     links under the vault-directory handle are removed, never directories.
  5. **Deletion procedure:** the list is a snapshot with each file's
     identity; before each removal the file is reopened, its identity must
     be unchanged and it must still be outside the live set; otherwise it is
     skipped and reported. The directory is flushed after the removals.
  6. **TPM:** journal targets and `tpm_cleanup` entries are resolved only
     under 9.2b on the matching TPM; an owner-range index that no
     authenticated journal, slots or cleanup entry mentions is reported,
     never touched (F53). A deleted or confirmed-absent cleanup entry stays
     recorded until a later commit prunes it (spec 6.5 n).
     **Recommendation for the pruning commit (identity question; pending,
     not approved):** an entry
     is pruned only on evidence gathered **in the pruning run itself, on the
     entry's own TPM**: measure the live H-2 identity; open the entry's
     scope-5 token (only after the core authenticated); compare the digests
     in constant time; then read the handle's public area. Prune when the
     handle is empty, or holds an index that is not ours (a Name that is
     neither of the entry's Names, or a different public area), because our
     index is then gone. Keep the entry when the identity differs, cannot be
     measured, or the TPM is unavailable (absence on another TPM proves
     nothing), and when our index is still present (remove it under 9.2b
     first). Which commits prune: `fsck --repair`, through its own commit of
     the existing kind used by `duress set` (an `update` journal, a new key
     table with the same entries, generation + 1), and any `recover` or
     `convert` for the entries it re-verified, instead of re-encrypting
     them. Everyday `add` and `rm` do not prune, so they never need the TPM
     for this. No format change: no "deleted" flag is stored, because a
     stored flag could not show that the index is still gone later.
  7. It replaces the Milestone 4 interim `CLOSE UNFINISHED CLEANUP` closure
     and includes the stale-partials cleanup of `clean-partials` for this
     vault.
- **Alternatives:** deletion on decryption alone (rejected above); deletion
  by name pattern (rejected by 8.2 rule 4); repair on every unlock (spec
  allows it, but the owner could not look first).
- **Security:** nothing is deleted on a name, pattern or decryption alone;
  restart artifacts are handled only by the accepted restart rules; the
  live set is excluded; every index deletion passes 9.2b.
- **Usability:** a safe first look, then an explicit repair; confirmations
  list exactly what will be removed.
- **Schema impact:** none; the eligibility rules make spec 8.2 rule 4 and
  SI-40 concrete and need the author's approval (SI-40 is pending).
- **Tests:** F31, the `fsck` halves of F33, F72 and F88, F44, F45, F53, F54,
  F27 to F29b; report-only `fsck` on every crash state of F25 deletes
  nothing; `--repair` with a journal present deletes only journal-recorded
  identities; an older key table that still authenticates an orphan object
  is kept until the object is removed; a file replaced between listing and
  removal is skipped; the live set is never removed.

### P8. Duress during recovery (spec 6.7)

- **Proposed resolution:** the three choices as drafted: (1) re-enter the
  existing duress passphrase, offered only when the old slots authenticated
  and hold a tag, verified against the old tag before a new tag is written;
  (2) generate a new one, shown once and typed back; (3) disable, confirmed
  with `DISABLE DURESS`. Old tag unavailable: only 2 and 3. Bound duress
  unavailable on this TPM (9.3): only 3, with the reason. The N3 notice
  (D7) applies when a duress passphrase results. The trigger stays inactive
  until Milestone 9.
- **What each choice needs:**

  | Choice | Terminal device | Standard input under `--secrets-stdin` |
  | --- | --- | --- |
  | Selection | The owner types the choice on the terminal; `--duress reenter` preselects 1 | Never read for the selection |
  | 1 re-enter | Not required with `--duress reenter` | One line: the duress passphrase |
  | 2 generate | Required (the passphrase is shown only there) | One line: its type-back |
  | 3 disable | Required (confirmation) | None |

  Without a terminal device, a vault whose old slots hold a duress tag can
  be recovered only with `--duress reenter` (choice 1). Otherwise the
  command stops before any write (exit 4). Whether the header holds a tag is
  public, so this is decided before any secret is read.
- **Alternatives:** silently dropping duress (rejected); carrying the old
  tag (rejected by 6.7).
- **Security:** no stale tag is ever written; a re-entered passphrase is
  verified against the authenticated old tag.
- **Schema impact:** none.
- **Tests:** F46, F57, F82, F63; the non-interactive refusal before any
  write; `--duress reenter` when the old tag is unavailable is refused
  before any write.

### P9. Test environment

- **Proposed resolution:** reuse the Milestone 5 setup (`swtpm` with fresh
  state per test, short lockout settings where needed, the local container
  recipe, native Linux CI with `PVAULT_TEST_REQUIRE_SWTPM`); every test that
  starts `swtpm` or another process runs in the isolated test process (V2);
  F83 with two emulators in one test; failpoints named after the recovery
  steps (`recover.a` to `recover.q`, every journal phase, the post-header
  flush) for the F25 and F26 matrices, in process and through the CLI; pin
  the Linux TPM jobs to `ubuntu-24.04` (`ubuntu-latest` moves to Ubuntu 26
  from 2026-10-19) and test the newer image separately.
- **Alternatives:** keep `ubuntu-latest`.
- **Security:** none to the product; tests never touch a real TPM.
- **Usability:** longer Linux test jobs.
- **Schema impact:** none.

### P10. Real-hardware validation

- **Proposed resolution:** not part of Milestone 6 acceptance, which stays
  on `swtpm`; still required before any bound-mode release. A future
  authorization would name the device, how owner authorization is supplied,
  that no destructive TPM operation is run, which handles may be used, and
  how test indexes are removed. **No real TPM access is authorized now.**

## 6. Interaction with open items

- **Milestone 4 gates:** section 1. Recovery card input on Windows uses the
  console path that the Windows checklist has not yet validated.
- **Milestone 5 limitations:** bound recovery and `convert` use the same TPM
  stack, so the accepted `tpm2-tss` memory limitation applies unchanged, and
  the CLI's logging override covers them.
- **Test runtime:** the crash matrices multiply process starts; under the V2
  isolation they run one at a time, which lengthens the Linux jobs.

## 7. Proposed sequence (once Milestone 4 is accepted or an exception is granted)

1. Approve P2 to P10 and Appendix A (aligned with M6-K1 to M6-K5) in one
   decision record; fold the CLI sections into `docs/CLI.md`.
2. `fsck` report-only, then `--repair`.
3. Path B entry, `verify-card`, portable recovery (A + B) with rotation and
   phase 2 delivery verification.
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
or environment variables; card text is a hidden prompt or exactly one
standard-input line under `--secrets-stdin`; confirmations and shown secrets
use only the terminal device; every secret-dependent failure is `Unlock
failed.` (exit 1). The drafts follow the decisions M6-K1 to M6-K5 (5a).
Under `--secrets-stdin`, lines are read in the order of each table, one
attempt each; end of input before a needed line is "Input ended before all
secrets were read." (exit 1), with nothing written or the operation rolled
back; remaining input is left unread.

**Old-card input (A.1, A.2, A.4).** For each old card exactly one of: its
card file (`--card-a-file`, `--card-b-file`, `--card-file`), its PNG photo
(`--card-a-png`, `--card-b-png`, `--card-png`; an existing photo, so no
terminal is needed, M6-K3), or its text (hidden
prompt; under `--secrets-stdin` one line). Giving both a file and a photo for
one card is a usage error (exit 2). Options of the other mode are refused
after the header is read ("This vault is portable; give --card-a-* and
--card-b-*." or the bound form; exit 2).

### A.1 `pvault verify-card` (Path B; verification only; shared lock; no writes)

```text
pvault verify-card <vault-dir> [--card-a-file <file> | --card-a-png <file>]
                               [--card-b-file <file> | --card-b-png <file>]      (portable)
pvault verify-card <vault-dir> [--card-file <file> | --card-png <file>]          (bound)
```

| Option | Meaning |
| --- | --- |
| `<vault-dir>` | The vault folder |
| `--card-a-file`, `--card-b-file` | Portable: an old card file (format 1, read as `discard-card` reads it) |
| `--card-a-png`, `--card-b-png` | Portable: an existing PNG photo of the printed old card; no terminal needed (M6-K3) |
| `--card-file`, `--card-png` | Bound: the bound card as a file or an existing photo (M6-K3) |
| Global | `--secrets-stdin`; `--tpm` is accepted and unused; `--tpm-owner-auth` is a usage error (exit 2) |

- **Flow:** preflight; shared lock; header (structural failure: `Unlock
  failed.`); bound: passphrase; each card (file, photo or text); per-card and
  pair checks (`docs/RECOVERY_DELIVERY_PROPOSAL.md` 6.1, 6.2a); combine;
  `core_mac`; the key table. No TPM, no duress check, no write; the rollback
  warning is shown when the vault is older than recorded, and the record is
  never updated (F66).
- **Output:** "The cards recover this vault (card set <8 hex>)." or "The
  passphrase and this card recover this vault (card set <8 hex>)." (exit 0).

| Point | Behavior | Lines |
| --- | --- | --- |
| Start | Options checked; no secret read | 0 |
| Passphrase (bound) | One line | 1 |
| Bound card | File or photo: 0. Otherwise its text | 0 or 1 |
| Card A (portable) | File or photo: 0. Otherwise its text | 0 or 1 |
| Card B (portable) | As Card A | 0 or 1 |
| End | Nothing more is read | |

Totals: bound 1 or 2; portable 0 to 2.

**Exit codes:** 0, 1, 2, 3, 6.

### A.2 `pvault recover` (Path B; exclusive lock; rotates the bundle)

```text
pvault recover <vault-dir>                                         (portable vault)
    [old cards: --card-a-file|--card-a-png <file>] [--card-b-file|--card-b-png <file>]
    new passphrase: [--words <10-16> | --custom]   [kdf options]
    --new-cards paper --new-cards-dir <dir> [--new-card-a-png <file>] [--new-card-b-png <file>]
  | --new-cards digital --new-card-a-dir <dir> --new-card-b-dir <dir>
        [--accept-risk digital-cards] [--accept-risk same-volume]
    [--duress reenter]

pvault recover <vault-dir> [--use-tpm]                             (bound vault, bound target)
    [old card: --card-file|--card-png <file>]   [kdf options]
    --new-cards paper --new-cards-dir <dir> [--new-card-png <file>]
  | --new-cards digital --new-card-dir <dir> [--accept-risk digital-cards]
    [--duress reenter] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]

pvault recover <vault-dir> --to-portable                           (bound vault, portable target)
    [old card: --card-file|--card-png <file>]
    new passphrase: [--words <10-16> | --custom]   [kdf options]
    (new-card options as for a portable vault)
    [--duress reenter] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]
```

| Option | Meaning |
| --- | --- |
| `<vault-dir>` | The vault folder |
| `--card-a-file`, `--card-a-png`, `--card-b-file`, `--card-b-png`, `--card-file`, `--card-png` | Old cards (above) |
| `--to-portable` | Bound vault only: recover into portable mode (6.8); no TPM needed |
| `--use-tpm` | Bound vault only, not with `--to-portable`: the S2 + S3 path (P2) |
| `--words <n>` | Portable target: a generated passphrase of 10 to 16 words, default 12 |
| `--custom` | Portable target: a custom passphrase, with SI-51's creation rules as at `init` (M6-K1) |
| `--kdf-memory`, `--kdf-iterations`, `--kdf-parallelism` | Argon2 for the new salt: `init`'s bounds, checks and low-memory warning; defaults otherwise (M6-K2) |
| `--new-cards paper\|digital` | Required: delivery of the new cards |
| `--new-cards-dir <dir>` | Paper only, required: folder for the new card files (as `init`'s `--cards-dir`) |
| `--new-card-a-png`, `--new-card-b-png`, `--new-card-png` | Paper only: verify a new printout from a PNG photo taken during the run (needs the terminal device, O1; M6-K3 does not change this) |
| `--new-card-a-dir`, `--new-card-b-dir` | Digital, portable target, both required (as `init`'s `--card-a-dir`, `--card-b-dir`) |
| `--new-card-dir` | Digital, bound target, required |
| `--accept-risk digital-cards`, `--accept-risk same-volume` | Digital only, as at `init` (`same-volume`: portable target only) |
| `--duress reenter` | Preselects duress choice 1 (P8) |
| Global | `--secrets-stdin`; `--tpm`; `--tpm-owner-auth` (bound target, or `--to-portable` for the old-index need; P4 table; with a portable vault, which uses no TPM, a usage error, exit 2) |

- **Before any secret is read:** options; preflight and the exclusive lock;
  the header's structure (4.4) and Argon2 caps (4.3); the new Argon2
  parameters (M6-K2: bounds, 4.3 checks, warning); the public duress-tag
  rule (P8); for a **bound target**, the public TPM preflight of P4: identity
  measurable (C4, N2: otherwise "This computer's TPM identity cannot be
  established, so a bound vault cannot be created here. You can recover it
  as a portable vault with --to-portable." exit 6), C2, C3, and exit 4 when
  owner authorization is set and cannot be supplied (D9); generation
  headroom and cleanup capacity (P5). Nothing has been written, and no
  owner authorization has been checked yet (P4).
- **Then:** old material and Path B (6.1, or P2 with `--use-tpm`); the key
  table; the replacement passphrase (portable target; M6-K1); duress choice
  (P8); "Deriving keys…"; the `prepared` journal (the first write); bound
  target: handle, define and write, Names confirmed (6.3 d to f); the new key
  table; the new cards rendered; delivery as at `init` (printing
  acknowledgment, photo or text; digital: files, risk acknowledgments,
  read-back); the rehearsal of the new cards against the new header;
  portable target: the type-back; the dual-MAC `committing` record; the
  header commit; old-index retirement or tracking (P4 table); old key table
  removed by digest; journal removed.
- **Final message (finding 7):** "Recovery complete: <vault> (<mode>,
  generation <n>). The old cards no longer open this vault, but they, and
  any photo, scan or file copy of them, still open older copies of it, such
  as backups. Destroy the old paper cards. For old card files, use pvault
  discard-card; deleting a file does not erase it from flash storage,
  snapshots, backups, cloud history or thumbnail caches." Bound vault with
  an old index that could not be removed: the P4 notice follows (exit 5).
- **Phase 2 failure or abort:** nothing old is modified; the old passphrase,
  cards and index keep working (6.4 k): "Nothing was changed; the old cards
  and passphrase still work." (exit 1, or 7 when cancelled).

| Point | Behavior | Lines |
| --- | --- | --- |
| Start | Without a terminal device: a portable target with a generated passphrase (no `--custom`) is refused (exit 6); a `--new-card-*-png` option is refused (exit 6, O1); a duress tag in the header without `--duress reenter` stops (exit 4). Bound target: the TPM checks above | 0 |
| Passphrase (bound vault, also `--to-portable`) | One line | 1 |
| Old cards | Per card: file or photo 0, otherwise its text | Portable 0 to 2; bound 0 or 1 |
| Owner authorization | Only with `--tpm-owner-auth` | 0 or 1 |
| Replacement passphrase (portable target) | Generated: shown on the terminal, no line. Custom (M6-K1): the passphrase, then again; the estimate as at `init` (Medium needs the terminal confirmation, refused without a terminal, exit 6; Weak or estimator failure: refused, exit 1); nothing written yet | 0 or 2 |
| Duress | `--duress reenter`: one line (refused before any write if the old tag is unavailable). Choice 2 on the terminal: one line, the type-back. Choice 3 or no tag: none | 0 or 1 |
| Printing | Acknowledgment from the terminal device if one exists, otherwise skipped; never from standard input | 0 |
| New cards (paper) | Per card: a photo 0, otherwise its text (written by the supplier after the card files appear) | Portable 0 to 2; bound 0 or 1 |
| New cards (digital) | Read back from the files | 0 |
| Type-back (portable target) | One line | 1 |
| End | Nothing more is read | |

**Exit codes:** 0; 1; 2; 3; 4 (another operation's pending journal, the
duress rule, a declined confirmation, a missing risk acknowledgment, owner
authorization needed but not declared); 5 (outcome uncertain, or the old
index left as an unresolved cleanup: run `pvault fsck`); 6; 7.

### A.3 `pvault convert` (ordinary unlock; exclusive lock; rotates the bundle)

```text
pvault convert <vault-dir> --to portable                    (bound vault)
    [--words <10-16> | --custom]   [kdf options]
    --new-cards paper --new-cards-dir <dir> [--new-card-a-png <file>] [--new-card-b-png <file>]
  | --new-cards digital --new-card-a-dir <dir> --new-card-b-dir <dir>
        [--accept-risk digital-cards] [--accept-risk same-volume]
    [--duress reenter] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]

pvault convert <vault-dir> --to bound                       (portable vault)
    [kdf options]
    --new-cards paper --new-cards-dir <dir> [--new-card-png <file>]
  | --new-cards digital --new-card-dir <dir> [--accept-risk digital-cards]
    [--duress reenter] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]
```

| Option | Meaning |
| --- | --- |
| `<vault-dir>` | The vault folder |
| `--to portable\|bound` | Required; the other mode than the vault's (the same mode: "This vault is already <mode>." exit 2) |
| `--words`, `--custom` | Bound → portable: the replacement passphrase, generated or custom with SI-51's rules (M6-K1) |
| `--kdf-memory`, `--kdf-iterations`, `--kdf-parallelism` | Argon2 for the new salt: `init`'s bounds, checks and warning; defaults otherwise (M6-K2) |
| `--new-cards paper\|digital`, `--new-cards-dir`, `--new-card-a-png`, `--new-card-b-png`, `--new-card-png`, `--new-card-a-dir`, `--new-card-b-dir`, `--new-card-dir` | Delivery of the new cards for the target mode, each with the meaning and rules of its `init` counterpart (M6-K4); the PNG options need the terminal (O1) |
| `--accept-risk digital-cards`, `--accept-risk same-volume` | Digital only, as at `init` (`same-volume`: portable target only) |
| `--duress reenter` | Preselects duress choice 1 (P8) |
| Global | `--secrets-stdin`; `--tpm`; `--tpm-owner-auth` (P4 table) |

- **Before any secret is read:** options; preflight (a file system failing
  8.5: exit 6) and the exclusive lock; the header's structure and Argon2
  caps; the new Argon2 parameters (M6-K2); the terminal device must exist
  (the confirmation needs it; otherwise exit 4); for a **bound target** the
  public TPM preflight of P4 (C4 and N2, C2, C3, D9), refusing before any
  secret is read; generation headroom and cleanup capacity (P5). The owner
  authorization is verified only later, by the TPM (P4).
- **Then:** the ordinary unlock with the duress check; the confirmation
  (M6-K5); the replacement passphrase (bound → portable; M6-K1); duress choice
  (P8; the old tag is available because the unlock authenticated the
  slots); "Deriving keys…"; the `prepared` journal (first write); bound
  target: the new index (6.3 d to f); the new key table; delivery and
  rehearsal (mode byte = the target); type-back for a portable target; the
  dual-MAC commit; old-index retirement under 9.2b (bound → portable).
- **Final message (finding 7):** "Converted <vault> to <mode> (generation
  <n>). The old cards no longer open this vault, but they, and any photo,
  scan or file copy of them, still open older copies of it, such as
  backups, in the old mode. Destroy the old paper cards. For old card files,
  use pvault discard-card; deleting a file does not erase it from flash
  storage, snapshots, backups, cloud history or thumbnail caches." Bound →
  portable, when the old index stays: the P4 notice (exit 5); an old index on
  another computer's TPM is named as the remote limitation (6.8).

| Point | Behavior | Lines |
| --- | --- | --- |
| Start | No terminal device: exit 4. A generated replacement passphrase and `--new-card-*-png` use the terminal, which is present. Bound target: the public TPM preflight | 0 |
| Passphrase | The ordinary unlock | 1 |
| Owner authorization | Only with `--tpm-owner-auth` | 0 or 1 |
| Confirmation | Terminal only, never standard input | 0 |
| Replacement passphrase (to portable) | Generated: none. Custom (M6-K1): two lines; the estimate as at `init` | 0 or 2 |
| Duress | As A.2 | 0 or 1 |
| Printing | Terminal | 0 |
| New cards (paper) | Per card: photo 0, otherwise its text | To portable 0 to 2; to bound 0 or 1 |
| New cards (digital) | Read back | 0 |
| Type-back (to portable) | One line | 1 |
| End | Nothing more is read | |

**Exit codes:** 0, 1, 2, 3, 4, 5, 6, 7.

### A.4 `pvault fsck` (exclusive lock)

```text
pvault fsck <vault-dir>                                     (report only)
pvault fsck <vault-dir> --repair                            (ordinary unlock with the passphrase)
    [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]
pvault fsck <vault-dir> --repair --recovery                 (Path B)
    [old-card options as A.1] [--tpm <device|swtpm:PORT>] [--tpm-owner-auth]
```

| Option | Meaning |
| --- | --- |
| `<vault-dir>` | The vault folder |
| (no other option) | Report only: no secret is read, nothing deleted, no TPM index touched; `--tpm-owner-auth` is a usage error (exit 2) |
| `--repair` | Unlock, then act as P7 |
| `--recovery` | With `--repair` only: authenticate with the cards (Path B) instead of the ordinary unlock; no duress check |
| Old-card options | With `--recovery`: as A.1 |
| Global | `--secrets-stdin`; `--tpm`; `--tpm-owner-auth` (old-index need; P4 table) |

- **Report contents (public state only, 5.8 and SI-41):** the header's
  structural state, mode and generation (unauthenticated); a pending
  journal's operation and phase (unauthenticated); journal-temp residue;
  files outside the vault layout; this vault's recorded stale partial
  exports; the number of `tpm_cleanup` entries (unauthenticated). Exit 0
  when nothing needs action, 4 when the owner must act, 5 when a state is
  indeterminate.
- **`--repair`:** P7, steps 1 to 7. Confirmations (`DELETE LISTED FILES
  <8 hex>`, stale partials) come only from the terminal device; without it
  they are declined, the files are reported and left (exit 4).

| Point | Behavior | Lines |
| --- | --- | --- |
| Report only | No secret | 0 |
| `--repair`: passphrase | The ordinary unlock | 1 |
| `--repair --recovery`: old material | As A.1 (bound: passphrase and the card; portable: Card A, Card B) | Bound 1 or 2; portable 0 to 2 |
| Owner authorization | Only with `--tpm-owner-auth`. Not declared and needed: that index is reported and left (exit 4) | 0 or 1 |
| Confirmations | Terminal only | 0 |
| End | Nothing more is read | |

**Exit codes:** 0, 1, 2, 3, 4, 5, 6.
