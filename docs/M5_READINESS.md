# Milestone 5 readiness review

Prepared 2026-10-06 as a **documentation-only review**. **Exception E1
authorized and closed as completed on 2026-10-06** (section 1; recorded in
`docs/SPEC_ISSUES.md`): an isolated, uncommitted TPM-library and API probe
outside the repository, against `swtpm` only. Section 11 holds the
recommended resolutions of D1 to D12 (updated with the probe results),
section 12 the probe plan and its emulator-only results, and section 13 the
final decision table. No Milestone 5 code,
dependency, CI change or spec decision is made here; every proposal below is
for the author's approval. Acceptance criteria are quoted, not changed.

**Milestone 5 accepted (author, 2026-10-11) as emulator-tested work only**
(section 14, "Acceptance"; `docs/SPEC_ISSUES.md`). Milestone 4 remains
unaccepted.

**Milestone 4 status when this was written:** implemented and **not
accepted**. Native CI passed on commit `b6baa13` (run 37541676635), and a
manual same-volume digital-delivery check passed on macOS
(`docs/M4_READINESS.md` 17). Both manual acceptance gates are **outstanding**:
the Windows console checklist (`docs/M4_READINESS.md` 14, including digital
steps 16 to 20b) and the printed-card photo check (14a, paper delivery only).
The Milestone 4 evidence and manual-test records in `docs/M4_READINESS.md`
and `docs/SPEC_ISSUES.md` were not changed by this review (they were later
committed together with Milestone 5, in `dab6264`).

Sources: `CLAUDE.md`; `PVAULT_BUILD_SPEC.md` sections 0, 1, 5.2, 5.5 to 5.7,
6.10, 7.4a to 7.4d, 7.6, 8.1 to 8.5, 9.1 to 9.3, 9.6, 11, 13, 15 and 16;
`docs/SPEC_ISSUES.md` (SI-18, SI-22, SI-32, SI-35, SI-36, SI-42, section 4
"Before Milestone 5", 10.x); `docs/M4_READINESS.md`; `docs/CLI.md`;
`docs/RECOVERY_DELIVERY_PROPOSAL.md`.

**Contents:** 1 starting before Milestone 4 acceptance · 2 scope ·
3 out of scope · 4 what exists · 5 pending decisions · 6 dependencies ·
7 tests · 8 interaction with the outstanding Milestone 4 gates · 9 what can
proceed now · 10 proposed sequence · 11 recommended resolutions and
remaining gaps · 12 E1 probe plan and results · 13 final decision table.

## 1. Can Milestone 5 start before Milestone 4 is accepted?

**No, not without an explicit, recorded exception from the author.**

| Source | Rule |
| --- | --- |
| Spec 0, item 1 | "Work one milestone at a time (Section 13). Do not start the next milestone until the current one's acceptance criteria pass." |
| `CLAUDE.md` | "Work on one milestone at a time. Stop after each milestone and report changes, validation results, and open issues." |
| `docs/SPEC_ISSUES.md` (Milestone 4 decisions) | "Manual gates accepted, results outstanding … Milestone 4 is accepted only after its native CI jobs and both manual gates pass." |
| `docs/M4_READINESS.md` 17 | "Acceptance needs the native CI jobs on Linux, macOS and Windows and both manual gates (14, 14a)." |
| Spec 13 (preamble) | "An item marked **PENDING** in this spec must be resolved before the milestone that first needs it starts." |

The spec's Milestone 4 row lists automated tests only, and those pass in
native CI. The two manual gates were added as Milestone 4 acceptance
conditions by the author's own decisions, so Milestone 4's acceptance
criteria do not pass yet. Neither the spec nor `CLAUDE.md` defines an
exception mechanism; an exception would therefore be a new author decision,
recorded in `docs/SPEC_ISSUES.md`.

**What needs no exception (in this reviewer's reading; the author decides):**
documentation-only preparation such as this review, and **decisions** on the
items Milestone 5 needs. Spec 13 requires PENDING items to be resolved
*before* the milestone starts, so deciding them is preparation, not
Milestone 5 work. Recording an approved decision in the spec or
`docs/SPEC_ISSUES.md` is documentation.

**What would need an exception:** any Milestone 5 product code, test code,
new dependency (`Cargo.toml`, `Cargo.lock`, `deny.toml`), CI change, or a
committed investigation spike inside the repository.

Possible exceptions, for the author's choice (section 9 has the detail):

| Option | Allows | Risk |
| --- | --- | --- |
| E0 (recommended now) | Nothing beyond documentation and decisions until Milestone 4 is accepted | None; Milestone 5 waits for two manual sessions |
| E1 (**authorized and closed as completed, 2026-10-06**; results in 12.2) | An uncommitted API spike outside the product tree (scratch crate) to confirm the `tss-esapi` calls that SI-18 and SI-22 leave open; `swtpm` only, in an isolated Linux environment; no real TPM, no host TPM settings, no product code, no shared `init`/card/CLI changes, no dependency or CI changes, no commit | Low; nothing enters the repository |
| E2 | Milestone 5 code limited to new, isolated modules (TPM session and NV layer, swtpm harness) behind the Linux `tpm` feature; no changes to `init`, the CLI, cards or terminal code until Milestone 4 is accepted | Medium; a gate finding in shared code could still force rework |
| E3 | Full Milestone 5 | Highest; gate findings in `init`, the CLI, cards or the terminal would land in code that Milestone 5 is changing |

## 2. Milestone 5 scope (spec 13, row 5)

> Bound mode via swtpm: policy-nonce index, precomputed and post-write Name,
> read rules (9.2a), ownership verification (9.2b), sessions (SI-22), duress
> setup (6.10) and availability (9.3). Accept when: F1 to F3, F17, F19, F30,
> F52, F59, F60, F61 and F65 (bound cards), F81.

| Part | Spec | Notes |
| --- | --- | --- |
| TPM access layer | 9.1, SI-18, SI-22 | `tss-esapi`; salted HMAC sessions with parameter encryption, failing closed; Linux only |
| NV index definition | 9.1, SI-22 | Owner range `0x01800000..=0x01BFFFFF`, 97 bytes, AUTHREAD and AUTHWRITE, DA protection on, `authValue = tpm_auth`, PolicyOR nonce policy (P1) |
| Names | 9.1, F30 | Pre-write and post-write Names precomputed from the public area; both confirmed; only the post-write Name stored |
| Handle allocation | 6.3, SI-35 | Random handle, probe, at most 32 tries; journal before `NV_DefineSpace`; collision and unknown-outcome handling (proposed F87, F88) |
| TPM identity measurement | 8.1, 9.2b, SI-36, N2 | Measure the H-2 EK digest; encrypted identity token (format exists since Milestone 3); refuse bound creation when it cannot be measured (proposed F91) |
| Bound `init` | 8.3 (four-phase safe init), 5.1 | `prepared` journal → bound index → key table → cards → header; resume (F59, F60), including identity-checked index removal before a header exists |
| Bound unlock | 5.2, 9.2a | Provisional `NV_ReadPublic` checks before `NV_Read`; Name or public-area mismatch fails generically without `NV_Read` (F52); no passphrase-only path (F3) |
| Ownership verification | 9.2b | Authenticated source, exact Name and public area, same TPM (token), then undefine with owner authorization; used by `init` resume (F60) |
| Owner authorization | 9.3 | Never set or changed; prompted when an index must be defined or deleted and owner authorization is set |
| Duress setup | 6.10, SI-32 | `duress set`, `duress disable`, the optional `init` step; portable and bound tags (9.6) |
| Duress availability | 9.3, SI-42 | C1 to C3, plus C4 (identity measurable); `duress set` refused and `status` reporting when unavailable (F81) |
| Bound cards | 7.4a, F61, F65 | Bound card (`share_x = 3`); payload, Base32 and QR rules already built in Milestone 4 |
| `status` | 6.6 of `docs/CLI.md`, 9.3 | Owner authorization set, storage hierarchy, lockout, duress availability |

## 3. Out of scope for Milestone 5

- **Duress trigger action** (deleting the index or overwriting slots on a
  match): destructive, behind the Milestone 8 review, built in Milestone 9
  (spec 0, item 2; spec 15). Spec 5.2 step 3 describes it; Milestone 5 must
  not implement it (decision D6 below).
- Owner Revoke, Erase, flush, K2 (Milestones 9 and 10).
- Recovery, bundle rotation, `recover --to-portable`, `convert`, `fsck`,
  `verify-card` (Milestone 6). F25, F80 and F83 are Milestone 6.
- Bound mode on Windows and macOS (Milestone 17 investigates).
- PCR binding (decided P1: nonce policy only in v1).
- Any real TPM: development uses `swtpm`; a real TPM needs the owner's
  explicit authorization for that session (spec 0, item 8).

## 4. What already exists

| Area | Built in | Reuse in Milestone 5 |
| --- | --- | --- |
| Header `mode = "bound"`, `BoundSlots`, `tpm_cleanup` (at most 32 entries) | Milestone 3 | Bound header encode and decode, MACs |
| Encrypted TPM-identity tokens (`tpmid.rs`, five scopes, H-2 template id) | Milestone 3 | Token encryption and decryption; Milestone 5 adds the live measurement |
| Journal schemas, including bound `init` and `IDX` fields; published vectors (`init-bound-committing`) | Milestone 3 | Write-ahead index records |
| Four-phase safe `init`, resume, card files, paper and digital delivery, rehearsal | Milestone 4 | Extended for the bound index and the bound card |
| Card payload with `mode` and `share_x = 3` validation | Milestone 4 | Bound card generation and checks (F61, F65) |
| Portable duress tag and the duress check in unlock (a match fails without mutation) | Milestone 4 | Duress setup adds the commit that stores a tag |
| CLI `--mode bound` | Milestone 4 | Currently refused: "Bound mode is not available in this version." (`docs/CLI.md` K1); `bound_header_is_refused_before_the_passphrase` |
| CI `swtpm smoke test` job (Linux; `swtpm`, `tpm2-tools`, `libtss2-dev`) | Milestone 0 | Starting point for the Milestone 5 swtpm test job |

## 5. Pending decisions

Each must be decided before Milestone 5 starts (spec 13). Items 1 to 4 are
from `docs/SPEC_ISSUES.md` section 4, "Before Milestone 5". The others came
up in this review.

| # | Decision | Source | Proposal or options | Blocks |
| --- | --- | --- | --- | --- |
| D1 | TPM crate pin and feature gating | SI-18 | `tss-esapi = "=7.7.0"` with `tss-esapi-sys` 0.6.0; Linux-only dependency behind the Cargo feature `tpm` (default on Linux); `tpm2-tss` ≥ 2.4.6. **Re-check before approval:** current `tss-esapi` releases (SI-18 noted 8.0 as alpha), RustSec advisories, the crate's minimum Rust version against MSRV 1.89, and the licenses of new transitive crates (cargo-deny) | All TPM code |
| D2 | Exact public area, Name computation and salted-session design, with trust assumptions | SI-22 | As proposed: attributes `0x00040004` pre-write, `0x20040004` post-write, `dataSize` 97, PolicyOR digest; transient ECC P-256 NULL-hierarchy salting key; AES-128-CFB HMAC sessions; decrypt for `NV_DefineSpace` and `NV_Write`, encrypt for `NV_Read`; no fallback. Active interposers are out of scope for v1 (documented) | F30, F52, F2, F19 |
| D3 | Handle allocation, collision and unknown outcome; overflow refusal | SI-35 (pending part) | As proposed: random handle, `NV_ReadPublic` probe, 32 tries; `TPM_RC_NV_DEFINED` → roll back and restart with a new journal; unknown outcome keeps the journal for `fsck`. Approve proposed tests F87 and F88 for Milestone 5 (the `fsck` half of F88 is Milestone 6) | Bound `init` |
| D4 | Duress availability checks and reporting | SI-42 | C1 to C3, plus C4 (now required: SI-36 tokens were approved for Milestone 3, and N2 makes C4 gate bound creation). Open question: warn on an owner's ordinary unlock when duress became unavailable? Recommendation in SI-42: `status` only | F81, `duress set` |
| D5 | Confirm the duress-setup draft | SI-32, spec 6.10 | `duress set` and `duress disable` (`DISABLE DURESS`) as ordinary-unlock commits; optional step in `init` after card verification and before the header write; refused in bound mode when unavailable; refused on read-only file systems | F59 (duress part), F81 |
| D6 | Duress behavior between Milestone 5 and Milestone 9 | Spec 0 item 2, 5.2 step 3, 15 | Proposed: a duress match stays a generic failure with **no** mutation, as in Milestone 4, until the trigger exists. `status` and documentation must not imply that duress acts before then (for example "Duress: configured (no action in this development build)"). Builds are not released before Milestone 18, but the wording must still be decided | Duress setup, `status` |
| D7 | N3 creation notice | Spec 5.6 (N3), PENDING | Whether `duress set` (or `init` with duress) warns when the main passphrase is custom and could fall into a refused generated-word class (the documented timing difference). Becomes relevant only once duress can be set | Duress setup |
| D8 | Bound card delivery under SI-52 | SI-52 (portable only), 7.4d | SI-52 defines paper and digital delivery for Card A and Card B. A bound vault has one card (`share_x = 3`). Needed: the `init` options for one card (for example `--card-dir` in digital mode); whether the same-volume acknowledgment applies (one card: no) and the vault-volume warning (yes); and the **rehearsal** for a bound vault (the delivered card must combine with S1 from the passphrase to the bundle that verifies the candidate header and key table; S2 from the TPM is not part of card recovery; spec 6.1 bound recovery is passphrase + card) | Bound `init` |
| D9 | CLI surface, approved before code (as `docs/CLI.md` was for Milestone 4) | `docs/CLI.md` K1, SI-18 | `--mode bound` behavior and whether a CLI default mode exists on Linux (spec 1 says bound is the default; K1 deferred it until bound exists); TPM selection (`--tpm device` per SI-18, plus a test-only or explicit option for a `swtpm` socket; not a secret, so an option is allowed); the owner-authorization prompt and its position in the `--secrets-stdin` line order; `duress set` and `duress disable`; new `status` lines; new messages, including the N2 refusal text from spec 9.3 | All user-facing work |
| D10 | Platform scope | Spec 13 (Milestone 17), SI-18 | Bound mode on Linux only; on macOS and Windows `--mode bound` keeps refusing with a clear message; portable-only builds need no TSS libraries | CI matrix, CLI |
| D11 | Development and test environment | Spec 0 item 8 | Linux CI with `swtpm` is required. Locally this Mac has Docker but no `swtpm` or `tpm2-tss`: options are a Linux container with `swtpm` for local runs, or relying on CI. A real TPM is never used without per-session authorization (this Mac has none for bound mode anyway) | Day-to-day work |
| D12 | swtpm test setup for the harder scenarios | F2, F19, F52, F81 | DA counter reads (`TPM_PT_LOCKOUT_COUNTER`) for F2 and F52; driving `swtpm` into lockout for F19 and F81 (short lockout parameters set on the emulator only); setting owner authorization and disabling the storage hierarchy on the emulator for F81; a fresh `swtpm` state per test | Test design |

## 6. Dependencies

| Kind | Item | Status |
| --- | --- | --- |
| Rust crate | `tss-esapi` (pin per D1) and its transitive crates | Not in the workspace; spec 7.6 lists `tss-esapi` with "version pin and features **PENDING SI-18**". Adding it needs D1 and a cargo-deny review (licenses, bans, advisories); any license exception would be added to `deny.toml` and `THIRD_PARTY_NOTICES.md`, as in Milestone 4 (A7) |
| System library | `tpm2-tss` ≥ 2.4.6 (`libtss2-dev` on Ubuntu) | Enforced by `tss-esapi-sys`'s build script; already installed in the CI smoke job |
| Emulator | `swtpm`, `swtpm-tools`; `tpm2-tools` for test setup only | Installed in the CI smoke job; not installed locally |
| CI | A Linux job that runs the bound tests against `swtpm` (feature `tpm`), including the Rust 1.89 job; macOS and Windows jobs keep building without the feature | To be designed with D10 and D11 |
| Earlier decisions | SI-36 tokens and H-2 template, N2, P1, N4, the 32-entry `tpm_cleanup` list | Approved; implemented as formats in Milestone 3 |

## 7. Tests

**Acceptance (spec 13, row 5):**

| Test | Scenario (spec 11) | Notes for the swtpm harness |
| --- | --- | --- |
| F1 | Bound vault copy only: cannot decrypt | Copy to a fresh `swtpm` (no index) |
| F2 | Wrong passphrase, correct TPM: `Unlock failed.`; DA counter increments | Read the lockout counter before and after |
| F3 | Right passphrase, index missing: `Unlock failed.` (no passphrase-only path) | Index undefined on the emulator by the test |
| F17 | Mode disagreement (portable unlock or portable cards on a bound vault, and the reverse) | Extends the Milestone 4 refusal test |
| F19 | TPM in lockout: clear message, no crash | Emulator lockout parameters |
| F30 | Name before vs after the first write: only the post-write Name is stored and matches | Compare with the public-area computation |
| F52 | Different Name or non-pvault public area at the handle: generic failure, `NV_Read` never called, DA counter unchanged | Decoy indices defined by the test |
| F59 | `init` interrupted after the header write, then re-run (also with the duress passphrase) | Failpoints; Path A; duress match changes nothing |
| F60 | `init` interrupted before the header write, re-run with and without the passphrase | Index removed only after 9.2b with the same-TPM token; without the passphrase it is left and reported |
| F61, F65 | Bound card payload and combine rules (`share_x = 3`) | Card unit tests; extend the Milestone 4 vectors if D8 changes delivery |
| F81 | Owner authorization set; storage hierarchy disabled; lockout | `duress set` refused, `status` "unavailable", a configured duress passphrase deletes nothing |

**Proposed, to approve with D3 and N2:** F87 (handle raced between probe and
define), F88 (unknown define outcome; the `fsck` resolution half is
Milestone 6) and F91 (bound `init` refused when the H-2 EK cannot be
measured: endorsement hierarchy disabled, endorsement authorization set, EK
not creatable).

**Regression:** every Milestone 4 test stays, including all paper and digital
tests. macOS and Windows keep their `--mode bound` refusal tests (D10). The
milestone also ends with the usual checks: `cargo fmt --check`, clippy,
`cargo test`, the native Rust 1.89 jobs on all three platforms, and
cargo-deny (spec 13).

## 8. Interaction with the outstanding Milestone 4 gates

| Gate | Overlap with Milestone 5 |
| --- | --- |
| Windows console checklist (14) | Bound mode is Linux-only (D10), so the TPM work does not touch Windows. Duress setup is not mode-specific, so `duress set` on a portable vault adds new terminal prompts on Windows (the shown duress passphrase, its type-back, `DISABLE DURESS`); the checklist would need steps for them later. A defect found by the gate in terminal input would affect those prompts too |
| Printed-card photo check (14a, paper only) | A bound vault's paper card uses the same renderer, QR encoder and PNG reader. Evidence from the gate carries over to the bound card. A defect it finds would affect bound cards as well |
| Shared code | Bound `init`, duress setup and `status` change `vault/init.rs`, the CLI and the card flow, which are also what the gates exercise. Fixing a gate finding while Milestone 5 changes the same files risks rework and confused evidence. This is the main reason to prefer E0 or E1 until Milestone 4 is accepted |

## 9. What can proceed while the Milestone 4 gates are outstanding

| Work | Without an exception | With E1 | With E2 | After Milestone 4 acceptance |
| --- | --- | --- | --- | --- |
| This review; decisions D1 to D12; recording approved decisions in the spec, `docs/SPEC_ISSUES.md` and `docs/CLI.md` | Yes | Yes | Yes | Yes |
| Drafting the `docs/CLI.md` Milestone 5 section for approval (D9) | Yes (documentation) | Yes | Yes | Yes |
| Uncommitted `tss-esapi` API spike outside the product tree | No | Yes | Yes | Yes |
| Adding `tss-esapi`, the `tpm` feature, CI swtpm test jobs | No | No | Yes | Yes |
| TPM session, NV, Name and identity modules with swtpm tests | No | No | Yes | Yes |
| Bound `init`, bound unlock, duress setup, CLI and `status` changes | No | No | No | Yes |

Running the two Milestone 4 gates needs only the author's time: the
Windows console session and a printed card. Completing them is the shortest
path to starting Milestone 5 without any exception.

## 10. Proposed sequence (once allowed)

1. Decisions D1 to D12 recorded; `docs/CLI.md` Milestone 5 section approved.
2. SI-18 confirmation: verify every SI-22 call in the pinned `tss-esapi`
   (E1 spike if approved earlier).
3. TPM layer: salting key, sessions, `GetCapability` checks (C1 to C4),
   `NV_ReadPublic` with exact public-area comparison, Name computation, EK
   measurement. swtpm tests: F30, F52 (DA counter), F19, F91.
4. Handle allocation and write-ahead index definition (F87, F88).
5. Bound `init` with card delivery (D8), resume and identity-checked removal
   (F59, F60); bound unlock (F1 to F3, F17).
6. Duress setup and availability (D4 to D7; F81, F59 duress part); `status`.
7. Full checks, native CI (including the swtpm job and the 1.89 jobs), and a
   Milestone 5 report. No destructive feature is written.

## 11. Recommended resolutions for D1 to D12 (for approval)

Prepared 2026-10-06 under E1. Nothing here is decided until the author
approves it; acceptance criteria are unchanged. "Probe" marks evidence gaps
that the E1 probe (section 12) is meant to close; gaps it cannot close are
listed as such.

### 11.1 Evidence gathered without the probe (2026-10-06)

Read-only lookups (crates.io API, OSV and the RustSec advisory database, and
the published crate sources, read but not built):

| Item | Finding |
| --- | --- |
| `tss-esapi` releases | Latest stable **7.7.0** (2026-04-24); newest overall 8.0.0-alpha.3 (2026-08-24). SI-18's premise still holds: 8.x is not stable |
| Declared minimum Rust | 7.7.0 and `tss-esapi-sys` 0.6.0: `rust-version = 1.85.0`, within pvault's MSRV 1.89 (to be confirmed by building with 1.89: probe) |
| Licenses | `tss-esapi`, `tss-esapi-sys`: Apache-2.0. New runtime crates `bitfield`, `enumflags2`, `num-derive`, `oid`, `picky-asn1`, `picky-asn1-x509`, `picky-asn1-der`, `pkg-config` (build): MIT OR Apache-2.0; `hostname-validator`, `mbox`: MIT. **`target-lexicon`** (build dependency of `tss-esapi-sys`, `^0.12.0`, resolves to 0.12.16): **Apache-2.0 WITH LLVM-exception**, which the current `deny.toml` allowlist does not cover; `deny.toml` checks build dependencies (`include-build = true`), so a crate-specific exception would be needed |
| Already in the workspace | `getrandom` 0.4, `log`, `num-traits`, `regex`, `serde`, `zeroize` |
| Advisories | `tss-esapi`: GHSA-w3vw-ccc5-qr8v (use after free in `Context::start_auth_session` with an explicit nonce), affected 7.0.0 to before 7.1.0 and before 6.1.2: **not** 7.7.0. `enumflags2`: RUSTSEC-2023-0035, affected 0.7.0 to before 0.7.7; `^0.7.1` resolves to 0.7.12: not affected. No advisory found for `tss-esapi-sys`, the `picky-asn1` crates, `mbox`, `hostname-validator`, `bitfield`, `oid`, `num-derive`, `target-lexicon` or `pkg-config` |
| System library | `tss-esapi-sys` 0.6.0's build script requires `tss2-sys`, `tss2-esys`, `tss2-tctildr` (and related) **≥ 2.4.6** through `pkg-config` |
| Bindings | Pre-generated for `aarch64-unknown-linux-gnu`, `arm-unknown-linux-gnueabi`, `x86_64-unknown-linux-gnu` (and `x86_64-unknown-darwin`); no `bindgen` or `clang` needed on Linux unless the `generate-bindings` feature is enabled |
| API coverage for SI-22 | Present in 7.7.0: `start_auth_session`, `tr_sess_set_attributes` with `with_decrypt` / `with_encrypt`, `execute_with_session(s)`, `create_primary`, `flush_context`, `nv_define_space`, `nv_undefine_space`, `nv_read_public`, `nv_write`, `nv_read`, `get_capability` with `PropertyTag::Permanent`, `StartupClear`, `LockoutCounter`, `MaxAuthFail`, `LockoutInterval`, `policy_or`, `policy_auth_value`, `tr_set_auth`, `tr_get_name`, `hierarchy_change_auth`; a `swtpm` TCTI (`TctiNameConf::Swtpm`) |
| Not wrapped in 7.7.0 | `DictionaryAttackLockReset`, `DictionaryAttackParameters`, `HierarchyControl` (marked "Missing function" in the source). pvault itself does not need them; the F19, F81 and F91 test setups do, through `tpm2-tools` against `swtpm` (D12) |
| Not covered by any lookup | Behavior and latency on real hardware TPMs; how `tpm2-tss` (C) handles session secrets in its own memory (not wiped by pvault; a section 10 limitation to document) |

### 11.2 Resolutions

**D1. TPM crate pin and feature gating (SI-18)**

- *Recommended:* `tss-esapi = "=7.7.0"` (exact pin; `tss-esapi-sys` 0.6.0
  through `Cargo.lock`) as a **Linux-only target dependency**, optional,
  enabled by a pvault feature `tpm` that is on by default (it has no effect
  on macOS and Windows, where the dependency is not built). Default crate
  features (no `generate-bindings`). System requirement `tpm2-tss` ≥ 2.4.6.
  **Plus one crate-specific `deny.toml` license exception:**
  `{ allow = ["Apache-2.0 WITH LLVM-exception"], crate = "target-lexicon" }`
  (build dependency of `tss-esapi-sys`; not compiled into pvault). The
  probe showed it is the **only** finding under the current policy
  (advisories, bans and sources pass; 12.2 check 1).
- *Alternatives:* (a) wait for `tss-esapi` 8.x stable (unknown date; 8.0 is
  alpha); (b) raw `tss-esapi-sys` FFI only (much more `unsafe` code in pvault,
  same C library); (c) a pvault-written TPM command layer over `/dev/tpmrm0`
  (would hand-write salted-session key derivation and parameter encryption,
  which spec 0 item 3 forbids); (d) driving `tpm2-tools` as subprocesses
  (authorization values would pass through arguments or files; rejected).
- *Evidence (probe, closed):* builds with Rust 1.89.0 and stable 1.99.0 on
  Ubuntu 24.04 aarch64 against `tpm2-tss` 4.0.1; the transitive graph is
  listed in 12.2. *Remaining:* the x86_64 build (CI, Milestone 5) and real
  hardware (11.4).
- *Impacts:* `Cargo.toml` (target dependency and feature), `Cargo.lock`,
  `deny.toml` (a crate-specific exception for `target-lexicon`,
  Apache-2.0 WITH LLVM-exception, build-only: compatible with GPL-3.0-only
  because the LLVM exception only adds permissions; for approval like A7),
  `THIRD_PARTY_NOTICES.md` (only for crates compiled into the binary;
  `target-lexicon` is build-only), spec 7.6 (replace "PENDING SI-18"), CI
  (`libtss2-dev` and `pkg-config` on the Linux jobs, including the 1.89
  job). No schema change.
- *Tests:* builds with and without the `tpm` feature on Linux; macOS and
  Windows build unchanged; cargo-deny clean; Rust 1.89 job.

**D2. Public area, Names and sessions (SI-22)**

- *Recommended:* approve SI-22 **with two amendments from the probe**:
  `nameAlg` SHA-256; attributes `0x00040004` pre-write and `0x20040004`
  post-write (ordinary, AUTHWRITE, AUTHREAD, DA protection on); `dataSize`
  97; `authPolicy` the PolicyOR of PolicyAuthValue and the nonce digest;
  Names computed by pvault from the 46-byte marshalled public area and
  compared with the TPM's; a transient ECC P-256 restricted decryption
  primary in the NULL hierarchy as the salting key; HMAC sessions with
  AES-128-CFB and SHA-256; no fallback to unsalted or clear sessions.
  - **Amendment 1: the salting key is created with an empty password
    session.** ESYS refuses `CreatePrimary` without an authorization session
    (`0x0007000b`, 12.2 check 3). The NULL hierarchy's authorization is
    always empty, so this session carries no secret; it is the only
    password session pvault uses, apart from the H-2 EK (D4).
  - **Amendment 2: per-command session attributes are fixed by pvault and
    enforced by pvault**, never left to the library: ESYS accepted a decrypt
    attribute on `NV_UndefineSpace`, which has no parameter to encrypt
    (12.2 check 5), so the stack does not reject wrong combinations.
    pvault builds every session from this table only (no caller-supplied
    attributes), and a unit test pins the table:

    | Command | Session | Attributes |
    | --- | --- | --- |
    | `GetCapability`, `NV_ReadPublic` | none | n/a (public data; responses are not integrity-protected, as SI-22 documents) |
    | `CreatePrimary`, NULL hierarchy (salting key) | empty password session | none |
    | `CreatePrimary`, endorsement hierarchy (H-2 EK, D4) | empty password session (C4 requires empty endorsement authorization) | none |
    | `NV_DefineSpace` (owner) | salted HMAC | **decrypt** (the `auth` parameter is `tpm_auth`) |
    | `NV_Write` (index authorization) | salted HMAC | **decrypt** (S2 wrapped) |
    | `NV_Read` (index authorization) | salted HMAC | **encrypt** (S2 wrapped) |
    | `NV_UndefineSpace` (owner) | salted HMAC | **neither** |

    Session lifetime is explicit: one session per command, flushed by
    pvault exactly once (the probe's double-flush errors, `0x1CB`, came from
    mixing `continueSession` clear with a library flush).
- *Alternatives:* bind the session to the EK instead of a NULL-hierarchy
  key (needs endorsement authorization and still no certificate check);
  unsalted sessions (rejected: `tpm_auth` and S2 would cross the bus in the
  clear).
- *Evidence (probe, closed, emulator only):* the exact public area is
  accepted; TPM-reported attributes and both Names equal pvault's
  computation; define, write, read and undefine work through salted
  sessions with the attributes above; the 97 bytes read back unchanged.
  *Remaining (11.4):* that parameter encryption actually hides the values on
  the wire was not observed (the probe checked attributes, not traffic);
  salting-key latency on hardware TPMs; active interposers (out of scope
  for v1, documented).
- *Impacts:* spec 9.1 and 5.2 step 5 (replace the PENDING notes), spec 4.1
  (the PENDING note on the exact public area); no header or journal schema
  change (the Milestone 3 bound fields already hold handle, Names and policy
  nonce).
- *Tests:* F30 (Names), F52 (decoy public areas, `NV_Read` never reached, DA
  counter unchanged), F2 (DA counter increments), a unit test pinning the
  per-command attribute table, a test that a session failure aborts instead
  of falling back, and a test that no `FlushContext` error occurs over a
  full define, write, read and undefine sequence.

**D3. Handle allocation, collisions, overflow (SI-35, pending part)**

- *Recommended:* approve SI-35 items 3 and 4 as written (random handle in
  the owner range, `NV_ReadPublic` probe, at most 32 attempts, journal before
  `NV_DefineSpace`; `TPM_RC_NV_DEFINED` → normal rollback and a new journal;
  definite errors → rollback; unknown outcome → keep the journal) and the
  generation overflow refusal. Approve F87 and the Milestone 5 half of F88.
- *Alternatives:* deterministic handles derived from `vault_id` (collide
  across vaults and reveal linkage); more attempts (no benefit at realistic
  occupancy).
- *Evidence gaps (probe):* the exact `tss-esapi` error value for
  `TPM_RC_NV_DEFINED` and for a missing index on `NV_ReadPublic`.
- *Impacts:* none on schemas (journal `IDX` fields exist since Milestone 3);
  two new failpoints in product code (between probe and define; after
  define with the outcome hidden) for the tests.
- *Tests:* F87, F88 (`init` part), a 32-attempt exhaustion test on an
  emulator with the probed handles pre-defined.

**D4. Duress availability (SI-42)**

- *Recommended:* **pvault constructs the H-2 template itself**, field by
  field from spec 8.1 (attributes `0x000300F2`, Policy-B-SHA256
  `ca3d0a99…b7a0`, AES-128-CFB, null scheme and KDF, NIST P-256, empty
  `unique`), and never uses `tss-esapi`'s EK helper, which builds the TCG
  **L-2** template for P-256 (Policy A, 32-byte zero `unique`): a different
  key and a different `ek_digest`. A unit test pins the marshalled template
  bytes. `ek_digest` is SHA-256 of the marshalled returned `TPMT_PUBLIC`
  (122 bytes on the emulator; 12.2 check 8). Then C1 (`ownerAuthSet` clear), C2 (`shEnable` set), C3
  (`inLockout` clear) and C4 (`ehEnable` set and `endorsementAuthSet` clear,
  plus the H-2 EK creatable), read with `GetCapability(TPM_PROPERTIES)` on
  `TPM_PT_PERMANENT` and `TPM_PT_STARTUP_CLEAR` and decoded by pvault (7.7.0
  has the property tags but no typed attribute structures). Evaluate at
  `duress set` (refuse if any fails), report each in `status`, and evaluate
  again on a duress match (no action until Milestone 9; D6). Unavailability
  is reported in `status` **only**, never during an ordinary unlock (a
  warning there would reveal that duress exists to a coercer).
- *Alternatives:* a warning on ordinary unlock (rejected for the reason
  above); checking only at `duress set` (misses later changes).
- *Evidence (probe, closed, emulator only):* each bit read back as expected
  after its setup; the failures are `0x9A2` (owner or endorsement
  authorization set, no DA count), `0x185` (hierarchy disabled) and `0x921`
  (lockout); the H-2 EK is deterministic for one TPM state and differs on a
  fresh state. *Remaining (11.4):* EK creation while in lockout; vendor
  differences on hardware.
- *Impacts:* `status` output (`docs/CLI.md` 6.6); no schema change.
- *Tests:* F81, F19, F91 (C4 at `init`), a unit test of the bit decoding.

**D5. Duress setup (SI-32, spec 6.10)**

- *Recommended:* confirm 6.10 for both modes: `duress set` (ordinary unlock
  with the duress check, generated 12-word duress passphrase shown once on
  the terminal and typed back, tag computed from the current slots, commit
  with a new key table and generation + 1) and `duress disable` (ordinary
  unlock, typed `DISABLE DURESS`, commit removing the tag); refused in bound
  mode when D4 fails, on read-only file systems and without a terminal (the
  duress passphrase is generated and shown only on the terminal, like a
  generated main passphrase). The optional `init` step runs only
  interactively, after card verification and before the header write.
- *Alternatives:* custom duress passphrases (rejected by SI-51: duress is
  generated only); offering duress in non-interactive `init` (impossible:
  the generated passphrase must be shown).
- *Evidence gaps:* none for the probe; the bound tag needs the new index
  fields at `init` (format already defined in Milestone 3).
- *Impacts:* new commands `duress set` and `duress disable`; `init` gains an
  interactive duress step; `docs/CLI.md` 5 and 6; header slots already carry
  the tag (no schema change).
- *Tests:* F59 (duress part), F81, `duress set`/`disable` round trips in both
  modes, the type-back mismatch, refusal without a terminal, a crash at each
  commit step (failpoints, as in Milestone 4).

**D6. Duress between Milestone 5 and Milestone 9**

- *Recommended:* a duress match keeps returning the generic failure with
  **no** mutation (Milestone 4 behavior) until the Milestone 9 trigger
  exists. `status` shows "Duress: configured (no action in this development
  build)" and the documentation says the same; spec 5.2 step 3 gets a note
  that the trigger is gated (spec 0 item 2). No release happens before
  Milestone 18, so this text never ships unless the trigger is missing.
- *Alternatives:* defer duress setup itself to Milestone 9 (contradicts the
  Milestone 5 row and spec 0 item 2, which builds setup before the gate).
- *Impacts:* `status` wording; spec 5.2 note; no schema change.
- *Tests:* a duress match after `duress set` changes nothing (vault and TPM
  byte-identical, DA counter unchanged apart from the expected read).

**D7. N3 creation notice (PENDING)**

- *Recommended:* at `duress set` (and the duress step of `init`), when the
  main passphrase is custom **and** the just-entered main passphrase falls
  into a class that generated-word handling refuses (5.6: empty after
  trimming, over 1,024 bytes after NFKC, an unassigned code point), print
  the documented timing notice and continue. No notice otherwise.
- *Alternatives:* always print it for custom main passphrases (noisier, but
  needs no evaluation); documentation only (owners may never see it).
- *Impacts:* one message (`docs/CLI.md` 7); spec 5.6 PENDING marker
  resolved. No schema change.
- *Tests:* notice shown for a refused-class custom passphrase, not shown
  otherwise; nothing about the passphrase is printed.

**D8. Bound card delivery (SI-52 for one card)**

- *Recommended:* the same two modes for the single bound card
  (`share_x = 3`, role "Bound card"): `--cards paper --cards-dir <dir>`
  (one file `pvault-<vault8>-<set8>-bound.svg`, printed and verified by
  photo or typed text), or `--cards digital --card-dir <dir>` (new option;
  `--accept-risk digital-cards` or the typed phrase; no same-volume
  acknowledgment, since there is one card; the vault-volume and sync
  warnings apply). The **rehearsal** for bound vaults follows spec 6.1:
  S1 from the passphrase and the candidate slots, S3 from the delivered
  card, combined to the bundle that must verify the candidate header and
  `keytable.1.pv`; S2 is not used. The R5 check after the commit applies to
  the one file.
- *Alternatives:* paper only for bound cards (owners without printers could
  not create bound vaults); reuse `--card-a-dir` for the bound card
  (misleading name).
- *Impacts:* `docs/CLI.md` 6.1; spec 7.4d (bound paragraph);
  `docs/RECOVERY_DELIVERY_PROPOSAL.md` (a bound addendum); `cards.cbor`
  already reserves role `"bound"` and version 2 already carries `delivery`,
  so **no schema change**; `docs/FORMAT.md` should add a bound-card
  format 1 vector (generator change in `tools/vectors`).
- *Tests:* bound variants of `digital_init_keeps_the_card_files`,
  `rehearsal_uses_the_delivered_cards`, `digital_crash_at_each_step` and the
  reader vector; F61, F65 for `share_x = 3`; paper bound card verification.

**D9. CLI surface**

- *Recommended:*
  - `--mode` stays required (no default) until spec 16 item 3 is decided;
    K1 is updated accordingly.
  - `--tpm <device|swtpm:PORT>`: `device` means `/dev/tpmrm0` and is the
    default for bound commands; `swtpm:PORT` connects to a local emulator
    on `127.0.0.1` (tests, development). Not a secret, so an option is
    allowed; no environment variable, so a test run cannot silently fall
    back to a device. During development the test harness always passes
    `swtpm:` explicitly.
  - Owner authorization (9.3): a hidden prompt "TPM owner authorization:"
    when C1 shows it is set and an index must be defined or deleted. Under
    `--secrets-stdin` the line order would otherwise depend on TPM state,
    so the owner must add `--tpm-owner-auth` (a flag without a value) to
    declare that the line follows the passphrase lines; without the flag,
    a set owner authorization refuses the command before anything is
    written (exit 4).
  - `pvault duress set <vault>`, `pvault duress disable <vault>`.
  - `status` adds: TPM (bound only), owner authorization set, storage
    hierarchy, lockout, duress availability (D4, D6).
  - Messages: the N2 refusal (spec 9.3 text), the TPM session failure, the
    lockout message (F19), the N3 notice (D7).
- *Alternatives:* bound as the CLI default on Linux (spec 1; changes every
  existing `init` example and test); a `PVAULT_TPM` environment variable
  (rejected above).
- *Impacts:* `docs/CLI.md` 2, 4, 5, 6.1, 6.6, 7 and K1; approved before code,
  as for Milestone 4. No schema change.
- *Tests:* parser tests; non-interactive line counts with and without
  `--tpm-owner-auth`; F79 (no secret in arguments).

**D10. Platform scope**

- *Recommended:* bound mode on Linux only in v1; on macOS and Windows
  `--mode bound`, `duress set` on a bound vault, and opening a bound vault
  refuse with "Bound mode needs a Linux computer with a TPM in this
  version." (exit 6); portable everything stays available. Milestone 17
  investigates other platforms.
- *Alternatives:* compile the TPM layer everywhere and refuse at runtime
  (needs `tpm2-tss` on every build host; no benefit).
- *Impacts:* `docs/CLI.md`; CI keeps macOS and Windows without TSS
  libraries.
- *Tests:* refusal tests on macOS and Windows; F17 on all platforms.

**D11. Development and test environment**

- *Recommended:* native Linux CI with `swtpm` is the evidence of record
  (a new job, plus the 1.89 job with the feature). Locally, a Docker Linux
  container with `swtpm`, `tpm2-tools` and `libtss2-dev` (section 12), with
  no device access. A real TPM is never used without the owner's
  per-session authorization; neither this Mac nor the container has one.
- *Alternatives:* CI only (slow feedback); a Linux VM (heavier than a
  container, same effect).
- *Impacts:* CI workflow; a documented local recipe; no product impact.

**D12. swtpm setups for the harder tests**

- *Recommended:* **isolated emulator state for every test**: a fresh `swtpm`
  state directory and TCP port pair per test (parallel-safe), so no test
  inherits another's DA counter, lockout, authorizations or indices. swtpm
  defaults to `maxAuthFail` 3 with a 1000 s lockout interval and recovery
  (12.2 check 2), so any test that makes more than two failed attempts on
  one emulator, or that drives lockout on purpose, first sets **short
  lockout parameters** (`tpm2_dictionarylockout --setup-parameters`, for
  example 2 tries and 600 s, as in the probe) on its own emulator. Setup
  through `tpm2-tools` against that emulator only (7.7.0 has no wrappers
  for `DictionaryAttackParameters` or `HierarchyControl`):
  `tpm2_dictionarylockout` (short lockout parameters, and driving lockout)
  for F19 and F81; `tpm2_changeauth -c owner` for F81 and the
  owner-authorization prompt; `tpm2_hierarchycontrol` (shEnable,
  ehEnable) and `tpm2_changeauth -c endorsement` for F81 and F91; the DA
  counter read through `GetCapability` (`TPM_PT_LOCKOUT_COUNTER`) for F2 and
  F52. A test-harness guard refuses any TCTI other than `swtpm:`.
- *Evidence (probe, closed, emulator only):* each setup's effect on the
  reported bits and the counter is recorded in 12.2 checks 6 and 7.
- *Impacts:* CI installs `tpm2-tools` (already in the smoke job); test-only.

### 11.3 Impact summary

| Area | Changes if D1 to D12 are approved as recommended |
| --- | --- |
| Dependencies | `tss-esapi` =7.7.0 (Linux, feature `tpm`), its transitive crates; a `deny.toml` exception for `target-lexicon` (build-only) |
| Schemas | **None.** The header, journal, token and `cards.cbor` formats from Milestones 3 and 4 already carry every bound field; D8 uses the reserved `"bound"` role |
| CLI | `--tpm`, `--tpm-owner-auth`, `--card-dir` (digital bound), `duress set`, `duress disable`, `status` lines, messages (D7, D9, D10, N2) |
| Spec | 4.1, 5.2, 5.6, 7.4d, 7.6, 9.1, 9.3 PENDING markers resolved; F87, F88, F91 adopted |
| CI | Linux `swtpm` test job (stable and 1.89), `libtss2-dev`, `pkg-config`, `tpm2-tools` |
| Tests | Section 7 plus the D-specific tests above |

### 11.4 Remaining gaps and what they block

"Implementation" means writing Milestone 5 code once allowed; "acceptance"
means Milestone 5 acceptance; "release" means the Milestone 18 release.
Nothing in this table is evidence about real TPM hardware.

| Gap | Blocks implementation | Blocks acceptance | Blocks release | Why, and how it closes |
| --- | --- | --- | --- | --- |
| Decoy public areas at the handle (F52) | No | **Yes** | Yes | Required acceptance test; written in Milestone 5 against `swtpm` |
| Handle raced between probe and define (F87) | No | **Yes**, if D3 adopts F87 | Yes | Needs a product failpoint; Milestone 5 test |
| Unknown define outcome (F88, `init` half) | No | **Yes**, if D3 adopts F88 | Yes | Needs a product failpoint; the `fsck` half is Milestone 6 |
| Successful index definition with a non-empty owner authorization | No | **Yes** | Yes | The D9 owner-authorization prompt must be shown to work; Milestone 5 test on `swtpm` (`tpm2_changeauth -c owner`) |
| H-2 EK creation while the TPM is in DA lockout | No | **Yes** | Yes | Decides whether C4 must be evaluated during lockout (the endorsement hierarchy's authorization is not DA-protected, but this was not observed); Milestone 5 test |
| Bound unlock end to end (F1 to F3, F17, F59, F60) | No | **Yes** | Yes | These are the Milestone 5 acceptance tests themselves |
| x86_64 Linux build and run | No | **Yes** | Yes | The probe ran on aarch64; native CI (x86_64 Ubuntu 24.04) covers it |
| Parameter encryption observed on the wire | No | No | No | The probe checked session attributes, not traffic; SI-22 relies on the TPM 2.0 specification and `tpm2-tss` for the encryption itself. Optional: a `swtpm` trace comparison, if the author wants it |
| **Session secrets inside `tpm2-tss` (C library memory)** | No | **Yes: needs a recorded decision** | Yes | Section 10 makes secrets hygiene mandatory, but pvault cannot wipe memory that `tpm2-tss` allocates for session keys, HMAC keys and parameter buffers (`tpm_auth`, wrapped S2). `tss-esapi` zeroizes its own Rust copies; whether `tpm2-tss` clears its buffers was not checked. Before acceptance: read the `tpm2-tss` 4.0.1 sources for those buffers and record the result, then either accept the residue as a documented section 10 limitation (`docs/FAILURE_MODES.md`) or design a mitigation |
| Real TPM hardware: behavior, timings, vendor differences | No | No (Milestone 5 is defined as "Bound mode via swtpm") | **Yes, by recommendation** | Only an owner-authorized real-TPM session can close it (spec 0 item 8); recommend at least one authorized hardware run on Linux before release, recorded like the manual gates |
| Salting-key latency on slow hardware TPMs | No | No | Yes (documentation) | Measured only on the emulator (about 9 ms); measure during the authorized hardware run |
| Active interposer between CPU and TPM | No | No | Yes (documentation only) | Out of scope for v1 (SI-22): `docs/THREAT_MODEL.md` must say so |

## 12. E1 probe plan (for approval before any setup)

**Purpose:** confirm, outside the repository, that `tss-esapi` 7.7.0 builds
with Rust 1.89 against `tpm2-tss` on Linux, and that the D2 to D4 and D12
calls behave as proposed on `swtpm`. The probe is throwaway code, not
Milestone 5 product code, and is never committed.

**Environment and its effects on this Mac:**

| Step | Effect on the host |
| --- | --- |
| Start Docker Desktop (installed: Docker 29.2.1 client, `Docker.app`) | Starts Docker's Linux virtual machine; uses CPU, memory (as configured in Docker Desktop) and disk space in Docker's own storage; may show Docker's first-run prompts if any are pending. Quitting Docker Desktop stops it |
| Pull `ubuntu:24.04` (arm64; matches the CI runner's Ubuntu release) | About 30 MB download, stored by Docker |
| One container `pvault-tpm-probe`, no `--privileged`, no devices, no host networking, no published ports | Inside the container only: `apt-get install` of `build-essential`, `pkg-config`, `ca-certificates`, `curl`, `swtpm`, `swtpm-tools`, `tpm2-tools`, `libtss2-dev`; `rustup` with Rust 1.89 and stable; cargo-deny 0.20.2 from its release (checksum-verified, as in CI). Several hundred MB to about 2 GB inside the container. Nothing is installed on macOS |
| Files | One bind mount: a new, empty scratch folder for the probe crate (in this session's scratchpad), read-write. The repository is **not** mounted; `deny.toml` is copied in as a file for the license check |
| TPM | `swtpm` runs inside the container with a temporary state directory, listening only on the container's own loopback. No real TPM exists in the container or on this Mac; no host TPM setting is read or changed |
| Network | Downloads from Docker Hub, Ubuntu mirrors, `static.rust-lang.org`, crates.io and GitHub releases (cargo-deny) |

**What the probe checks:**

1. Build with Rust 1.89 and stable: `tss-esapi =7.7.0` and its graph
   (`Cargo.lock` recorded); cargo-deny with the repository's `deny.toml`
   (expect the `target-lexicon` license finding).
2. `swtpm` startup; `GetCapability` for `TPM_PT_PERMANENT`,
   `TPM_PT_STARTUP_CLEAR`, `TPM_PT_LOCKOUT_COUNTER`.
3. Transient ECC P-256 primary in the NULL hierarchy; salted HMAC session,
   AES-128-CFB, SHA-256; decrypt and encrypt attributes per command.
4. `NV_DefineSpace` with the exact SI-22 public area and PolicyOR digest;
   the TPM's pre-write Name equals an independent computation; `NV_Write`
   of 97 bytes; post-write Name equal; `NV_ReadPublic` exact comparison;
   `NV_Read` returns the bytes; `NV_UndefineSpace` with (empty) owner
   authorization.
5. Error values: `NV_ReadPublic` on an absent handle; `NV_DefineSpace` on an
   existing handle (`TPM_RC_NV_DEFINED`); wrong `authValue` on `NV_Read` and
   the DA counter before and after.
6. D12 setups through `tpm2-tools`: owner authorization set (C1 bit),
   `shEnable` cleared (C2), lockout driven with short parameters (C3),
   endorsement authorization set and `ehEnable` cleared (C4); each bit read
   back through `GetCapability`.
7. The H-2 ECC P-256 EK created twice from the fixed template gives the
   same public key (identity measurement is deterministic on one emulator
   state) and a different one on a fresh `swtpm` state.

**Results:** recorded in this section (commands, versions, outputs); the
probe crate and container are then removed: `docker rm -f
pvault-tpm-probe`, optionally `docker image rm ubuntu:24.04`, and the scratch
folder deleted. Nothing enters the repository.

### 12.1 First probe attempt (2026-10-06): blocked by Docker Desktop

Authorized by the author on 2026-10-06 (setup as described above). **None of
the eight checks ran**; no emulator or TPM observation exists yet.

| Step | Observed |
| --- | --- |
| Host | macOS 27.0 (arm64); Docker Desktop 4.64.0 (Docker 29.2.1 client and engine); Docker was not running before the probe |
| Existing Docker data (left untouched) | Images `postgres:15-alpine`, `redis:alpine`, `rabbitmq:3-management`, `docker/welcome-to-docker:latest`; container `welcome-to-docker` (exited); 2 volumes |
| Scratch | A new scratch folder holding only a copy of `deny.toml` with the probe-only `target-lexicon` exception; the repository `deny.toml` is unchanged; the repository was never mounted |
| Image | `ubuntu:24.04`, arm64, `sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55`, pulled |
| Container | `docker run` (no `--privileged`, no devices, default bridge network, no published ports, one bind mount of the scratch folder) created `pvault-tpm-probe` but never started it; a second test with no mount (`pvault-tpm-probe-nomount-test`) hung the same way |
| Docker Desktop | Stayed in state `starting`; its VM log stopped at "libproxy: disconnected data connection: multiplexer is offline" about a minute after launch; one restart did not help; afterwards the engine answered `info` but returned HTTP 500 for container listing. No reset, update, reinstall or settings change was made |
| After | Docker Desktop quit was requested; the backend stopped, its interface processes remained. The two created containers (never started) remain in Docker's data until the engine works and they can be removed; the `ubuntu:24.04` image remains |

**Second attempt (same evening).** A stale Docker Desktop interface process
from the first quit blocked a new engine start (Docker reported
"pid 80428: Docker Desktop"); the author chose "Stop processes" and Docker
Desktop relaunched with its VM process running. The engine then failed the
same way: the VM log again ended with "libproxy: disconnected data
connection: multiplexer is offline" about one minute after boot, the state
stayed `starting`, and `docker ps` first returned HTTP 500 and later hung.
No container was started, so the 60-second start limit was never reached;
the two old probe containers could not be removed while the engine was
down. The failure is reproducible across fresh starts of Docker Desktop
4.64.0 on macOS 27.0 in this setup; its cause inside Docker is not known.

Remaining evidence gaps: all of those listed for the probe (sections 11.1
and 11.2); the source-level findings of 11.1 stand unchanged.

### 12.2 Probe run (2026-10-06, after a Mac restart): all eight checks ran

The author restarted the Mac; Docker Desktop was then version **4.94.0**
(client and engine 29.8.2) and the engine answered within the time limits.
Only the remaining old probe container was removed (the second one no longer
existed); the new `pvault-tpm-probe` started in under a second (limit 60 s)
with `privileged=false`, network `bridge`, no devices, no published ports, no
added capabilities and one bind mount (the scratch folder). The repository
was never mounted. **Everything below is an emulator observation (`swtpm`)
unless it says otherwise; nothing here is evidence about real TPM hardware.**

**Environment (inside the container only):** Ubuntu 24.04.5 LTS, aarch64;
`swtpm` and `swtpm-tools` 0.7.3-0ubuntu5.24.04.1 (TPM emulator 0.7.3);
`tpm2-tools` 5.6-1build4; `libtss2-dev` 4.0.1-7.1ubuntu5.1 (`tss2-esys`,
`tss2-sys`, `tss2-tctildr`, `tss2-mu` 4.0.1, above the 2.4.6 minimum);
`pkg-config` 1.8.1; `git` 2.43.0 (added for cargo-deny's advisory fetch);
Rust 1.89.0 and stable 1.99.0 (rustup, minimal profile); cargo-deny 0.20.2
(aarch64 musl release, SHA-256 `995c82be…7dc` matched its published
checksum). Each emulator ran with throwaway state in the container's `/tmp`,
bound to the container's own 127.0.0.1.

**Resolved dependencies** (probe crate: `tss-esapi =7.7.0`, `sha2 0.10`;
`Cargo.lock` 49 packages, SHA-256 `203d55b2…638a`). From `tss-esapi`:
`tss-esapi-sys` 0.6.0, `bitfield`/`bitfield-macros` 0.19.5, `enumflags2`
0.7.12, `getrandom` 0.4.3, `hostname-validator` 1.1.1, `log` 0.4.34, `mbox`
0.7.1, `num-derive` 0.4.2, `num-traits` 0.2.19, `oid` 0.2.1, `picky-asn1`
0.10.1, `picky-asn1-der` 0.5.7, `picky-asn1-x509` 0.15.5, `regex` 1.13.1,
`serde` 1.0.229, `zeroize` 1.9.1; build: `pkg-config` 0.3.34,
`target-lexicon` 0.12.16. Two `syn` versions (2.0.119 and 3.0.6) are a
duplicate-version warning only.

| # | Check | Result (emulator) |
| --- | --- | --- |
| 1 | Build and policy | Builds with Rust 1.89.0 and stable 1.99.0, no warnings. cargo-deny with the **repository policy as is** (plus an allowance for the probe crate's own license): advisories ok, bans ok (one duplicate warning), sources ok, **licenses failed only on `target-lexicon`** ("license is not explicitly allowed"). With the probe-only `target-lexicon` exception: all four pass. The repository `deny.toml` is unchanged |
| 2 | Capabilities | `GetCapability(TPM_PROPERTIES)` from `0x200`: `TPM_PT_PERMANENT` `0x00000400`, `TPM_PT_STARTUP_CLEAR` `0x8000000f`; C1 to C4 decoded as expected on a fresh emulator. swtpm defaults: `maxAuthFail` 3, `lockoutInterval` 1000 s, `lockoutRecovery` 1000 s, counter 0 |
| 3 | Salting key and sessions | ECC P-256 restricted decryption primary in the NULL hierarchy created (about 9 ms on the emulator). **It needs an authorization session** (ESYS `0x0007000b`, "not enough sessions", without one): an empty password session, since the NULL hierarchy's authorization is always empty. Salted HMAC sessions (AES-128-CFB, SHA-256) with decrypt or encrypt per command worked |
| 4 | Index definition and Names | `NV_DefineSpace` with the exact SI-22 public area through a salted decrypt session: TPM-reported attributes `0x00040004`, size 97, `authPolicy` equal to the PolicyOR computation; **pre-write Name equals the independent computation**. After `NV_Write` (97 bytes, decrypt session): attributes `0x20040004`, **post-write Name equals the independent computation** |
| 5 | Read and delete | `NV_Read` through an encrypt session returned the 97 bytes unchanged; `NV_UndefineSpace` with empty owner authorization in a salted session succeeded. A decrypt attribute on `NV_UndefineSpace` (no parameter to encrypt) was **accepted**, not refused |
| 6 | Error codes and DA | `NV_ReadPublic` absent handle: `0x18B` (TPM_RC_HANDLE, handle 1). `NV_DefineSpace` on an existing handle: `0x14C` (TPM_RC_NV_DEFINED). `NV_Read` with a wrong `authValue`: `0x98E` (TPM_RC_AUTH_FAIL, session 1); lockout counter 0 → 1 |
| 7 | D12 setups (fresh emulator each) | C1 `tpm2_changeauth -c owner`: `ownerAuthSet` true; `NV_DefineSpace` with empty owner authorization then fails `0x9A2` (TPM_RC_BAD_AUTH, no DA count). C2 `tpm2_hierarchycontrol -C p shEnable clear`: `shEnable` false; `NV_DefineSpace` fails `0x185` (TPM_RC_HIERARCHY). C3 `tpm2_dictionarylockout` max-tries 2: wrong reads give counter 0 → 1 → 2, then `0x921` (TPM_RC_LOCKOUT) and `inLockout` true. C4a `tpm2_changeauth -c endorsement`: `endorsementAuthSet` true; EK creation fails `0x9A2`. C4b `ehEnable clear`: `ehEnable` false; EK creation fails `0x185` |
| 8 | H-2 EK identity | Built from the spec 8.1 template (attributes `0x000300F2`, Policy-B-SHA256, AES-128-CFB, null scheme and KDF, P-256, empty `unique`); created with an empty-password session in the endorsement hierarchy. Same emulator state: the same `ek_digest` twice (`50204e32…a961`); fresh state: a different one (`ac0d1687…4edd`). The marshalled `TPMT_PUBLIC` is 122 bytes, consistent with the spec's "excluding the outer size" |

**Findings that change or refine section 11:**

- **D1:** the build and policy results confirm the recommendation; the
  `target-lexicon` exception is required, and nothing else in the graph
  needs one.
- **D2:** the salting key is created with an empty password session (not
  "no session"), which must be written into SI-22; it carries no secret.
- **D2/D3:** ESYS accepted a decrypt attribute on a command with no
  parameter to encrypt, so pvault cannot rely on the stack to reject a
  misconfigured session; it should set exactly the attributes SI-22 lists
  per command and test them.
- **D3:** the codes for the SI-35 table are confirmed on the emulator:
  `0x14C` for a raced definition, `0x18B` for an absent handle on
  `NV_ReadPublic`.
- **D4:** C1 to C4 bits read back as expected after each setup; an owner
  authorization set makes index definition fail with `0x9A2` (no DA count),
  which is what the owner-authorization prompt (D9) must handle.
- **D8/D12:** swtpm's default lockout parameters (3 tries, 1000 s) would
  lock tests out quickly; tests must set short parameters or use a fresh
  emulator per test, as proposed.
- **Spec 8.1 / SI-36:** `tss-esapi`'s own EK helper builds the TCG **L-2**
  template for P-256 (Policy A, 32-byte zero `unique`), not **H-2**; pvault
  must construct H-2 itself, as the probe did. This is a source-level fact
  about 7.7.0, not an emulator observation.
- **Probe artifact, not a pvault finding:** `FlushContext` errors `0x1CB` at
  exit came from the probe closing sessions with `continueSession` cleared
  and the library flushing them again; pvault's session lifetime must be
  explicit.

**Remaining evidence gaps:**

- Real TPM hardware: behavior, timings (salting-key creation measured only
  on the emulator) and vendor differences. Not closable under E1.
- An active interposer (out of scope for v1, documented).
- How `tpm2-tss` holds session secrets in its own memory (not wiped by
  pvault); a section 10 limitation to document.
- Not exercised: F52 decoy public areas (different attributes, size or
  policy at the handle), the handle race between probe and define (F87),
  an unknown define outcome (F88), a successful definition with a non-empty
  owner authorization, EK creation while in DA lockout, and the bound
  unlock path as a whole. These are Milestone 5 tests, not probe items.

**Cleanup:** the container `pvault-tpm-probe` was removed with all emulator
state (it lived inside the container). Remaining: the image `ubuntu:24.04`
(141 MB, kept for a possible rerun; removable with `docker image rm
ubuntu:24.04`), the scratch folder (266 MB, mostly build output; outside the
repository), and Docker Desktop running. Unrelated Docker data (four images,
the `welcome-to-docker` container, two volumes) is unchanged.

## 13. Final decision table (D1 to D12)

Recommendations as of 2026-10-06, after E1. "Choice" lists what the author
must still decide; "approve" means the recommendation can be taken as is.

| # | Recommendation | Choice for the author |
| --- | --- | --- |
| D1 | `tss-esapi = "=7.7.0"` (`tss-esapi-sys` 0.6.0), Linux-only optional dependency behind feature `tpm` (default on); `tpm2-tss` ≥ 2.4.6; one `deny.toml` exception `{ allow = ["Apache-2.0 WITH LLVM-exception"], crate = "target-lexicon" }` (build-only) | Approve the pin and the exception |
| D2 | SI-22 public area, Names and salted HMAC sessions (AES-128-CFB, SHA-256), no fallback; **salting key created with an empty password session**; **per-command session attributes fixed and enforced by pvault** (table in 11.2); explicit session lifetime | Approve SI-22 with the two amendments |
| D3 | SI-35 handle allocation (random, probe, 32 attempts, journal first), collision (`0x14C`) and unknown-outcome handling, generation overflow refusal; adopt F87 and the Milestone 5 half of F88 | Approve; confirm F87/F88 as acceptance tests |
| D4 | **pvault-built H-2 template** (never the library's L-2 helper), `ek_digest` over the 122-byte `TPMT_PUBLIC`; C1 to C4 from `TPM_PT_PERMANENT` and `TPM_PT_STARTUP_CLEAR`; evaluated at `duress set`, in `status`, and on a duress match | Approve; and decide the SI-42 open question: report unavailable duress **in `status` only** (recommended) or also warn on ordinary unlock |
| D5 | Spec 6.10 for both modes: `duress set` and `duress disable` (`DISABLE DURESS`), terminal required, optional interactive step in `init` | Approve the 6.10 draft |
| D6 | Until Milestone 9, a duress match stays a generic failure with no mutation; `status`: "Duress: configured (no action in this development build)"; note in spec 5.2 | Approve, or choose different `status` wording |
| D7 | N3 notice only when the main passphrase is custom **and** falls in a refused generated-word class | **Choose:** conditional notice (recommended), always for custom, or documentation only |
| D8 | Bound card: `--cards paper --cards-dir` (file `…-bound.svg`) or `--cards digital --card-dir` with `digital-cards`; no same-volume acknowledgment; rehearsal S1 + S3 against the candidate header and key table (spec 6.1); no schema change; add a bound-card format 1 vector | Approve, or choose another option name than `--card-dir` |
| D9 | `--mode` stays required; `--tpm device\|swtpm:PORT` (no environment variable); `--tpm-owner-auth` declares the owner-authorization line under `--secrets-stdin` (refused without it when owner authorization is set); `duress set`/`disable`; `status` TPM lines; `docs/CLI.md` updated and approved before code | **Choose:** keep `--mode` required (recommended) or make bound the Linux default; approve the option names |
| D10 | Bound mode on Linux only; macOS and Windows refuse `--mode bound` and bound vaults (exit 6) | Approve |
| D11 | Native Linux CI with `swtpm` is the evidence of record; local runs in a Docker Ubuntu 24.04 container as in the probe (worked with Docker Desktop 4.94.0); never a real TPM without per-session authorization | **Choose:** local container recipe (recommended) or CI only |
| D12 | **Isolated emulator state per test** (fresh state directory and ports); **short lockout parameters** (`tpm2_dictionarylockout`) before any test with more than two failed attempts; setup only through `tpm2-tools` against that emulator; harness refuses any TCTI but `swtpm:` | Approve |

**Decisions arising from the gaps (11.4):**

1. `tpm2-tss` session-secret memory: approve reading the 4.0.1 sources
   before acceptance and recording the result, then either accept a
   documented section 10 limitation or require a mitigation.
2. Real TPM hardware: decide whether one owner-authorized hardware run on
   Linux is a release requirement (recommended), and when to authorize it.

Starting Milestone 5 itself still needs Milestone 4 acceptance (both manual
gates) or a new, explicit exception (section 1).

## 14. Implementation under E2 (2026-10-06 to 2026-10-11; commits `dab6264` and `c4a4480`)

Milestone 5 is implemented under exception E2 (`docs/SPEC_ISSUES.md`),
against the approved D1 to D12 and the acceptance-plan amendment. Milestone
5 was **accepted on 2026-10-11 as emulator-tested work only** ("Acceptance"
below); **Milestone 4 is not accepted** and both of its manual gates remain
outstanding; no real TPM was accessed (development on `swtpm` only).

**Acceptance (author, 2026-10-11).** Basis: implementation commit
`c4a4480`, evidence commit `9a7a6dd`, and native CI runs 38157453235 and
38159526520 (all 12 jobs green in each), against the spec 13 row 5 criteria
as amended, verified on `swtpm`, with the `tpm2-tss` report decided (15).
Acceptance is **not** real-TPM validation, does **not** establish complete
secret-memory wiping, and does **not** make bound mode release-ready:
owner-authorized real-hardware validation stays required before any
bound-mode release. Every limitation recorded below stays open (E1, V3's
cause, the runner's process-start window, the accepted `tpm2-tss` memory
limitation) and so do the licensing questions in `THIRD_PARTY_NOTICES.md`.

**Commit and native CI:** committed as `dab6264` (2026-10-11). Its first
native CI run (38154441494) did not start: GitHub refused every job for an
account billing problem. After the repository was made public, the re-run
(38155611115, attempt 2, commit `0af6cf1`) passed 11 of 12 jobs; the fuzz
smoke job failed at its seed step ("Failed to find tss2-sys library"),
because the seed test builds `pvault-core` with its default features, which
include `tpm` on Linux, and that job did not install `tpm2-tss`. Commit
`c4a4480` installs `libtss2-dev` in that job, as the release-check job
already did; no test, assertion or timing limit changed.

**Native CI evidence (run 38157453235, commit `c4a44806f7b0`, 2026-10-11:
all 12 jobs succeeded).**
<https://github.com/yashtamhane/pvault/actions/runs/38157453235>. Read from
the job logs, not only the job status. Counts come from each job's main
`cargo test --workspace --locked` step; stable and Rust 1.89 gave identical
counts on each operating system.

| Platform | Shared-process libtest: passed / failed / ignored | Isolated tests passed in their own process | Substantive libtest tests | Scenario suites: passed / skipped |
| --- | --- | --- | --- | --- |
| Linux (ubuntu-latest, x86_64) | 235 / 0 / 39 | 33 | 266 | 17 / 2 |
| macOS (macos-latest) | 235 / 0 / 19 | 13 | 246 | 14 / 2 |
| Windows (windows-latest) | 226 / 0 / 15 | 9 | 233 | 12 / 2 |

- **No double counting:** the shared-process "passed" count includes the
  runner (`test_process::tests_that_start_processes_run_in_their_own_process`),
  and the isolated count includes the completeness check
  (`test_process::the_isolated_set_is_complete`). Neither is a substantive
  test, so substantive = shared passed − 1 + isolated − 1. The isolated tests
  appear in the shared "ignored" count, not in its "passed" count. Scenario
  suites are a separate test binary and are not in the libtest counts.
- **Isolated tests:** the "Isolated process tests ran" step printed the list
  on every operating system (Linux 33: the 20 TPM emulator tests, 4
  signal-restoration, 6 store crash, the lock-holder test, the `mkfifo`
  test and the completeness check; macOS 13, without the emulator tests;
  Windows 9, without the emulator and Unix signal tests), and on Linux the
  required emulator names were present. Both Linux test jobs installed
  `swtpm` 0.7.3 and `tpm2-tss` 4.0.1 with `PVAULT_TEST_REQUIRE_SWTPM=1`, so
  the emulator tests could not skip; no "swtpm is not installed" line
  appears.
- **The other ignored tests** (6 per platform) are not skipped coverage:
  helper processes started by their tests (`lock_holder_child`,
  `crash_child`, `stdin_helper`, and on Unix `signal_helper_reads_from_pty`),
  on Windows the drive-mapping probe instead (run by the Windows locality
  step: 2 passed), the fuzz seeds (run by the fuzz smoke job) and the manual
  QR measurement.
- **Scenario skips:** the two suites skipped in the main step,
  `fat_exfat_images` and `ownership_ignored_mounts_are_refused`, run in the
  dedicated image step (below).
- **Native-name coverage** (Linux and Windows): 1 unit test and 1 scenario
  suite each, no skips. **Benches** (`--benches`, a rerun): Linux 196,
  macOS 196, Windows 190 passed.
- **Other jobs:** rustfmt; cargo-deny 0.20.2 (advisories, bans, licenses,
  sources pass for the product and the fuzz workspace; the binary's SHA-256
  checked; two `duplicate` warnings, as at `b6baa13`); Unicode table
  regeneration (no diff); `swtpm` smoke test (0.7.3); release build checks
  (F85: the `fault-injection` release build refused by its
  `compile_error!`, the release build succeeds, no failpoint name in the
  artifacts); fuzz smoke (seed test, then 60 s per target for all five
  targets, no crash).

**Dedicated image results (run 38157453235, `PVAULT_TEST_REQUIRE_IMAGES`).**

| Platform | Images | Result |
| --- | --- | --- |
| Linux | Loopback `vfat`, `exfat` (kernel) and exFAT through FUSE (`fuseblk`) | `fat_exfat_images` passed: export and paper and digital card folders refused (exit 6) on each; the `fuseblk` vault refused (no stable file identity). `ownership_ignored_mounts_are_refused` skipped (macOS only) |
| macOS | `hdiutil` FAT32, exFAT; APFS with ownership ignored and enforced | Both suites passed; `fat_exfat_images` with its `fuseblk` part skipped (Linux only) |
| Windows | `diskpart` VHDX, FAT32 and exFAT | `fat_exfat_images` passed (vault refused, no stable file identity; export and card folders refused, exit 6), its `fuseblk` part skipped (Linux only); the ownership suite skipped (macOS only) |

**Not covered by this run:** real TPM hardware (bound mode is tested only on
`swtpm`; real-hardware validation stays required before any bound-mode
release); bound mode outside Linux (refused there by design); the Milestone
4 manual gates; native Linux on ARM (the arm64 runs were local, in a
container). The recorded limitations stay open: E1 (its test passed
natively here, which does not show that it cannot recur under load), V3's
unknown original cause, the runner's single process-start window (V2), the
accepted `tpm2-tss` memory limitation (15), and the open licensing questions
in `THIRD_PARTY_NOTICES.md`.

**Code (by area):**

| Area | Where |
| --- | --- |
| TPM layer: public area, policy, Names, session table, C1 to C4, H-2 template bytes, `Tpm` trait, handle allocation | `crates/pvault-core/src/tpm/mod.rs` |
| `tss-esapi` backend (Linux, feature `tpm`): salted sessions with pvault's per-command attributes, sessions flushed once, empty password session for the salting key and the H-2 EK, error classification by TSS layer | `tpm/esapi.rs` |
| Bound keys, bound duress tag (with EK digest), 5.2 unlock path with the 9.2a checks, 9.2b removal, bound rehearsal (S1 + S3), owner authorization | `vault/bound.rs` |
| Bound `init` (TPM preflight, write-ahead index journal, define/write/confirm, rollback with 9.2b removal, one bound card, duress step), bound resume (Path A; journaled index resolved on the same TPM), R5 for the bound card | `vault/init.rs` |
| `duress set`, `duress disable`, N3 notice; `transact` reused for the slots change | `vault/duress.rs`, `vault/edit.rs` |
| `unlock_with` (bound), `status` TPM lines and inactive duress | `vault/mod.rs`, `vault/status.rs` |
| CLI: `--mode bound`, `--card-dir`, `--card-png`, global `--tpm` and `--tpm-owner-auth`, `duress set`/`disable`, exit codes; TPM stack logging off | `crates/pvault-cli/src/lib.rs`, `platform/mod.rs` |
| Dependency, license exception, notices, CI | `Cargo.toml`, `crates/pvault-core/Cargo.toml` (feature `tpm`), `deny.toml`, `THIRD_PARTY_NOTICES.md`, `fuzz/Cargo.toml` (no default features), `.github/workflows/ci.yml` |

**Acceptance tests (spec 13 row 5, as amended):**

| Test | Where (emulator unless noted) |
| --- | --- |
| F1, F3 | `vault::tests::bound::bound_vault_needs_its_index`; F1 also through the CLI (`bound_vault_through_the_cli`) |
| F2 | `bound::wrong_passphrase_and_lockout`, `tpm::…::wrong_auth_counts_and_locks_out`; CLI (standard error exactly `Unlock failed.`) |
| F17 | `bound::digital_bound_card_and_check` (a bound card for a portable check: `WrongMode`); `bound_header_is_refused_before_the_passphrase` (all platforms) |
| F19 | `bound::wrong_passphrase_and_lockout` (lockout before any passphrase) |
| F30 | `bound::bound_init_unlock_and_everyday_commands`, `tpm::…::define_write_read_undefine`, `names_equal_the_emulator_observation` (all platforms) |
| F52 | `bound::decoy_public_areas` (another size; NO_DA set): generic failure, DA counter unchanged |
| F59 | `bound::interrupted_after_the_header` (in process, with the duress passphrase); CLI crash at `init.committed` (`bound_crash_at_each_step`) |
| F60 | `bound::interrupted_before_the_header` (with and without the passphrase); CLI crashes at 7 pre-commit steps |
| F61, F65 (bound cards) | `bound::digital_bound_card_and_check`; bound card format 1 vector (`independent_card_file_vector`, all platforms); existing card tests |
| F81 | `bound::duress_availability`, `bound::bound_duress_set_and_disable`, `interrupted_after_the_header` (a configured duress passphrase changes nothing) |
| F87 | `bound::raced_handle_starts_over`, `tpm::…::raced_handle_is_reported_and_untouched` |
| F88 (`init`) | `bound::unknown_define_outcome_is_resolved_by_the_resume` |
| F91 | `bound::unmeasurable_identity_refuses_bound_init` |
| F103 | `tpm::…::parameter_encryption_on_the_wire`: recorded transport, `tpm_auth`, S2 data and owner authorization absent; negative case (encryption off in a test build) shows `tpm_auth` and the data. Emulator only; not a claim about every active transport attacker |
| D5 to D7 (both modes) | `portable_duress_set_and_disable`, `n3_notice_is_conditional` (all platforms), `bound::bound_duress_set_and_disable` |
| D9 | `bound::owner_authorization`; CLI `--tpm-owner-auth` line and refusal (exit 4) |
| TPM-library logging off (15) | `tpm_library_logging_is_off_from_the_start` (CLI on `swtpm`, `TSS2_LOG=all+TRACE` and `TSS2_LOGFILE` set) |

The emulator tests named above (`tpm::…` emulator tests and `bound::…`), like
every other test that starts a process, run one at a time in a test process
of their own (`test_process`; V2 below).

**Coverage audit (2026-10-07).** Every test named above exists and is
registered. Checked against the F-row texts:

- Closed during the audit: F81 asked for `status` to show "unavailable"; with
  duress off it only showed `off`. `status` now reads `off (unavailable on
  this TPM: <reasons>)` for a bound vault (D4), tested for owner
  authorization set and lockout. F52 now also has a decoy that differs only
  in `authPolicy` (so in its Name).
- Partially covered, open:
  - F17: a portable card offered during bound delivery is refused by the
    card comparison but has no dedicated test (recovery-time card mode
    checks are Milestone 6).
  - F19: lockout is tested for unlock (before the passphrase), not for a new
    bound `init` (whose preflight refuses on `inLockout` by the same check).
  - F81: the storage hierarchy disabled is tested for `init` (refused) but
    not for `duress set`, which cannot be reached then (the unlock itself
    fails with the hierarchy disabled).
  - F103: "a session that cannot be salted or encrypted aborts the command"
    is guaranteed by construction (no fallback path; errors map to
    `TpmSession`) and exercised only through a transport loss
    (`response_codes_are_classified_by_layer`), not by a forced salting
    failure.

**Validation results (2026-10-11, after the V1 to V3 corrections and the
extended V2 isolation; the source committed as `dab6264`).** The runner's
printed summary and the CI step that checks it were added just before the
commit and were dry-run on Mac and Linux ARM only. Exit statuses are those
of the commands themselves (every verification script exits non-zero when
any step fails); summaries were checked against the logs, not filtered
output alone.
Container runs used a read-only source copy checked file by file against the
working tree, fresh build directories and new log names. Environments:

- **Mac:** macOS arm64, native; Rust 1.99 stable and 1.89 (MSRV).
- **Linux ARM:** an arm64 Docker container on the Mac (Ubuntu 24.04,
  `tpm2-tss` 4.0.1, `swtpm` 0.7.3); no real TPM.
- **Linux x86_64 (emulated):** an amd64 container under emulation on the
  same Mac; `swtpm` runs with its seccomp filter off (a wrapper in that
  container only, because the emulator rejects the filter). This is **not**
  native CI; the native results are above (run 38157453235).

Distinct tests, one complete run each:

| Check | Mac | Linux ARM | Linux x86_64 (emulated) |
| --- | --- | --- | --- |
| `cargo fmt --check` (workspace, fuzz) | exit 0, 0 | | |
| `clippy --all-targets -D warnings` | exit 0 | exit 0 (fresh directory) | exit 0 (fresh directory) |
| Windows cross clippy (`x86_64-pc-windows-msvc`) | lib/bin exit 0; all targets exit 0 (benches removed: `criterion` does not cross-build) | | |
| `cargo test --workspace`, stable | exit 0: 235 passed, 0 failed, 19 ignored, the 13 isolated tests among them, all passed in their own process; scenarios 14 passed, 2 skipped | exit 0: 235 passed, 0 failed, 39 ignored, the 33 isolated tests among them, all passed in their own process; scenarios 17 passed, 2 skipped | exit 0: same counts as ARM |
| `cargo test --workspace`, 1.89 | exit 0 (same counts) | exit 0 (same counts) | exit 0 (same counts as ARM; an earlier 1.89 run hit E1 below) |
| Release and test-hook exclusion (Linux TPM build) | | exit 0, `RESULT 0` | exit 0, `RESULT 0` |
| rustdoc `-D warnings` | exit 0 | exit 0 (with the TPM modules) | |
| cargo-deny (product, fuzz) | exit 0 both (two `duplicate` warnings, the same as at `b6baa13`) | | |
| Fuzz | targets build (exit 0); smoke on 2026-10-07: seeds and each of the 5 targets 60 s, exit 0, no artifacts (no parser changed since) | | |

Reruns under parallel execution (the same tests again, not new tests;
bounded):

| Rerun | Linux ARM | Linux x86_64 (emulated) |
| --- | --- | --- |
| Full lib suite, after the extended V2 isolation | 10 of 10 passed | 6 of 6 passed |
| Full lib suite, after the first V2 correction only | 6 of 6; with the lock probe 6 of 8 (V2 residual) | 3 of 4 (V2 residual); with the lock probe 6 of 6 |
| Affected tests together (before the extended isolation; 18 tests) | 10 of 10 passed | 6 of 6 passed |
| Scenario suite | 3 of 3 passed | 2 of 2 passed |
| Negative controls, one fault each | V1, V3, logging and emulator isolation: 6 of 6 as intended | runner: 4 of 4 as intended (Mac) |

Mac has no emulator tests and no TPM scenarios (bound mode is Linux only).
The skips are the existing platform skips (`ownership_ignored_mounts_are_refused`,
`fat_exfat_images`). The release check builds `--release --workspace` with
TPM support (`tss-esapi` 7.7.0 in the graph; linked `libtss2-esys`, `-mu`,
`-sys`, `-tctildr`), then requires: the `fault-injection` release refused;
no failpoint name, `PVAULT_FAILPOINT`, `PVAULT_TEST_*` switch (including
`PVAULT_TEST_ISOLATED_PROCESS`) or test-hook or runner name as a string in
`pvault`; no test-hook code symbol (`hooks`, `weaken_for_test`,
`tpm::testing`, `test_process`, `failpoints`) in `pvault` or
`libpvault_core.rlib`. A run with a string known
to be present exited 1. (`weaken_for_test` and `Swtpm` occur as names in the
rlib's metadata: rustc records items removed by `cfg` for its diagnostics,
and `Swtpm` is the `TpmTarget::Swtpm` variant. Neither is code.) The CI
release job checks failpoint names only; the test-switch check is local.

**E1 (timing failure under concurrent emulated load; Milestone 2 test and
limit unchanged):** on emulated x86_64 with 1.89,
`adversarial_inputs_at_the_limit_finish_in_time` (estimator) measured one
estimate at 2.15 s against its 2 s limit while three platforms' suites ran on
the same Mac. Neither the test nor the estimator changed in Milestone 5, and
the limit is not relaxed. Focused verification with no competing workload
(2026-10-11, x86_64 emulated, 1.89, virtual machine load below 1): 20 of 20
runs passed, each whole test (9 estimates) in 1.41 to 1.49 s, so the failing
estimate ran more than 13 times slower than its idle average. Passing reruns
do not show that it cannot recur under load. Native CI (x86_64) has not run.

**Issues found during verification, and their corrections (2026-10-11).**
All three were test-side; no production behavior, lock, timeout or
assertion was weakened. Each correction has a negative control (a scratch
copy with one deliberate fault, built in its own directory) that fails in the
intended way.

- **V1 (test race, Milestone 2 code; corrected).**
  `platform::terminal::tests::echo_is_off_during_input_and_restored_after`
  failed 3 times on emulated x86_64 (never on Mac or ARM) with the terminal
  showing `"\r\nPassphrase: "`: the test typed as soon as echo was off, which
  happens before the prompt is written, so `ECHONL` (kept on by design) could
  echo the newline ahead of the prompt.
  - **Correction:** the test types only once `Passphrase: ` is visible on the
    terminal, as a person would, and asserts that echo is off at that moment.
    After the read it waits for the newline's echo before checking that the
    secret was not echoed (an echoed secret would arrive before that newline,
    so the check no longer depends on timing). The prompt, echo-off,
    not-echoed and restoration assertions are all kept.
  - **Negative controls:** with the prompt written 300 ms after echo goes off,
    the previous test body (as at `b6baa13`) fails (`shown.starts_with`),
    and the corrected test passes (3 of 3).
- **V2 (test-harness race; corrected by isolation of every process-starting
  test).** Lock tests saw a released lock as still held (`VaultInUse`; stale
  partials not stale). A stress test showed the mechanism: while one thread
  drops and retakes a lock, another thread's process start briefly
  duplicates the descriptor into the child until its `exec` (0 busy results
  in 36 million retakes without process starts; up to millions with them; on
  ARM the holders were caught as forked children not yet `exec`ed).
  - **First correction:** the 20 emulator tests (about 70 `swtpm` and
    `tpm2-tools` starts per run) moved to a test process of their own. The
    failure still occurred 3 times in 24 repeated full lib runs (x86_64
    emulated 1 of 10, ARM 2 of 14), all under heavy host load. The lock probe
    caught one on native arm64: `bound_header_is_refused_before_the_passphrase`
    got `VaultInUse` while a child forked by a store crash test
    (`store::tests::run_child`, Milestone 3 code; process name
    `store::tests::t…`, not yet `exec`ed) held that vault's `vault.gate` and
    `vault.lock`.
  - **Correction (approved 2026-10-11):** every test that starts a process
    from the shared lib test process on Unix is ignored there and run by one
    runner, `test_process::tests_that_start_processes_run_in_their_own_process`,
    in one child test process with one test thread: the 20 emulator tests,
    the 4 signal-restoration tests, the lock-holder test
    (`concurrent_processes_and_crash_release`), the 6 store crash tests, the
    `mkfifo` test (`source_kinds_are_refused`), and the completeness check
    below (33 on Linux with TPM support, 13 on macOS). Every assertion and
    all production behavior are unchanged; only where these tests run
    changed. The runner is the only process start left in the shared process
    (one per run; see "Remaining window").
    - **Every expected test ran and passed:** the runner names each test
      exactly (`--ignored --exact`) and requires a successful exit,
      `running N tests` with N the expected count, and `test <name> ... ok`
      for each name; otherwise it fails with the child's whole output (child
      failures propagate).
    - **Complete:** `test_process::the_isolated_set_is_complete` (run in the
      isolated process) lists every ignored test and fails on one that is
      neither run by the runner nor a known helper or probe
      (`lock_holder_child`, `signal_helper_reads_from_pty`, `crash_child`,
      `qr_reliability_measurement`, `fuzz_seeds`, the Windows drive-mapping
      probe), and on an expected name that is not an ignored test.
    - **No recursion:** the runner refuses to run when
      `PVAULT_TEST_ISOLATED_PROCESS` is set, and the child selects only
      ignored tests by exact name, so it cannot select the runner.
    - **Guarded:** each helper that starts a process (`Swtpm::start`,
      `run_child`, `holder`, `signal_restores`, the `mkfifo` call) refuses to
      run outside the isolated process.
    - **CI coverage:** `cargo test --workspace` (every OS, stable and 1.89)
      runs the runner, so the moved tests keep running in CI; no CI step
      selects them by exact name. Windows' own process starts (`icacls`,
      `subst`, `net`) stay in place: Windows has no fork, and files are
      opened as non-inheritable handles.
    - **Not affected:** the other test binaries (no vault locks) and the
      scenario harness (its children take the locks, not the harness).
  - **Negative controls:** a deliberate failure in one isolated test fails the
    runner ("the isolated tests failed", with the child's message); an
    unlisted ignored test fails the completeness check; the runner refuses
    to run inside the isolated process; an isolated test run in the shared
    process is refused by its helper.
  - **Result:** after this correction, 16 of 16 repeated full lib runs passed
    (ARM 10, x86_64 emulated 6), plus 6 complete workspace runs (stable and
    1.89 on Mac, ARM and x86_64). This is bounded evidence, not proof that
    the race cannot occur.
  - **Remaining window (open, not eliminated):** the runner itself starts its
    child once per run from the shared, parallel process. From the process
    start until the child's `exec` (Rust's `spawn` returns only after it),
    the child holds duplicates of every descriptor the shared process has
    open at that moment, other tests' vault locks included. A test in the
    shared process that releases a lock and takes it again inside that
    window can still see "vault in use". The window is one short interval
    per run instead of dozens (it is longer under emulation); it was not
    observed in the runs above. Closing it would need the runner outside the
    shared test binary or a test-only guard in the locking path; neither was
    done. Windows is not affected (no fork; non-inheritable handles).
  - **CI evidence:** the test job runs the runner again with `--nocapture`
    ("Isolated process tests ran") and requires its list of the tests that
    passed in their own process; on Linux the list must include the TPM
    emulator tests, which cannot skip there (`PVAULT_TEST_REQUIRE_SWTPM`).
- **V3 (cause still unknown; harness corrected).**
  `digital_card_check_after_commit` failed once on emulated x86_64 with 1.89
  (2026-10-07; no prompt for 180 s after the skipped `SET DURESS`). It has not
  recurred; the evidence of that run cannot tell a stall, an exit or a lost
  keystroke apart, so **the cause stays unknown**.
  - **Correction (inheritance):** both test pseudo-terminal helpers (scenario
    harness and terminal module) now open the terminal with close-on-exec set
    atomically (`/dev/ptmx` and the slave through `File`, which always sets
    `O_CLOEXEC`) instead of `openpty`, and assert it, so processes that other
    tests start (including long-lived `swtpm`) no longer inherit them.
  - **Correction (evidence):** every pty scenario waits through one helper,
    `pty::wait_for_prompt`. If the child ends or the time runs out, it records
    whether the child was still running and, on Linux, its scheduler state and
    wait channel; stops it and records the exit status; reads its standard
    error (at most 5 s); and includes the terminal transcript. The test
    passphrase is redacted from both.
  - **Negative control:** a prompt that never appears (8 s timeout) produced
    "still running after 8s; scheduler state S", exit status signal 9, the
    standard error and a transcript ending at the real `Type CHECK` prompt,
    with the passphrase absent. In this container the kernel hides the wait
    channel (it reads `0`); the scheduler state is still reported.

Earlier diagnostic copies and the stress test lived only in the containers'
work volumes and scratch folders; the repository is unchanged by them.

## 15. How `tpm2-tss` handles session secrets (report for a separate decision)

Required before Milestone 5 acceptance (amendment of 2026-10-06). Source read:
`tpm2-tss` 4.0.1, the release tarball
(`tpm2-tss-4.0.1.tar.gz`, SHA-256
`532a70133910b6bd842289915b3f9423c0205c0ea009d65294ca18a74087c950`), the
version Ubuntu 24.04 ships and pvault is built and tested against. This is a
source reading, not a memory measurement; nothing was run against a real TPM.

| Item | What the code does | Secret involved |
| --- | --- | --- |
| Authorization values (`Esys_TR_SetAuth`, `esys_tr.c`) | Copies the `TPM2B_AUTH` into the ESYS object (`esys_object->auth = *authValue`) and keeps it for the object's life; long values are replaced by their hash | `tpm_auth`, the owner authorization |
| Session keys (`esys_iutil.c`) | Session key and the auth value are concatenated into `sessionValue` (`memcpy`) inside the session object to key HMACs and parameter encryption | session key, `tpm_auth`, owner authorization |
| Releasing objects, sessions and the context (`SAFE_FREE`, `Esys_TR_Close`, `Esys_Finalize`) | `SAFE_FREE` is `free()` and a null assignment; no clearing anywhere in these paths | all of the above stay in freed heap memory |
| Command and response buffers (the SYS context, `Esys_Finalize`) | Parameters are marshalled into the command buffer and encrypted there; responses are decrypted (`iesys_decrypt_param`) through a stack array (`UINT8 plaintext[p2BSize]`) and the response buffer; neither is cleared; the context is freed without clearing | `x || S2_wrapped` of `NV_Read` |
| Returned structures (`Esys_Free`) | `free()` only; `tss-esapi` copies `NV_Read` data into its own buffer and then calls `Esys_Free` | `x || S2_wrapped` |
| Logging (`util/log.c`, `esys_iutil.c`) | Level from `TSS2_LOG`. At debug level it logs the session key (`LOGBLOB_DEBUG(…sessionKey…)`), each parameter before encryption ("param to encrypt") and the encrypted salt. At the default level it writes error and warning lines to standard error | session key, `tpm_auth`, `S2_wrapped` |

What pvault controls, as implemented:

- `tss-esapi` zeroizes its Rust-side copies of authorization values
  (`tr_set_auth` wipes its local buffer); pvault passes `tpm_auth` and the
  owner authorization only through zeroizing types and drops them early.
- **Logging is turned off in the CLI** (`platform::quiet_tpm_stack`, the
  first thing `main` does after the estimator-child branch, while the process
  has one thread): `TSS2_LOG=all+NONE` and `TSS2_LOGFILE` removed, overriding
  the environment; no switch turns it back on. This was also needed for spec
  5.6: without it a wrong passphrase on a bound vault printed the TPM stack's
  "authorization HMAC check failed" lines next to `Unlock failed.`.
  - Verified before the first TPM-library operation
    (`tpm_library_logging_is_off_from_the_start`, Linux, real CLI on `swtpm`):
    bound `init`, `status`, `list` and a wrong-passphrase `list` run with
    `TSS2_LOG=all+TRACE` and `TSS2_LOGFILE` naming a file. At trace level the
    library logs from its first call, so an operation before the override
    would leave output; no file appears and standard error has no TPM-stack
    line (the wrong passphrase gives exactly `Unlock failed.`). Negative
    control: with the override removed from a scratch copy, the same test
    fails because the library wrote the file.
  - **Scope of the guarantee:** the `pvault` CLI only. `pvault-core` does not
    call `quiet_tpm_stack` itself, because changing the environment is sound
    only while a process has one thread, which a library cannot know. A
    program that uses `pvault-core` directly gets the same protection only by
    calling it itself, before its first TPM operation and before starting any
    thread. The function is therefore `unsafe` with that requirement as its
    safety contract (it was a safe function before; only the CLI calls it).
    The library's own tests run without the override.

**Decision (author, 2026-10-11):**

1. **Residual secrets in freed C memory** (authorization values, session
   keys, `S2_wrapped`, decrypted response bytes, until reused or the process
   exits) are **accepted as a documented limitation for Milestone 5** (spec
   10 item 8; to be carried into `docs/FAILURE_MODES.md`, memory attacks).
   Exposure needs memory access to the process or a swap or crash image;
   crash images are already prevented (10.3), and memory locking (10.2)
   covers only pvault's own buffers. This **does not** establish complete
   secret-memory wiping and **does not** authorize a bound-mode release.
   Not pursued now: a short-lived TPM child process (b) or upstream clearing
   (c).
2. **Logging stays forced off, with no debug switch**, verified as above.

Real-hardware validation (required before release of bound mode; not
authorized now) does not change these findings: they are properties of the
software stack.
