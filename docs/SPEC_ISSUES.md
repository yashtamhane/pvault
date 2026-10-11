# Specification issues and decisions (Milestone 0.5)

This is the decision record for the Milestone 0.5 consistency pass.

- **Spec reviewed:** `PVAULT_BUILD_SPEC.md` version 6 (SHA-256
  `3832b3645ba360f61492ad54ca167767135d4a50889cde43b285fe1a111ab20e`).
- **Spec produced:** version 7, then 7.1 (documentation corrections; Section 7), then 7.2 (Milestone 1 approvals; Section 8), 7.3 (project license; SI-04) and 7.4 (Milestone 1 acceptance and Milestone 2 approvals; Section 10).
- **Milestone 0.5:** closed on 2026-10-04 under the 7.1 criterion, by the author's approval of the Section 8 decisions. Every PENDING item below stays pending and may not be implemented.
- **Evidence:** gathered on 2026-10-04 (Section 3).
- **Product code:** not changed.

**What closes Milestone 0.5 (spec 7.1, Section 13).** Three conditions:
1. Every issue below has a recorded status and the milestone it blocks.
2. The author has resolved every issue that blocks **Milestone 1**.
3. Every other issue stays PENDING and is resolved before the milestone it blocks starts.

Milestone 0.5 does not require every issue to be resolved.

## Status values

| Status | Meaning |
| --- | --- |
| **Accepted** | The author's direction is applied in spec v7. |
| **Accepted (modified)** | Applied in v7, but differs from the first proposal in this report. |
| **Pending (evidence)** | Evidence is collected below. The author must approve the proposal before it enters the spec. |
| **Pending (design)** | A design is proposed below for review. The spec marks the topic **PENDING** and nothing may be implemented. |
| **Open (author)** | The author's decision is still needed. |

Every item that the first revision of this report marked "Decision: No" was
re-evaluated rather than accepted automatically. The outcome is recorded per
issue.

---

## 1. Revised decision table

| ID | Topic | Status | Resolution (short) | Spec v7 | Tests | Blocks |
| --- | --- | --- | --- | --- | --- | --- |
| SI-01 | `libc` / `windows-sys` scope | Accepted | Narrow platform-FFI scope; isolated `platform` modules; reviewed SAFETY comments | 0 (rule 6), 7.6, 7.6a | all FFI tests | M1 |
| SI-02 | Test and bench placement | Accepted | `crates/pvault-tests` (unpublished) for cross-crate tests; benches in `pvault-core/benches` | 11, 12 | all F-tests | M1 |
| SI-03 | Windows core dumps | Accepted | Best effort on Windows, no registry changes; Linux debugger impact documented | 10.3, 14 | core-dump tests | M7 (docs) |
| SI-04 | License and notices | Accepted (license, wordlist) + Pending (release notices) | **`GPL-3.0-only`**, Copyright 2026 Yash Sandeep Tamhane; official GPL v3 text in `LICENSE`; `COPYRIGHT` notice; manifests set `license = "GPL-3.0-only"`; dependency compatibility assessed; `cargo-deny` approved. **EFF wordlist: decided** (EFF's CC BY 4.0 grant, embedded unmodified, attribution; applied in M2). Still pending: `cargo-about` for release notices (M13) and the RFC/IETF-excerpt question | 14, 16 | `cargo-deny` licenses; wordlist SHA-256 test | M13 |
| SI-05 | MSRV and toolchain pinning | Accepted | `rust-version = 1.89`; native 1.89 build-and-test CI jobs on 3 OSes gate each milestone; release toolchain pinned by M13 | 12, 13 | MSRV CI jobs | M1 |
| SI-06 | Section 16 decisions | Open (author) | Name and passphrase lengths decided; **PCR P1 decided** (nonce-policy only in v1; PCR requires a future reviewed format revision); wizard default remains open | 9.1, 16 | n/a | M14 (wizard only) |
| SI-07 | CBOR implementation | Accepted (option 2, M3) | Three options compared; secret and path handling designed (decode, storage, zeroization, errors) | 4.4, 7.6, 7.8, 10.1 | F14, F71, F73, fuzz | M3 |
| SI-08 | Shamir implementation | Accepted (option 1); implemented in M2 | `vsss-rs = "=6.0.1"` through its public polynomial API with pvault-owned, wiped storage; no allocation inside `vsss-rs`; independent vectors | 7.4, 7.6 | F5, F6, F62 | M2 |
| SI-09 | QR input | Accepted | `png` with bounded limits; SVG output; camera deferred | 7.4a, 7.4c, 7.6 | F47, F61 | M4 |
| SI-10 | Card files | Accepted (lifetime lock and cleaner approved for M4, A6) | Explicit destination, owner-only, recorded identity, identity-checked cleanup, remnants documented; active-operation lifetime lock and cleaner rules approved | 7.4b | F78 | M4 |
| SI-11 | Secure file creation | Accepted + Pending (design) | FFI primitives, refuse when unsupported (accepted); `--force` exchange design and its real guarantees (pending; refused until approved) | 7.6a, 7.9 | F50, F51, proposed F90 | M4 |
| SI-12 | Durability primitives | Accepted (M3; W1, N1) | Windows **W1 selected**: writable NTFS/ReFS under the explicit undocumented assumption, with no verified power-loss claim; remaining platform table still awaits approval | 4.3, 8.5 | F25, F26 (process crash only) | M3 |
| SI-13 | FAT/exFAT and crash safety | Accepted (modified) | Mutations refused outside an allowlist; read-only otherwise; no redundant headers | 1, 2, 8.5 | F74 | M3 |
| SI-14 | Lock protocol | Accepted (G + L, M3) + Pending (mount, upgrade: SI-45) | Gate lock + mount lock; no PID markers; no atomic conversion assumed | 4, 8.4 | F56a, F56b, F72 | M3 |
| SI-15 | Memory locking | Accepted (modified) | Best effort, visible, optional strict mode; Argon2 memory wiped, not locked | 10.2 | F77 | M3 / M7 |
| SI-16 | Argon2 memory limits | Accepted (modified; D8 definitions, M3) | Hard caps; total-RAM policy; available-memory resource check; specific messages; never lowered | 4.3, 5.8 | F13, F76 | M3 |
| SI-17 | Fuzz toolchain | Accepted | Nightly for `fuzz/` only; Linux CI smoke job | 12 | fuzz targets | M3 |
| SI-18 | TPM dependencies | Pending (design) | Exact pin and feature gating proposed | 7.6, 9.1 | M5 tests | M5 |
| SI-19 | Non-TTY secret input | Accepted (modified) | Explicit `--secrets-stdin`; never argv or environment | 10.6 | F79 | M4 |
| SI-20 | Deterministic CBOR | Accepted | 4.4 profile; units; fixed `s1_x`/`s2_x` | 4.1, 4.4 | F14 | M3 |
| SI-21 | KDF parameters | Accepted | Argon2id v0x13; HKDF-SHA-512, no salt, L = 32 | 5.1 | KDF vectors | M1 |
| SI-22 | TPM public area and sessions | Pending (design) | Exact public area; salted HMAC sessions with parameter encryption; fail closed | 9.1 | F30, F52 | M5 |
| SI-23 | Stream version and `rec_len` | Accepted | `version` in the AAD; exact `rec_len` | 7.7 | F11 | M3 |
| SI-24 | Dual-cipher claim | Accepted | Option (a): claim narrowed to the chunk layer; no cascaded wraps | 2 (A1) | docs | M1 |
| SI-25 | Structural corruption vs F8 | Accepted (modified) | F8 narrowed; limit documented; no embedded slots | 6.1, F8 | F8 | M3 |
| SI-26 | Duress-tag presence | Accepted (modified) | Optional tag kept; leak documented | 4.1, 9.6 | n/a | M3 |
| SI-27 | Passphrase normalization | Accepted | Space-separated words, hyphens kept, input-only hint | 7.3 | F75 | M2 |
| SI-28 | Generation semantics | Accepted | Transaction counter; Revoke excluded; `keytable_gen == generation` | 3, 7.8, 9.7 | F18, F58 | M3 |
| SI-29 | Header resilience | Pending (design) | Backups documented (accepted); S2 + S3 path proposed | 6.1, 14 | proposed F86 | M6 |
| SI-30 | Vault paths | Accepted (decode/input split, M3) | Unique normalized paths; directory entries; `--replace` | 7.8 | F64, F73 | M3 (decode rules) / M4 (input rules, case folding) |
| SI-31 | `convert` | Accepted | Protocol drafted (6.9); confirm before M6 | 6.9 | F32, F68, F82 | M6 |
| SI-32 | Duress setup | Accepted | Protocol drafted (6.10); confirm before M5 | 6.10 | F46, F57, F59, F81 | M5 |
| SI-33 | Duress scope and ordering | Accepted | Command table; duress check before the journal check | 5.7 | F63 | M4 |
| SI-34 | Portable single-card check | Accepted (modified) | Two-card verification kept and documented; no commitments | 7.4a | F63 | — |
| SI-35 | Recovery details, handles, overflow | Accepted (core digests, tracking, cleanup list, M3) + Pending (handle allocation, overflow: M5) | Allocation/collision protocol; explicit old/new/tracking core digests; authenticated 32-entry cleanup tracking; overflow refusal | 3, 6.3, 8.1 | proposed F87, F88 | M3 / M5 |
| SI-36 | Cross-machine and TPM-less recovery | Accepted (tokens, H-2 template, duress formula, M3; TPM runtime M5) | Portable recovery and same-TPM rule applied; replace non-rekeyable identity MACs with exact encrypted, scoped TPM-identity tokens; PCR P1 selected | 6.5, 6.8, 8.1, 9.1, 9.2b, 9.6 | F25, F80, F83 | M3 (format) / M6 |
| SI-37 | Object keys not rotated | Accepted (modified) | Documented; `--rekey-files` deferred | 6.11 | n/a | — |
| SI-38 | Safe `init` | Accepted (M3; `init` built in M4) | Four authenticated phases; file-identity ownership; exact confirmation/block rules for unowned residue | 8.1, 8.3 | F26, F59, F60, F69 | M3 / M4 |
| SI-39 | Journal schemas | Accepted | Exact schemas in 8.1; Revoke/Erase at M8 | 8.1 | F27, F71 | M3 |
| SI-40 | Leftover files | Accepted (transition artifacts, M3; live-vault add/rm, A3/A4, M4) + Pending (fsck rules: M6) | Authenticated-ownership rules; add/rm reordering | 4, 8.2, 8.3 | F25, F26, proposed F89 | M3 |
| SI-41 | Message table | Accepted (modified) | Table in 5.8; parse failures stay generic | 5.6, 5.8 | F7, F13, F14 | M3 |
| SI-42 | Owner authorization and duress | Accepted + Pending (design) | `tpm-harden` removed; availability rule; checks C1 to C3 prepared, plus C4 if the SI-36 encrypted identity token is adopted | 9.3 | F75, F81 | M5 |
| SI-43 | Erase confirmation | Accepted (modified) | Basename + vault-ID prefix; no unrelated deletion | 9.5 | F84 | M9 |
| SI-44 | K2 | Pending (design) | Constraints applied; details at the M8 review | 9.10 | F43, F49 | M8 |
| SI-45 | Mount | Pending (design) | Write model proposed; crates and CI to review | 13 (M11) | F56b | M11 |
| SI-46 | Card milestone | Accepted | Cards move to M4 | 7.4a, 13 | F61, F65 | M4 |
| SI-47 | CLI document | Accepted | `docs/CLI.md` drafted and approved before M4 | 14 | n/a | M4 |
| SI-48 | Failpoints | Accepted | Test-only feature; excluded from release builds | 11 | F85 | M3 |
| SI-49 | Guarantee table | Accepted | Two rows added; crash-safety statement added | 2 | docs | M7 |
| SI-50 | Minor items | Accepted | Itemized below | various | F17, F70 | as noted |
| SI-51 | Passphrase options | Accepted (final design and schemas, M3) | Main: generated (10–16, default 12) or custom (NFC-only, refuse and warn lists, `zxcvbn` 3.1.1 at creation only, in a child process, "Estimated" provisional bands, fail closed on creation). Duress: generated only, fixed at 12 words. Bounded terminal input replaces `rpassword` (7.6a extended). Unlock: 1 Argon2id run, or 2 for a custom main with duress (1 when generated-word handling refuses the input, N3); verification-only skips the duress-only run. Header and journal schemas pending | 2, 4.1, 5, 6, 7.3, 7.6, 7.6a, 8.1, 9.6, 10, 16 | F75, new | M2 (done) / M3 |
| SI-52 | Paper or digital recovery cards | Accepted in direction (revision 4, 2026-10-06); implemented in M4, not yet accepted; R5 after the commit, Q2 superseded | Explicit `--cards paper` or `--cards digital`; digital card files are the deliverable (same cryptography and files); strict per-file reader for card-file format 1 with a byte-exact vector; separate pair validation; no card-file unlock for everyday commands (L1 revised: `list`, `get`, `add`, `rm` keep the passphrase; passphrase-free access only through M6 `recover`); recovery rehearsal from the delivered cards against the candidate header (both modes); no automatic deletion of digital cards after a restart, owner-directed `discard-card` with unverified, labeled metadata comparison and the stronger confirmation always; `cards.cbor` v2; init journal unchanged (Q2 superseded: not needed without deletion after a restart; schema and published vectors of M3 kept); R5 optional card check after the commit, handles released first, never rolls back or deletes; `docs/RECOVERY_DELIVERY_PROPOSAL.md` | 5.7, 7.4a, 7.4b, 7.4d | F93 to F102 | M4 |

---

## 2. Per-issue records

### SI-01 Platform FFI crates — Accepted

- **Resolution:**
  - `libc` (Unix) and `windows-sys` (Windows) are approved only for:
    - process hardening;
    - file-system operations (handle-relative open, create and rename; no-follow flags; identity; permissions and ACLs; flush; file-system type);
    - memory queries and locking;
    - file locking.
  - All calls live in isolated `platform` modules, with reviewed `// SAFETY:` comments.
  - Rule 6 is amended.
  - Unsupported operations are refused; there are no weakening fallbacks (7.6a).
- **Remaining uncertainty:**
  - The Milestone 0 core-dump code still lives in `secrets.rs`. Moving it into `platform/` is a code change for Milestone 1 and was not done here.
  - Some Windows primitives (owner-only ACLs, handle-relative rename) need `windows-sys` features that are not enabled yet.
- **Affected:** Milestones 1, 3, 4 and 7; F50, F51, F74, F77, F78.

### SI-02 Test and bench placement — Accepted

- **Resolution:**
  - `crates/pvault-tests` (`publish = false`) owns `tests/failure_scenarios.rs` through `[[test]] path` entries.
  - Criterion benches go in `crates/pvault-core/benches/`.
  - `fuzz/` sits outside the workspace (SI-17).
- **Remaining uncertainty:**
  - `criterion` 0.8 depends on `alloca`, which builds C code. Benches therefore need a C toolchain, which the CI runners have.
  - Cross-compiling benches from macOS fails without a cross C compiler (Section 3.1). Benches are not cross-compiled.
- **Affected:** Milestone 1 benches; every F-test.

### SI-03 Windows core dumps — Accepted

- **Resolution:**
  - Windows protection is documented as best effort (`SetErrorMode`, and `WerSetFlags` with no heap).
  - The Linux `PR_SET_DUMPABLE` debugger impact is documented.
  - No persistent registry or policy changes.
  - Optional `LocalDumps` detection may warn, but must not imply complete prevention.
  - `status` reports the protection level.
- **Remaining uncertainty:** whether to implement `LocalDumps` detection at all. Optional, and not blocking.
- **Affected:** Milestone 7 docs; `status` output.

### SI-04 License and notices — Accepted (license); release notices pending

**Decision (author, 2026-10-04):** pvault is licensed under the **GNU General Public License, version 3 only** (`GPL-3.0-only`), with **Copyright 2026 Yash Sandeep Tamhane**.

**Applied:**
- **`LICENSE`:** the official GPL v3 text, unmodified (35,149 bytes, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`).
  - Provenance: gnu.org was unreachable from the development machine over TLS (handshake failures through both curl and Python). The text was taken from two independent copies that are byte-identical: `COPYING` in the official GNU Hello 2.12.1 release tarball (`mirrors.kernel.org/gnu/hello/`), and GitHub's license API (`gpl-3.0`).
  - Its SHA-256 is the widely published hash of `https://www.gnu.org/licenses/gpl-3.0.txt`. The GNU release tarball's GPG signature was not checked.
- **`COPYRIGHT`:** the copyright line plus the GPL's "how to apply" notice, adapted for version 3 *only* (no "or any later version").
- **Manifests:** `[workspace.package] license = "GPL-3.0-only"`, inherited by `pvault-core` and `pvault-cli`.
- **README:** a License section.
- **`THIRD_PARTY_NOTICES.md`:** now states the project license and that third-party material keeps its own license.
- **`deny.toml`:**
  - pvault's crates are checked (`[licenses.private] ignore = false`) through per-crate exceptions for `GPL-3.0-only`.
  - The dependency allowlist is unchanged, so a GPL-licensed dependency would still need its own review.
  - A probe without the exceptions fails on exactly `pvault-cli` and `pvault-core`, which shows they are evaluated.

**Dependency compatibility with GPL-3.0-only:**

| Licenses | Where | Assessment |
| --- | --- | --- |
| `MIT OR Apache-2.0` / `Apache-2.0 OR MIT` (47 crates), `MIT` (`strsim`) | Linked into the binaries | Compatible. MIT (Expat) is GPL-compatible. Apache-2.0 is compatible with GPLv3 (though not with GPLv2), so either option works |
| `BSD-3-Clause` (`subtle`) | Linked | Compatible (Modified BSD) |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (`r-efi`) | UEFI targets only, via `getrandom`; not built for pvault's targets | Compatible through the MIT or Apache-2.0 option. **Resolves M1-F4** |
| `(MIT OR Apache-2.0) AND Unicode-3.0` (`unicode-ident`) | Build time only, inside proc-macro crates (`clap_derive`, `thiserror-impl`); not linked into the binaries (`cargo tree -e normal,no-proc-macro`) | Compatible. The FSF list names the earlier Unicode data-files licenses as GPL-compatible, and Unicode-3.0 carries the same permissive terms. Not shipped in any case |
| Dev and benchmark only: `MIT OR Apache-2.0`, `Unlicense OR MIT`, `BSD-2-Clause OR Apache-2.0 OR MIT`, `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`, `Apache-2.0` (`ciborium`) | Tests and benches only; never shipped | Compatible through the MIT or Apache-2.0 options |
| Wycheproof test vectors (Apache-2.0) | Repository test data only | Compatible. The Apache-2.0 text is kept in `third_party/wycheproof/LICENSE`, and changes are stated in each file |

Basis: the FSF's published license list (<https://www.gnu.org/licenses/license-list.html>). It could not be re-fetched from the development machine, which is why the table states assessments rather than quotations.

**Obligations to carry forward:**
- Binary releases must ship the GPL text, provide the Corresponding Source, and include the notices of every statically linked dependency (MIT, Apache-2.0 and BSD-3-Clause notices). That last part is why `cargo-about` (or an equivalent) is still proposed for Milestone 13.
- `cargo-deny` keeps checking new dependencies against the allowlist.

**Still open:**
1. **RFC test-vector excerpts (M1-F5):** whether the IETF Trust's license covers them. The license choice does not settle this.
2. **EFF large wordlist: decided 2026-10-04 and applied in Milestone 2** (see "Applied in Milestone 2" below).

   *Primary-source findings:*
   - **The file:** `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`, 108,800 bytes, `Last-Modified: Mon, 18 Jul 2016`, SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`. It carries **no license notice of its own**.
   - **The pages:** neither the announcement (`/deeplinks/2016/07/new-wordlists-random-passphrases`) nor `/dice` states a separate license for the lists. Both carry only the site footer "Copyright (CC BY)", which links to `https://www.eff.org/copyright`.
   - **EFF's current copyright policy:** "Any and all original material on the EFF website may be freely distributed at will under the **Creative Commons Attribution 4.0 International License (CC-BY)**, unless otherwise noted." No other note applies to the wordlist. The list is EFF's original selection (Joseph Bonneau, EFF, 2016).
   - **Where "CC BY 3.0 US" came from:** probably EFF's 2016-era site license. The Internet Archive snapshot of `eff.org/copyright` from 2016-07-28 exists, but could not be retrieved (HTTP 429 rate limiting, after retries). This history is **unverified**.
   - **Conclusion:** the exact license currently on offer from EFF for this file is **CC BY 4.0 International**. If the 2016 grant was CC BY 3.0 US, that grant also remains valid (CC grants are irrevocable). The recipient may rely on the 4.0 grant.

   *Compatibility with a `GPL-3.0-only` program:*
   - **Creative Commons' own FAQ** says CC licenses "are currently not compatible with the major software licenses" in general. It names **CC BY-SA 4.0** as one-way compatible with GPLv3, and **CC0** as GPL-compatible. It makes **no statement** about CC BY 4.0 or CC BY 3.0 with the GPL.
   - **The FSF license list** (from recollection; gnu.org was unreachable from the development machine, so this is unverified): it lists **CC BY 4.0** as compatible with GPLv3. No equivalent statement for CC BY 3.0 US is known.
   - **The relevant terms do not conflict.** The binding conditions of CC BY 4.0 are attribution (3(a)) and no additional restrictions or technical measures on the Licensed Material (2(a)(5)(B)). GPLv3 section 7(b) expressly allows "preservation of specified reasonable legal notices or author attributions" as an additional term. The GPL imposes no restriction that stops recipients from exercising the CC BY rights in the wordlist.
   - **What this does and does not establish:** the gap is the lack of an explicit, verifiable compatibility statement. It is **not** proven incompatibility. No primary source found states that CC BY (3.0 or 4.0) material cannot be embedded in a GPLv3 program.

   **Decision (author, 2026-10-04):** use EFF's current **CC BY 4.0** grant. Preserve the original asset, unmodified, and the required attribution. Document the licensing basis and the remaining uncertainty.

   *How it will be applied in Milestone 2:*
   - `assets/eff_large_wordlist.txt`, byte-identical to EFF's file (SHA-256 above, checked by a test).
   - A `THIRD_PARTY_NOTICES.md` entry giving: title, "EFF's Long Wordlist"; author, Electronic Frontier Foundation; source URL; license, CC BY 4.0 International with a link; no changes made; and the basis (EFF's copyright policy as of 2026-10-04).
   - The remaining uncertainty is stated: no verified FSF or CC statement on CC BY with GPLv3, and the 2016 policy history is unverified.

   *Recommended resolution (as adopted):*
   - Embed the file **unmodified** (dice numbers included), as **separately licensed data under CC BY 4.0**, relying on EFF's current grant. It is not relicensed.
   - Give TASL attribution: title "EFF's Long Wordlist" (`eff_large_wordlist.txt`); author Electronic Frontier Foundation; source URL; license CC BY 4.0 with a link; "no changes made".
   - Put that attribution in `THIRD_PARTY_NOTICES.md`, in `assets/README`, and in the notices shipped with binaries (Milestone 13).
   - Record the SHA-256 and verify it in a test.
   - Do not strip the dice numbers, because that would be an adaptation.

   *Alternatives, if the author prefers not to rely on the CC BY 4.0 grant:*
   - (a) ship the wordlist as a separate file next to the binary (an aggregate under GPLv3 section 5), with its SHA-256 checked at run time;
   - (b) ask EFF for an explicit statement or permission;
   - (c) use a list under CC0 or a GPL-compatible software license (a spec change, since 7.6 names the EFF list).
   *Applied in Milestone 2:*
   - `assets/eff_large_wordlist.txt` is byte-identical to EFF's file (SHA-256 `addd3553…903e`). The test `wordlist_is_the_unmodified_eff_file` checks the hash, the 7,776 unique words, the dice numbers and the four hyphenated words.
   - `THIRD_PARTY_NOTICES.md` and `assets/README.md` carry the TASL attribution, the licensing basis and the remaining uncertainty.
   - The binary embeds the file unchanged (`include_str!`); the dice numbers are skipped when the list is parsed in memory, which is use, not an adaptation of the distributed file.
3. **Notices tooling for release artifacts** (`cargo-about`, or a manual process), at Milestone 13.

**Affected:** Milestone 2 (wordlist, done), Milestone 13 (release notices); `Cargo.toml`, `LICENSE`, `COPYRIGHT`, `README.md`, `deny.toml`, `THIRD_PARTY_NOTICES.md`.

### SI-05 MSRV 1.89 — Pending (evidence)

- **Evidence (Section 3.1):**
  - The current locked graph builds and passes all 19 tests on Rust 1.89.0 (macOS), and cross-checks cleanly for Windows and Linux.
  - Every approved crate planned so far resolves and builds on 1.89 with the MSRV-aware resolver. The versions selected are listed in Section 3.1.
  - The only cross-target failure was the C build step of `criterion`'s `alloca` dependency. It is a toolchain issue, not a Rust-version issue.
  - `std::fs::File::lock` and its variants are documented as stable since 1.89.0.
- **Not yet verified:**
  - `tss-esapi` needs `tpm2-tss` (Linux only).
  - `fuser`, Tauri, the WinFsp bindings and the PQC crates are unchosen.
  - Tests have not run natively on Linux or Windows under 1.89. A CI job is needed for that.
- **Proposal:**
  - Declare `rust-version = "1.89"` only once a CI job runs `cargo +1.89 test --workspace --locked` on all three operating systems, and passes.
  - Pin the release toolchain with `rust-toolchain.toml`, using an exact version, by Milestone 13.
  - Development may keep floating stable, alongside the 1.89 job.
- **Approval needed:** MSRV 1.89, the CI job, and when to pin.
- **Affected:** CI from Milestone 1.

### SI-06 Section 16 decisions — Open (author)

- **Decided:** keep the name `pvault`.
- **Decided through SI-51 (2026-10-04):** generated main passphrases are 10–16 words, default 12; duress passphrases are fixed at 12 words for now.
- **Decided (P1, 2026-10-05):** v1 is nonce-policy only. PCR binding
  changes the NV policy, expected Names, cleanup reconstruction,
  TPM-identity-token AAD and duress tag, so it requires a future reviewed
  format revision. It is not a Milestone 5 runtime-only addition to v1.
- **Recommendations awaiting confirmation:**
  - **Wizard default:** bound on Linux, when a usable TPM 2.0 is present and bound duress or indices can work. Portable on platforms without bound support.
- **Affected:** the wizard default (Milestone 14) remains the only open SI-06
  author choice. The P1 format selection affects Milestones 3 and 5.

### SI-07 CBOR implementation — Pending (evidence)

**Scope correction.**
- The only CBOR that carries plaintext secrets is the decrypted **key table** (file keys, and paths, which are sensitive).
- The header holds only wrapped values, nonces and tags.
- The journal and the per-user records hold no secrets.
- The card payload is a fixed binary layout, not CBOR. The previous revision of this report wrongly listed a "card payload envelope".

**Evidence (`ciborium` 0.2.2, `ciborium-ll` 0.2.2; Section 3.2):**

| Behavior | Finding |
| --- | --- |
| Canonical / deterministic mode | None. The encoder always writes shortest-form heads, but the decoder accepts non-shortest heads and indefinite lengths. |
| Tags | Silently skipped: `Header::Tag(..) => continue`. |
| `deserialize_bytes` | Reads into the **caller-supplied scratch buffer**, only if the length fits, then calls `visit_bytes(&scratch[..len])`. Otherwise it errors; there is no allocation. |
| `deserialize_byte_buf`, `deserialize_string` | Grow a fresh `Vec` / `String` segment by segment. Each reallocation leaves an **unwiped copy**. |
| `from_reader` | Uses a stack `[0; 4096]` scratch that is never wiped. `from_reader_with_buffer` accepts a caller-owned scratch. |
| Encoder `serialize_bytes` | Writes the head, then `write_all(bytes)` straight to the writer. No intermediate copy. |
| Error text | `Unexpected::Bytes` prints only "byte array". `Unexpected::Str` prints the **string content**, so paths could appear in error text. |

**Options compared:**

1. **`ciborium` with caller-owned zeroizing scratch, plus strict validation.**
   - **Decoding:** secret fields go only through a custom visitor via `deserialize_bytes`, copying straight into `SecretBytes`. The scratch is a locked, zeroize-on-drop buffer we own. Input comes from the locked plaintext buffer as `&[u8]`.
   - **Forbidden in key-table types:** `Vec<u8>`, `ByteBuf`, `String`, `Value` and `deserialize_byte_buf`.
   - **Strictness:** re-encode the decoded value into a **comparing sink** (a `Write` that compares against the input instead of storing it). This rejects any non-deterministic input without a second plaintext copy. Plus `deny_unknown_fields`, serde's duplicate-field errors, explicit length checks and a low recursion limit.
   - **Secret copies on decode:** the input buffer (ours), the scratch (ours, wiped), the destination secret, and unavoidable register/stack temporaries.
   - **Failure paths:** the scratch guard wipes on error and on unwind. Errors are mapped to a generic message, so path text never reaches output.
   - **Risk:** relies on `ciborium` internals staying as observed. Mitigations: an exact version pin, plus tests with an allocation-counting allocator showing that no allocation happens while secret fields decode.
2. **Bounded fixed-schema codec, in-house.**
   - A decoder and encoder for the 4.4 profile only, roughly 400 to 600 lines. It returns borrowed slices and is deterministic by construction, with no serde.
   - Secret handling is fully controlled.
   - It is more code to fuzz and review. It is serialization, not cryptography, so rule 3 does not forbid it.
3. **Full general-purpose parser.** Not proposed.

**Vault-path handling (applies to option 1 and option 2; added in 7.1).** Vault paths are **confidential metadata**, not key material. They are zeroized, but are not placed in locked memory: the locking budget is reserved for keys, and `--strict-memory` covers keys only. This classification is part of the approval.

*Decoding a path from the key table:*
1. Text is decoded only through `deserialize_str`, using a custom visitor. In `ciborium` 0.2.2 this path reads into the caller's scratch buffer when the text fits, and otherwise returns an error with no allocation (Section 3.2). The scratch is exactly 4096 bytes, the path limit, so a longer path fails before any allocation. `String`, `deserialize_string` and `Value` are never used.
2. The visitor receives `&str` borrowed from the scratch. It runs the decode-time checks on the borrowed text, then copies it once into a `VaultPath`: a zeroize-on-drop `Box<str>` allocated at exactly the right length, so it never grows or reallocates.
3. **Decode-time checks** (independent of the Unicode version):
   - valid UTF-8, total length at most 4096 bytes, each component 1 to 255 bytes;
   - no leading `/`, empty components, `.` or `..`, `\`, U+0000 to U+001F, U+007F, or any of `< > : " | ? *`;
   - no trailing space or dot;
   - no Windows reserved names (ASCII case-insensitive);
   - entries in strictly ascending bytewise order, which also rejects exact duplicates;
   - every parent present as a `dir` entry.
4. **Not checked at decode time:** NFC form and case-fold collisions. Their results depend on the Unicode tables, which change between Rust and crate versions. Checking them at decode time could make an existing vault fail to open after an upgrade.

*Input (`add`, `--replace`, conversion):*
- An OS path must be valid UTF-8, or it is refused with a message.
- Two passes produce NFC: the first counts the normalized length, the second fills a zeroizing buffer of exactly that size, so nothing grows.
- The full rule set then runs, including collisions against existing entries, compared iterator to iterator without building folded copies.
- **Evidence gap:** Unicode *default case folding* (`CaseFolding.txt`, status C + F) is not in `std`, and no approved crate provides it. `char::to_lowercase` is a lowercase mapping, not case folding: it differs for `ß`, final sigma and others. Options:
  - approve a case-folding crate;
  - vendor a generated table at a pinned Unicode version (a Unicode license notice is then required);
  - redefine collisions as "equal after NFC and `to_lowercase`".
  This is an SI-30 decision, **before Milestone 4** (the first input-time check, `add`), provided the decode/input split is approved; otherwise it is needed before Milestone 3.

*In-memory storage of the key table:*
- `Vec<Entry>` is reserved at exactly the CBOR array length (bounded by 64 MiB divided by the minimum entry size) before decoding, so it never reallocates.
- Each `Entry` holds a `VaultPath` and two `SecretBytes<32>` (each its own boxed, zeroizing allocation), so moving an `Entry` moves only pointers.
- Uncertainty for Milestone 7: locking many small key boxes page by page is inefficient. A locked key arena may be needed, and would be a `secrets.rs` design change.

*Encoding:* `serialize_str` and `serialize_bytes` write the head and then the content straight into the caller's fixed, locked output buffer (Section 3.2). There is no intermediate copy.

*Errors:*
- Every key-table decode failure maps to one fixed error, `KeyTableCorrupt`, with no payload and no offset, and therefore no path text.
- `ciborium` errors are never displayed or logged, because `Error::Semantic(String)` can carry serde text, and `Unexpected::Str` includes the string.
- Visitor `expecting()` texts are static.
- No `unwrap` or `expect` on decode results.
- A `Debug` implementation never prints input.
- The key table is AEAD-authenticated before parsing, so a decode error means a bug or a key compromise. **Proposed addition to 5.8, pending with SI-07:** the user sees "The key table is damaged.". It is reachable only after successful authentication, so it reveals nothing to someone without the keys.

*Zeroization on every path:*
- The scratch buffer sits in a guard that wipes it on drop, including on error and during unwinding.
- A partially built `Vec<Entry>` drops each `VaultPath` and each `SecretBytes`, and both zeroize.
- The plaintext buffer is wiped by its owner.
- The comparing-sink check (option 1) runs after a full decode. A mismatch gives the same fixed error, and everything is dropped and wiped.

*Verification for the approval:* a test-only allocation-counting allocator asserts that decoding performs exactly one allocation per path, one per key box, and one for the `Vec`, with no reallocations. A `proptest` round trip and the `keytable_parse` fuzz target cover the rest.

**Recommendation:** option 1 for every structure, including the key table, with the restrictions above. Fall back to option 2 **for the key table only** if the allocation tests show any secret byte passing through a growable buffer.

**Approval needed:** option 1 with the fallback trigger, or option 2.

**Revised recommendation (2026-10-05, for review; `docs/M3_READINESS.md` D3):** option 2, a fixed-schema in-house codec for every structure. It adds a two-pass key-table decode (pass 1 validates and sizes without allocating), exact-capacity arenas, a 65,536-entry cap (**decided N5**: a v1 product limit counting files and directories; an over-limit operation is refused before any write and leaves the vault unchanged; spec 7.8, proposed F92) and an architecture-independent decoded-size charge. The Milestone 2 normalization finding (M2-F1) is the main reason for revising the earlier option-1 recommendation. Nothing is approved.

**Affected:** Milestone 3 (header, journal, key table), the `keytable_parse` fuzz target, F14 and F71.

### SI-08 Shamir — Accepted (option 1); implemented in Milestone 2

**Evidence (`vsss-rs` 6.0.1; Section 3.3):**

| Requirement | Finding |
| --- | --- |
| GF(2^8) with 0x11B | Yes: `a ^= 0x1b & t` in a branch-free multiply. |
| Constant time | Branch-free, table-free multiply. |
| Uniform coefficients, including zero | Yes, since an audit fix; the code comment cites "audit finding #2". |
| Explicit x = 1, 2, 3 | Yes, via participant-ID iterators. |
| Wiping secrets | **No.** The `Vec<GfShare>` polynomial holds the secret byte (slot 0) and the coefficients, and is freed unwiped. The `zeroize` feature only adds `DefaultIsZeroes` impls. |
| Deterministic vectors | Feasible. Each coefficient is the low byte of `rng.try_next_u32()`, so a scripted test RNG reproduces fixed coefficients. That mapping is a version-specific internal. |
| Weight | Default features pull in `crypto-bigint`, `elliptic-curve` and `serde`. `rand_core` 0.10. |

**Proposal (the minimal in-house implementation permitted by 7.4):**
- **Size:** a `shamir.rs` of roughly 100 lines.
- **Arithmetic:** a branch-free GF(2^8) multiply with 0x11B, plus inversion by exponentiation (`a^254`), constant time.
- **Split:** coefficients come from a caller-supplied source (the OS RNG in production, fixed in tests). The coefficient buffer is zeroizing.
- **Combine:** Lagrange interpolation at 0 for exactly two shares with distinct x.
- **Marking:** `// SECURITY-REVIEW-REQUIRED`.
- **Vectors:** independent vectors in `FORMAT.md`, computed by a separate script with a table-free reference implementation, not by pvault itself.
- **Cross-checks:** `vsss-rs` as a dev-dependency only, with `default-features = false` plus the needed features. Property tests check that `combine(ours) == combine(vsss)`. A scripted-RNG test checks that `split(vsss, coeffs) == split(ours, coeffs)` at the pinned version.

**Further investigation (2026-10-04): zeroizing storage, a patch, and in-house compared.**

*Findings in `vsss-rs` 6.0.1 source:*
- `vsss_rs::shamir::create_shares_from_polynomial` is public and generic over **any** `P: Polynomial<S>`, and the `Polynomial` trait is public. pvault can therefore supply its own coefficient storage.
- `ReadableShareSet::combine_in_place` works on a borrowed slice and writes into caller-owned output, with no allocation.
- `validate_share_set` rejects fewer than 2 shares, a zero identifier, or duplicate identifiers **before** interpolation. Its branches look only at identifiers, which are public.
- Interpolation branches only on index equality.
- `gf256_mul` is branch-free (`a ^= 0x1b & t`), and `invert` is a fixed `a^254` square-and-multiply chain.
- Fixed arrays `[S; L]` implement the share-set traits, so no `Vec` is needed.

*Scratch experiment (outside the repository; a counting/inspecting global allocator):*

| Path | Heap allocations | Secret-derived heap freed without wiping | Correctness |
| --- | --- | --- | --- |
| (A) `Gf256::split_bytes_with_participant_ids_iter` (the crate's byte API) | 6 | **2 small blocks freed with non-zero contents**. From the code, one is the polynomial `Vec` (last secret byte plus its coefficient) | — |
| (B) Caller-owned `WipingPoly([GfShare; 2])` (wiped in `Drop`) + `shamir::create_shares_from_polynomial` into `[GfShare; 3]` + `combine_in_place` | **0** during split and combine of 96 bytes | none on the heap | All three 2-of-3 pairs recover the secret; every share equals `s ⊕ a₁·x` computed with an independent GF(2^8) reference (0x11B); duplicate and zero identifiers are rejected |

*Options compared:*

| | 1. `vsss-rs` with caller-owned wiping storage (recommended) | 2. Patched, pinned `vsss-rs` | 3. Minimal in-house `shamir.rs` |
| --- | --- | --- | --- |
| Wiping | pvault owns every buffer: the polynomial wrapper wipes in `Drop`, and the share and output arrays are wiped by pvault | The patch adds wiping to the internal `Vec` | Fully controlled |
| Constant time | `vsss-rs` multiply and inversion (branch-free; reviewed above) | Same | Must be written and reviewed (`// SECURITY-REVIEW-REQUIRED`) |
| Field compatibility | 0x11B, x = 1, 2, 3, interpolation at 0, verified | Same | Must be shown with vectors |
| Coefficients and vectors | pvault writes the coefficients directly into its own polynomial (from `getrandom`, or fixed in tests), so it does not depend on `vsss-rs`'s RNG-to-coefficient mapping | Same as 1 | Direct |
| Error paths | Parameter and identifier validation before interpolation; wiping by `Drop` on every exit, including errors and unwinding | Same | Own |
| New crates | `vsss-rs`, `ff`, `generic-array`, `hex`, `rand_core`, `rustversion`, build-only `syn` 2 and `zeroize_derive`; all MIT or Apache-2.0 | Same, plus a vendored fork to maintain | None |
| Spec rule 3 | Allowed: a listed crate is used | A forked crypto crate; heavy maintenance | Allowed only "if no listed crate fits", and option 1 shows that it fits |

*Residual in every option:* stack and register temporaries of single field elements (the intercept passed to `fill`, the evaluation accumulator). These cannot be wiped reliably in Rust and are documented (10.5).

**Recommendation:** option 1.
- Pin `vsss-rs = "=6.0.1"` with the smallest working feature set (to be confirmed in Milestone 2).
- Use a `WipingPoly` and fixed share arrays, all owned and wiped by pvault.
- Write the coefficients directly from `getrandom`.
- Keep the vectors from the independent Python reference, plus the existing cross-checks.

**Decision (author, 2026-10-04): option 1 approved**: `vsss-rs = "=6.0.1"` with pvault-owned, zeroizing storage.

**Plan for turning the scratch checks into repository tests (Milestone 2):**
- **Correctness:**
  - all three 2-of-3 pairs recover the 96-byte secret;
  - the portable 2-of-2 recovers it;
  - F5: one share alone gives a different value;
  - F6: shares from two different splits do not combine to either secret.
- **Independent vectors (F62):** `tools/vectors/gen_vectors.py` gains a Shamir section computed with a separate Python GF(2^8) reference on 0x11B: secret, coefficients, and the shares at x = 1, 2, 3. The Rust test fixes the coefficients through pvault's own polynomial storage, so it does not rely on `vsss-rs`'s RNG mapping.
- **Field compatibility:** an exhaustive 256 × 256 comparison of `vsss-rs` multiplication against the independent reference, and of inversion for all 255 non-zero elements.
- **Allocations:** a dedicated test binary with a counting global allocator asserts **zero heap allocations** during pvault's split and combine of a 96-byte secret, on both success and error paths.
- **Wiping:** the storage wrapper exposes `wipe()`, which `Drop` calls. Tests check that `wipe()` zeroes the coefficients, and, using `MaybeUninit` plus `drop_in_place`, that dropped storage is zeroed. Share and output arrays are wiped the same way.
- **Error paths:** duplicate x, x = 0, mismatched lengths, and a wrong x for the mode are rejected before interpolation, with nothing left unwiped.
- **Constant time:** a review checklist confirms no table lookups or secret-dependent branches in the `vsss-rs` multiply, invert and interpolate paths (Section 3.3 evidence). There is no timing test, because such tests are unreliable in CI.

**Implemented in Milestone 2** (`crates/pvault-core/src/shamir.rs`):
- `vsss-rs = "=6.0.1"` with `default-features = false`; that is the smallest working feature set.
- Done as planned: all pairs, 2-of-2, F5, F6, F62 vectors from the independent Python generator (log/antilog tables, every pair re-interpolated), the exhaustive 256 × 256 multiplication and 255-inverse comparison, `wipe()` and the `MaybeUninit` drop test.
- **Allocation test, as measured:** `tests/heap_hygiene.rs`. Because every `SecretBytes` is one boxed allocation (so moving a secret never copies it), a 2-of-3 split + combine + 2-of-2 split + combine makes **exactly 9 allocations, all pvault's own buffers** (per split one coefficient buffer plus one per share; one output per combine). **None happens inside `vsss-rs`**, and no non-zero block is freed. The error path (a share combined with itself) allocates nothing. The plan's "zero heap allocations" referred to `vsss-rs`; pvault's own buffers are heap boxes by design (10.1).
- **Not done here:** "a wrong x for the mode" needs the header's mode, which arrives with Milestone 3; mismatched lengths are impossible by type (`SecretBytes<96>`).

**Affected:** Milestone 2; F5, F6, F62.

### SI-09 QR input — Accepted

- **Resolution:**
  - Render SVG only (`qrcode` with default features off).
  - Input comes from Base32 or a PNG (the `png` crate is approved), under the 7.4c limits: 16 MiB file size, 4096 px, a 64 MiB decode buffer checked before allocation, no APNG, and pixel buffers wiped.
  - Camera input is deferred to Milestone 14.
- **Remaining uncertainty:** whether `rqrr` reliably decodes phone photos of printed cards at the chosen limits. This is to be measured in Milestone 4. Base32 always remains available.
- **Affected:** Milestone 4; F47, F61.

### SI-10 Card files — Accepted

- **Resolution:**
  - An explicit, owner-named destination, never inside the vault.
  - SVG files, created exclusively and without following symlinks, with owner-only permissions.
  - Each file is recorded in `cards.cbor` (path and identity) before share bytes are written.
  - Deletion only for recorded files whose identity matches, never by name.
  - File, terminal and history remnants are documented.
- **Remaining uncertainty:** whether a terminal display mode for card text should exist at all. It is currently "never unless explicitly requested", and the option itself is undecided.
- **Affected:** Milestone 4; F78.

**Pending design (7.1): active-operation lifetime lock and cleaner rules.** This mirrors the approved 7.9 transfer locks, adapted for card files.

*Files, all in the per-user config directory:*

| File | Role |
| --- | --- |
| `cards.cbor` | The record (4.4 profile). Entries hold `op_id`, `path`, `dev`, `ino` / file ID, `vault_id`, `set_id` and `created_at`. |
| `cards.lock` (R) | Taken for every read-modify-write of `cards.cbor` (tmp → flush → rename → directory flush); readers take it shared. |
| `cards/<op_id>.lock` (C) | One per card-writing operation, with a random 16-byte `op_id`. |

*Lock order:* C before R. Waits are bounded to 2 s, and only for R, and only while holding C. Nobody waits while holding R. So the protocol cannot deadlock (it is integrated with SI-14).

*Writer* (`init`, `recover`, `recover --to-portable`, `convert`):
1. Before creating any card file, create `cards/<op_id>.lock` without following symlinks (mode `0600`) and lock it exclusively. It stays locked until step 5 finishes, or until the OS releases it when the process dies.
2. For each card:
   1. Create the file exclusively, without following symlinks and with owner-only permissions, relative to the destination handle.
   2. Read its identity from the open handle.
   3. Under R, append the record entry.
   4. Only then write the share bytes.
3. Delivery verification runs (6.4). The lock C stays held throughout, including while the owner prints.
4. On success, abort or rollback: for each of the operation's entries, reopen it without following symlinks. If it is a regular file with matching identity, unlink it and flush the directory. Otherwise drop the entry and report it. Under R, remove the entries.
5. Release C and delete `cards/<op_id>.lock`. This happens only after step 4 has removed the entries.

*Crash windows:*
- A crash between steps 2.1 and 2.3 can leave an **empty, unrecorded** file, but never unrecorded share bytes. A later card write that collides with it may remove it only if it is a regular file of size 0, after confirmation (the 7.9 rule).
- A crash at any later point leaves recorded entries whose C is released, so they are treated as stale.

*Cleaner* (`fsck`, `clean-partials`; never inside the vault):
1. Take R briefly, snapshot the set of `op_id`s, and release R. A malformed record is reported and never used.
2. For each `op_id`, **try** C without blocking.
   - If C is held, the operation is alive. **Skip its entries entirely:** do not list, offer or delete them.
   - If C is acquired, keep holding it for the rest of the cleanup.
3. Take R (bounded wait), re-read that operation's entries, and release R. Entries that have vanished are ignored.
4. List the stale entries and ask the owner to confirm.
5. For each confirmed entry, reopen it without following symlinks. If it is a regular file with matching device and inode / file ID, unlink it. Otherwise drop the entry only.
6. Under R, remove the handled entries. Release C and delete the stale `cards/<op_id>.lock`.

*Unlinked-lock race:* a cleaner that locks a `cards/<op_id>.lock` the writer has already unlinked finds no entries at step 3 and does nothing.

*Liveness* comes only from the OS lock, with no PID files.

**Approval needed:** this design.

**Affected:** Milestone 4; F78 (the cleaner-while-active and after-kill cases).

### SI-11 Secure file creation — Accepted

- **Resolution:**
  - No-replace renames: `renameat2(RENAME_NOREPLACE)`, `renameatx_np(RENAME_EXCL)`, and a Windows handle-relative rename. Refuse when unsupported.
  - `--force` only by atomic exchange plus verification of the displaced entry; refused where exchange is unavailable.
  - No check-then-rename fallback.
- **Remaining uncertainty:**
  - Windows `--force`. A race-free replace that never replaces a reparse point must be validated before Windows gets `--force`; until then it is refused.
  - `RENAME_EXCHANGE` support varies by file system, but all allowlisted Linux file systems support it. To confirm in Milestone 4.
- **Affected:** Milestone 4; F50, F51.

**Pending design (7.1): `--force`.** Until this is approved, `--force` is refused on every platform (7.9).

*Preconditions:*
- The `.pvpartial` (P) is complete: every chunk was verified, and the file was flushed.
- It is recorded in `partials.cbor`, and its transfer lock is held.
- The parent directory D is open as a handle.

*Steps:*
1. **Exchange.** Atomically exchange P and the destination name N, relative to D: Linux `renameat2(RENAME_EXCHANGE)`, macOS `renameatx_np(RENAME_SWAP)`. Afterwards N names our complete plaintext, and the name P names the displaced entry X.
   - If the exchange fails because N does not exist, fall back to the normal no-replace rename.
   - If it fails because the call is unsupported, refuse: delete P under the existing rules, and report.
2. **Inspect X** through D, without following symlinks (`fstatat(AT_SYMLINK_NOFOLLOW)`).
3. **Success: X is a regular file.** Unlink the name P (which removes the owner's old file, the replacement they asked for), flush D, then remove the record entry and the transfer lock (7.9 step 5).
4. **Rollback: X is not a regular file** (a symlink, directory, device or other special file). Exchange again, so N names X and P names our file. Then delete P (our plaintext), using the 7.9 identity check. Fail with "The destination is not a regular file; nothing was replaced."
5. **Failed rollback** (the second exchange returns an error): stop.
   - N holds our complete plaintext. That is permitted: 7.9 allows plaintext at the requested destination.
   - The name P holds X, unmodified.
   - Report exactly that: "The exported file is at N. The previous entry (a <type>) was moved to P and was not modified or followed."
   - Remove the record entry, because our inode is no longer at P. pvault never deletes X.
6. **Crash windows:**
   - Before step 1: an ordinary tracked partial (F33).
   - Between steps 1 and 3 or 4: N holds our complete plaintext, and P holds X. A later cleaner reopens P without following symlinks. X's identity differs from the record (or X is not a regular file), so the entry is **dropped without deleting anything**, and P is reported to the owner.
   - During step 4, after the second exchange: P holds our file again, which matches the record. The normal stale-partial cleanup (with confirmation) handles it.

*Guarantees it actually provides:*
- It never writes through or into a symlink, directory or special file at the destination. Exchange and unlink operate on directory entries, and unlink never follows links or removes directories.
- It never exposes incomplete or unverified plaintext at N. The exchange happens only after full verification.
- A displaced entry that is not a regular file is never deleted. It is either restored to N (rollback) or left at P and reported (failed rollback, or a crash).
- The old regular file is unlinked, not securely erased.

*What it does **not** guarantee:*
- "Replace only a regular file" is not atomic. Between the exchange and the rollback, other processes can see our file at N while a symlink or directory sits at P.
- A process that can write to D can swap the entry at P between the inspection and the unlink. The unlink then removes whatever entry is at P: only a directory entry, never a link target, and never a non-empty directory.
- Rollback can fail. The outcome is then reported, not repaired.

*Windows:* no atomic exchange is available, so `--force` stays refused.

*Proposed test:* F90. Covers `--force` over a regular file, a symlink, a directory and a FIFO; crash injection after the exchange; and a simulated failed rollback. Expected outcomes are as above.

**Approval needed:** the design, and the stated guarantees.

### SI-12 Durability primitives — Pending (evidence)

**Evidence (primary documentation; Section 3.4):**
- **macOS `fsync(2)`:** the drive "may not physically write the data … for quite some time", and data can be lost or reordered on power loss.
- **macOS `fcntl(2)`:** `F_FULLFSYNC` "asks the drive to flush all buffered data to the permanent storage device". Implemented on HFS, FAT, UDF and APFS.
- **macOS `rename(2)`:** "guarantees that an instance of new will always exist, even if the system should crash in the middle of the operation". `RENAME_EXCL` and `RENAME_SWAP` depend on volume capabilities (`ENOTSUP` otherwise).
- **Linux `rename(2)`:** atomic replacement is stated for **concurrent observers** ("no point at which another process … will find it missing"), not for crashes.
- **Linux `fsync(2)`:** flushes the disk cache when the file system supports it ("older kernels and lesser used filesystems do not know how to flush disk caches"). It needs a separate `fsync` on the directory for the directory entry.
- **Linux `RENAME_NOREPLACE`:** requires file-system support (ext4 since 3.15; many others since 4.9).
- **Windows `MoveFileExW`:** `MOVEFILE_WRITE_THROUGH` "guarantees that a move performed as a copy and delete operation is flushed to disk". No crash-atomicity statement for same-volume renames was found, and this does not specify `NtSetInformationFile(FileRenameInformation)`.
- **Windows `FlushFileBuffers`:** flushes a file. Flushing a volume requires administrative privileges.
- **Windows `NtCreateFile` / `NtSetInformationFile`:** `RootDirectory` plus a
  one-component `ObjectName` provides the required handle-relative open, and
  `FileRenameInformation.RootDirectory` makes the destination relative to the
  held directory handle. `FILE_OPEN_REPARSE_POINT` opens a reparse point
  itself. The Win32 write-through documentation says an NTFS write-through
  request flushes metadata changes, including a rename resulting from the
  request. The `NtCreateFile` flag definition itself speaks only of requested
  write operations. Neither source establishes ReFS behavior, old-or-new
  crash atomicity, power-loss safety or equivalence to
  `MoveFileExW(MOVEFILE_WRITE_THROUGH)`.
- **Rust `std::fs::rename` (1.89):** on Windows it uses `MoveFileExW` or `SetFileInformationByHandle`, so the flags are not under our control. Use explicit calls.

**Proposed primitives:**

| Platform | File flush | Replace | Directory entry | Claim |
| --- | --- | --- | --- | --- |
| Linux (ext4, XFS, Btrfs) | `fsync` | `renameat` / `renameat2` | `fsync(dirfd)` | Crash consistency as provided by these journaling file systems with flush support |
| macOS (APFS, HFS+) | `fcntl(F_FULLFSYNC)` | `renameat` | `F_FULLFSYNC` on the directory fd (to verify) | `rename(2)`'s documented crash guarantee |
| Windows (NTFS, ReFS) | `FILE_WRITE_THROUGH` for data writes plus `FlushFileBuffers` | handle-relative `NtSetInformationFile(FileRenameInformation)` after a no-follow `NtCreateFile` open | none available without admin | **Not documented** as crash- or power-loss durable by Microsoft; W1 is an explicit assumption |

**Detection correction:** Linux must resolve the open directory's mount ID and
parse `/proc/self/mountinfo` by locating the first token exactly equal to `-`
after the six fixed fields. The filesystem type is the token immediately after
that separator; optional fields make a fixed field number incorrect. Accept
only exact `ext4`, `xfs` or `btrfs`. Never infer ext4 from `statfs` magic
`0xEF53`, which is shared with ext2/ext3. Query/parse ambiguity fails closed.

**Replacement failure boundary:** failure before replacement is an ordinary
pre-commit abort. A replacement-call error has unknown outcome and requires
reopening/authenticating the header against the journal's exact expected-core
digests. Once replacement succeeds, a required directory/full-flush failure is
“committed-visible, durability unknown”: retain the committing journal and all
old/new dependencies, report the distinct durability error, and let restart
authenticate the header and retry the flush before cleanup. It must never be
reported or handled as a pre-commit abort. A failed flush after journal unlink
likewise permits a harmless stale authenticated journal on restart.

**Author selection W1 (2026-10-05), reconciled with the required
handle-relative implementation:** NTFS and ReFS remain writable under the
following explicit product assumption. The primitive name is amended from the
earlier `MoveFileExW` draft because path-based replacement is not permitted:

> After the temp-file flush, successful same-volume handle-relative
> `NtSetInformationFile(FileRenameInformation)` replacement leaves either the
> authenticated old header or the authenticated new header after process, OS
> or power failure.

This is not a Microsoft-documented guarantee and is not a claim of verified
power-loss safety. `FILE_WRITE_THROUGH` is requested on the verified source
handle under the documented NTFS metadata-flush behavior, but is not claimed
to establish ReFS behavior, atomic old-or-new survival, or equivalence with
`MoveFileExW(MOVEFILE_WRITE_THROUGH)`. Native kill-at-each-step tests establish process-crash
behavior only on tested systems; VM power-cut testing is additional
configuration evidence and cannot turn the assumption into a platform
guarantee. The read-only-Windows and redundant-header alternatives are not
selected.

**Remaining uncertainty:**
- Windows crash atomicity of rename-replace remains an undocumented, now
  explicit assumption.
- Whether directory `F_FULLFSYNC` is meaningful on APFS.
- Device firmware that ignores flushes.

None of these can be proven by process-crash tests (now stated in 2 and 8.5).

**Readiness-audit additions (2026-10-05, for review):**
- Windows SMB shares can report `NTFS`. The local-volume acceptance criterion (spec 8.5) requires four results on each held directory handle:
  - Q1: `FileRemoteProtocolInfo` fails with `ERROR_INVALID_PARAMETER` or
    `ERROR_NOACCESS`; native Windows CI run 37390554153 observed
    `ERROR_NOACCESS` (998) on the runner's local NTFS temp directory, and
    Microsoft does not document one unique local-volume error;
  - Q2: `VOLUME_NAME_GUID` gives a `\\?\Volume{` path;
  - Q3: `GetDriveTypeW` is `DRIVE_FIXED` or `DRIVE_REMOVABLE`;
  - Q4: the volume name is exactly `NTFS` or `ReFS`, with a matching serial for `objects/`.

  Every other result refuses, with no weaker retry. Native Windows CI run
  37390554153 recorded Q1 `ERROR_NOACCESS` (998), a local volume-GUID path,
  `DRIVE_FIXED`, and `NTFS` for the runner's local temp directory. Q2's SMB
  behavior remains unverified: native probes still need local ReFS, a VHD, a
  mapped SMB drive and an available UNC path. Until every query matches an
  accepted result, the criterion fails closed.
- `objects/` must be on the same mount and volume as the vault directory.
- A durability-capability preflight runs before any side effect, so that a *predictable* "unsupported" is a refusal rather than a post-commit "durability unknown". Passing it never weakens post-commit handling: any failure after the header replacement call, whatever its error code, still follows the failure boundary ("outcome unknown" or "committed-visible, durability unknown").
- **Decided N1 (2026-10-05), with the primitive name amended by the later handle-relative correction:** W1 retains its risk boundary and now names `NtSetInformationFile(FileRenameInformation)`, not path-based `MoveFileExW`. The Windows ordering assumptions WO-1 (journal first), WO-2 (key table before header) and WO-3 (deletions do not overtake the commit) are stated explicitly as unverified, and documentation says that a Windows power loss or OS crash during a commit can leave a vault unreadable, recoverable only from a backup (spec 2 and 8.5).

See `docs/M3_READINESS.md` D5.

**Approval needed:** the remaining primitive table and allowlist details. W1
itself and its limitation wording are selected; that does not approve the
other SI-12 recommendations.

**Affected:** Milestone 3; F25, F26, F44, F45, F54, F67.

### SI-13 Unsupported file systems — Accepted (modified)

- **Resolution:**
  - Mutations are allowed only on allowlisted file systems: Linux ext4, XFS and Btrfs; macOS APFS and HFS+; Windows NTFS and ReFS.
  - Everything else (FAT32, exFAT, NFS, SMB/CIFS, FUSE) is read-only for v1.
  - Portable duress modifies nothing there.
  - No crash-safety claim, and no redundant headers.
- **Remaining uncertainty:**
  - **Availability consequence:** a portable vault on a typical exFAT pendrive or SD card can be opened and read, but **not changed**, in v1. Cross-platform writable portable media would need NTFS (no native macOS write support) or a future reviewed protocol.
  - The exact allowlist needs SI-12 confirmation.
  - File-system type detection uses the 7.6a FFI.
- **Affected:** Milestone 3 (detection); Milestone 4 (refusals); F74.

### SI-14 Lock protocol — Pending (design)

**Evidence:**
- Linux `flock(2)`: "Converting a lock … is not guaranteed to be atomic: the existing lock is first removed, and then a new lock is established."
- macOS `flock(2)`: the previous lock is released "possibly after other processes have gained and released the lock".
- `LockFileEx`: "Exclusive locks cannot overlap an existing locked region". It has no conversion.
- Rust 1.89 `File::lock`: if the handle "already holds a lock", the behavior "is unspecified and platform dependent, including the possibility that it will deadlock".

**Proposed protocol:**

1. **Lock files**, created without following symlinks, mode `0600`, never truncated, never deleted or renamed while the vault exists, and opened **once per process** (that rule also protects against `fcntl`-emulated `flock` on NFS releasing locks on close):

   | File | Mode | Purpose |
   | --- | --- | --- |
   | `vault.gate` (G) | exclusive only | Held only while changing the mode of L. Never held while waiting for anything. |
   | `vault.lock` (L) | shared or exclusive | The vault lock of 8.4. |
   | `vault.mount` (M) | exclusive | Held by a mounted session for its whole life. Liveness means "M is locked". The OS releases it on death, so there are no PID files. |
   | Per-user `partials.lock` (P), `transfers/<id>.lock` (T), `rollback.lock` | as 7.9 / 9.7 | Records. |

2. **Acquisition rules.**
   - Every try is non-blocking, with two bounded exceptions:
     - a process that already holds L may retry G for up to 2 s;
     - a holder of T may wait up to 2 s for P.
   - G holders and P holders never wait. No cycle of waits can form, so the protocol cannot deadlock.
   - A handle that holds a lock is **never** re-locked. Conversion is always unlock, then lock, on the same handle, under G.
3. **Exclusive acquire** (mutations, and the start of every ordinary unlock):
   1. Try G. If busy: "The vault is in use by another pvault process."
   2. Try L exclusive. If busy: try M. If M is held → "This vault is mounted. Use the mounted drive, or unmount first." Otherwise → "in use". Release G and exit.
   3. Release G and keep L exclusive.
4. **Downgrade** (`list`, `get`, and a mount after its unlock):
   1. Take G (bounded retry; any competing G holder fails on L and releases at once).
   2. Unlock L, then try L shared.
   3. Release G.

   Step 2 cannot fail against cooperating processes: every exclusive acquirer needs G, and shared holders are compatible. If it fails anyway, abort the read-only operation with "in use".
5. **Upgrade** (a commit through the mount):
   1. Take G, unlock L, and try L exclusive.
   2. On success: release G, commit, then downgrade.
   3. On failure (a `status` reader holds L shared): re-take L shared (guaranteed while G is held), release G, and retry with backoff for up to 2 s in total. Then fail that write with a busy error. What happens to the write is part of SI-45.
6. **`status`:** tries L shared only, never G. It reports "mounted" by probing M, and "in use" if L is held exclusively.
7. **Mounted session:**
   1. Exclusive acquire, then unlock and the duress check.
   2. Take M exclusive, then downgrade L.
   3. Hold M and L shared for the session. On exit, release M, then L.
8. **Transfers (7.9):**
   - An export holds L shared, then T, then P briefly to write the record.
   - The cleaner (`clean-partials`, no vault lock) holds P and **tries** T without blocking; it skips the entry if T is held.
   - Transfer lock files are deleted by the exporter after its record entry is removed. A cleaner that locks an already-unlinked T re-reads `partials.cbor` under P, finds no entry, and does nothing.
9. **Non-cooperating writers:** out of scope, and documented (8.4).

**Remaining uncertainty:**
- Windows `LockFileEx` on zero-length files: this is expected to work, because the lock range may extend past end-of-file, but it must be tested in Milestone 3.
- The 2 s bounds are provisional.

**Approval needed:** the protocol above.

**Affected:** Milestone 3 (8.4); Milestone 11 (mount); F56a, F56b, F72, F70.

### SI-15 Memory locking — Accepted (modified)

- **Resolution:**
  - Best-effort locking of key material and the key-table buffer, with a one-time warning and the state shown in `status`.
  - Optional strict mode (`--strict-memory`) that refuses on locking failure.
  - Argon2 memory is allocated after the 4.3 checks, used once, wiped before release and freed. It is never locked.
- **Remaining uncertainty:**
  - Argon2 working memory holds blocks from which the 32-byte output can be computed. If swapped, those blocks reach disk; this is mitigated only by encrypted swap, which is documented, not enforced.
  - Whether strict mode should also refuse when swap is unencrypted cannot be detected portably, so it is left out.
- **Affected:** Milestone 3 (key-table buffer); Milestone 7; F77.

### SI-16 Argon2 memory limits — Accepted (modified)

- **Resolution:**
  - Hard caps in KiB, giving `Unlock failed.`.
  - Policy limit: m ≤ 50% of **total** RAM, with a specific message.
  - Resource check: **available** memory ≥ m + 64 MiB, with a specific message.
  - Allocation only after all three checks.
  - Stored parameters are never lowered.
- **Remaining uncertainty:**
  - The 64 MiB margin is provisional.
  - "Available memory" means different things per platform (`MemAvailable`, Mach VM statistics, `ullAvailPhys`); the definitions will be fixed in Milestone 3.
- **Affected:** Milestone 3; F13, F76.
- **Proposed definitions (2026-10-05, for review; `docs/M3_READINESS.md` D8):**
  - Linux `MemAvailable`;
  - Windows `ullAvailPhys`;
  - macOS `sysconf(_SC_PAGESIZE) × (free_count + inactive_count)` from `host_statistics64(HOST_VM_INFO64)`.

  A query failure refuses before allocation. (`libc` has no `host_page_size`, and its `mach_host_self` is deprecated; it is used under a scoped allow, with no new crate.)

### SI-17 Fuzz toolchain — Accepted

*Re-evaluated "Decision: No".* Accepted with one addition: a Linux CI job that builds the fuzz targets and runs a short smoke fuzz on every push. The 10-minute campaigns stay in Milestone 7.

- **Remaining uncertainty:** whether the nightly toolchain should be pinned to a dated nightly for reproducibility. Recommended: yes.
- **Affected:** Milestones 3 and 7.

### SI-18 TPM dependencies — Pending (design)

*Re-evaluated "Decision: No". The author moved it to design review.*

**Proposal:**
- **Pin:** `tss-esapi = "=7.7.0"`, with `tss-esapi-sys` 0.6.0 locked. `tss-esapi` 8.0 is still alpha; re-evaluate when it is stable.
- **System library:** `tpm2-tss` ≥ 2.4.6 is enforced by `tss-esapi-sys`'s `build.rs` (`MINIMUM_VERSION`). The Ubuntu 24.04 CI runners install it via `libtss2-dev`.
- **Feature gating:** a Linux-only target dependency behind the Cargo feature `tpm` (default on Linux), so portable-only builds need no TSS libraries.
- **Device access:** real-device access stays behind `--tpm device` plus explicit authorization during development. `status` explains missing `/dev/tpmrm0` permissions.

**Remaining uncertainty:** the `tss-esapi` 7.7 API coverage for every call in SI-22. Confirm at the start of Milestone 5, before writing code.

**Affected:** Milestone 5.

### SI-19 Non-TTY secret input — Accepted (modified)

- **Resolution:**
  - An explicit `--secrets-stdin` flag reads secrets one per line, in prompt order.
  - Without it, a non-TTY standard input is refused for secret prompts.
  - Secrets are never accepted from argv or the environment.
- **Remaining uncertainty:** the flag name is to be confirmed in `docs/CLI.md`.
- **Affected:** Milestone 4; F79.

### SI-20 Deterministic CBOR — Accepted

*Re-evaluated "Decision: No".* Accepted as the 4.4 profile, with one change from the first proposal: `s1_x` and `s2_x` are **kept**, with fixed required values, instead of being removed. That keeps the field set as specified and catches corruption.

- **Remaining uncertainty:** none beyond SI-07, the implementation choice.
- **Affected:** Milestone 3; F14.

### SI-21 KDF parameters — Accepted

*Re-evaluated "Decision: No".*
- **Alternative considered:** a `vault_id` HKDF salt. Rejected because `master_pw` is already a uniformly random 32-byte Argon2 output, unique per vault through `core.salt`, and every `info` string is distinct.
- **Accepted:** Argon2id v0x13, no secret or associated data, 32-byte output; HKDF-SHA-512 with no salt and L = 32.
- **Remaining uncertainty:** none. Known-answer vectors are due in Milestone 1.

### SI-22 TPM public area and sessions — Pending (design)

**Evidence:**
- **`TPMA_NV` bits** (`tss-esapi` 7.7.0 `attributes/nv_index.rs`): AUTHWRITE is bit 2, AUTHREAD bit 18, NO_DA bit 25, WRITTEN bit 29 and PLATFORMCREATE bit 30. The `TPM_NT` field is bits 7 to 4.
- **Command codes** (`constants/tss.rs`): `TPM2_CC_PolicyAuthValue = 0x0000016B`, `TPM2_CC_PolicyOR = 0x00000171`, `NV_DefineSpace = 0x0000012A`, `NV_UndefineSpace = 0x00000122`.
- **Sessions:** `start_auth_session(tpm_key, bind, nonce, SessionType, SymmetricDefinition, HashingAlgorithm)` exists. Session attributes support `with_decrypt` and `with_encrypt`.

**Proposed exact public area (`TPMS_NV_PUBLIC`):**

| Field | Value |
| --- | --- |
| `nvIndex` | chosen handle in `0x01800000..=0x01BFFFFF` |
| `nameAlg` | `TPM_ALG_SHA256` (`0x000B`) |
| `attributes` | `0x00040004` (ORDINARY, AUTHWRITE, AUTHREAD) pre-write; `0x20040004` (adds WRITTEN) post-write; every other bit clear, including NO_DA, so DA protection is on |
| `authPolicy` | `SHA-256(0^32 ‖ u32_be(0x171) ‖ A ‖ B)`, where `A = SHA-256(0^32 ‖ u32_be(0x16B))` and `B = SHA-256("pvault/v1/policy-nonce" ‖ tpm_policy_nonce)` |
| `dataSize` | 97 |

- **Name:** `u16_be(0x000B) ‖ SHA-256(marshal)`, 34 bytes. `marshal` is `u32 nvIndex ‖ u16 nameAlg ‖ u32 attributes ‖ u16(32) ‖ authPolicy ‖ u16 dataSize`, 46 bytes.
- **Checks:** 9.2a and 9.2b compare the complete public area to this template.

**Proposed sessions (fail closed):**
1. **Salting key:** per process, create a transient **ECC P-256 primary in the NULL hierarchy** with a fixed template. That needs no owner or endorsement authorization and no persistent handle. Flush it on exit.
2. **Session:** `StartAuthSession(tpmKey = that key, bind = none, type = HMAC, symmetric = AES-128-CFB, authHash = SHA-256)`.
3. **Parameter encryption:**
   - `NV_DefineSpace`: **decrypt**. Its `auth` parameter is `tpm_auth`, which would otherwise cross the bus in the clear.
   - `NV_Write`: **decrypt**.
   - `NV_Read`: **encrypt**.
   - The owner-authorized commands (`NV_DefineSpace`, `NV_UndefineSpace`) use the same kind of session.
4. **No fallback:** if key creation, session start or parameter encryption fails, abort with a TPM session error. Never fall back to a password session or to clear parameters.

**Trust assumptions (to document):**
- Salting defeats a **passive** bus observer: `tpm_auth` and wrapped S2 are hidden.
- An **active interposer** can substitute the salting key, because the CreatePrimary response is unauthenticated. Defeating that needs EK-certificate verification, which is out of scope for v1 and documented.
- `NV_ReadPublic` responses are not integrity-protected; a forged response leads only to failure or one DA count.

**Remaining uncertainty:**
- The latency of creating an ECC primary on slow hardware TPMs.
- The exact `tss-esapi` calls for the per-command session attributes. Verify in Milestone 5.

**Approval needed:** the public area and the session design.

**Affected:** Milestone 5; F30, F52, F2, F19.

### SI-23 Stream version and `rec_len` — Accepted

*Re-evaluated "Decision: No".* Accepted: `u16_be(version)` in the AAD; exact `rec_len`; only version 1 accepted; wording fixed.

- **Remaining uncertainty:** none.
- **Affected:** Milestone 3; F11.

### SI-24 Dual-cipher claim — Accepted (option a)

- **Resolution:**
  - A1 lists the exact primitives.
  - The dual-cipher margin covers the chunk layer only.
  - Wraps rely on XChaCha20, and authentication on HMAC-SHA-512.
  - No whole-vault single-cipher-break claim.
  - No cascaded wraps in v7.
- **Remaining uncertainty:** whether to revisit cascaded wraps later. Not planned.
- **Affected:** docs (A1, README, ASSUMPTIONS).

### SI-25 Structural corruption vs F8 — Accepted (modified)

- **Resolution:**
  - F8 now covers value-byte corruption that still parses.
  - Structural corruption, core corruption and (bound) `s1_*` corruption are documented as possibly preventing recovery.
  - No embedded-slots format.
- **Remaining uncertainty:** none. The availability limit is a documented property.
- **Affected:** Milestone 3; F8.

### SI-26 Duress-tag presence — Accepted (modified)

- **Resolution:** keep the optional tag; document that its presence reveals that duress is configured.
- **Remaining uncertainty:** whether a later version should always store a tag. Deferred.
- **Affected:** docs.

### SI-27 Passphrase normalization — Accepted

- **Resolution:**
  - NFKC, trim, whitespace runs collapsed to one space, Unicode lowercase.
  - Hyphens are part of words (four EFF words contain them).
  - An input-only word-list hint stops before Argon2 and before any TPM use.
  - `normalize()` applies everywhere, including the init-journal key.
- **Remaining uncertainty:** none.
- **Affected:** Milestone 2; F75.

### SI-28 Generation semantics — Accepted

*Re-evaluated "Decision: No".*
- **Accepted:**
  - Generation is the authenticated transaction counter, +1 per commit made with the bundle; Revoke and duress do not change it.
  - **`keytable_gen == generation` after every commit.** Slots-only commits such as `duress set` re-encrypt the unchanged key table, at an accepted cost of up to 64 MiB of re-encryption on rare operations.
  - The rollback-detection limits are documented in 9.7.
- **Remaining uncertainty:** none.
- **Affected:** Milestone 3; F18, F58.

### SI-29 Header resilience — Pending (design)

- **Accepted (applied):**
  - Header backup requirements are documented (6.1, 14).
  - No recovery from a lost or unparseable header is claimed.
- **Proposed S2 + S3 path** (`recover --use-tpm`, an explicit owner choice and never an automatic fallback):
  1. **Surviving metadata required:** a header that parses (4.4); an intact core whose `core_mac` verifies; and the slots fields `tpm_nv_index`, `tpm_nv_name`, `tpm_policy_nonce` and `s2_nonce`. Also the index present on this TPM, the passphrase and the bound card. `s1_*` may be damaged.
  2. **Derive and read:** derive `k_s2wrap` and `tpm_auth`. Make a provisional read under 9.2a (one DA count if the passphrase is wrong). Unwrap S2. Decode S3. Combine S2 (x = 2) with S3 (x = 3).
  3. **Verify:** check `core_mac`. Then check the old `slots_mac`, which normally fails here and gives `old_slots_authenticated = false`.
  4. **Continue** with 6.2 onward. The old index stays and is reported (F55 rule).
- **Not covered:** a missing or damaged core, damaged TPM fields, a missing index, or a header that does not parse.
- **Proposed test:** F86, where `s1_ct` is corrupted and passphrase + TPM + card recovers, and the old index is reported.
- **Approval needed:** the path and its command name.
- **Affected:** Milestone 6.

### SI-30 Vault paths — Accepted

- **Resolution (7.8):**
  - Unique paths that are NFC, `/`-separated and relative.
  - Traversal, absolute paths, empty components and control characters rejected; Windows-incompatible names rejected on every platform.
  - Case-fold and NFC collisions rejected.
  - Explicit `dir` entries.
  - `created_at` and `modified_at`, with no permission bits.
  - `--replace` with a fresh ID and keys.
- **Remaining uncertainty:**
  - The 4096-byte and 255-byte limits.
  - Unicode default case folding versus OS-specific case rules (APFS and NTFS differ in edge cases); using the strictest, default folding, may reject a few names some platforms would allow.
  - Confirm the entry layout before Milestone 3.
- **Affected:** Milestones 3 and 4; F64, F73.

### SI-31 `convert` — Accepted (drafted)

- **Resolution:** the 6.9 protocol.
  - Ordinary unlock and typed confirmation.
  - New bundle, salt, `set_id` and cards.
  - A new passphrase for bound → portable.
  - Write-ahead journal, delivery verification, dual-MAC commit, and old-index retirement only under 9.2b.
- **Remaining uncertainty:** the confirmation phrases. Review the draft before Milestone 6.
- **Affected:** Milestone 6; F32, F68, F82.

### SI-32 Duress setup — Accepted (drafted)

- **Resolution:** the 6.10 protocol: `duress set` / `duress disable` as ordinary-unlock commits; an optional step in `init`; refused when bound duress is unavailable.
- **Remaining uncertainty:** review the draft before Milestone 5.
- **Affected:** Milestone 5; F46, F57, F59, F81.

### SI-33 Duress scope and ordering — Accepted

- **Resolution:**
  - The 5.7 command and authentication table.
  - Unlock order: lock → header → Argon2 limits → word check → Argon2 → duress check → pending-journal check.
- **Remaining uncertainty:** none.
- **Affected:** Milestone 4; F63.

### SI-34 Portable single-card verification — Accepted (modified)

- **Resolution:** keep two-card authenticated verification. Document that it brings the cards together. No public commitments.
- **Remaining uncertainty:** none for v1.

### SI-35 Recovery details, handle allocation, overflow — Pending (design)

*Re-evaluated "Decision: No". The author moved it to design.*

**Proposal:**
1. **`new_gen`** = `old_gen` + 1 with a checked add. At `u64::MAX`, commits are refused ("generation limit reached"), which is unreachable in practice.
2. **Argon2 parameters at recovery or conversion:** the current defaults, which must pass 4.3 on this machine, recorded in the new core.
3. **Handle allocation:**
   1. Pick a uniformly random handle in `0x01800000..=0x01BFFFFF` from the OS RNG.
   2. Probe it with `NV_ReadPublic`; absent means it is a candidate. Try at most 32 times, then fail with "no free NV handle".
   3. Write the journal (write-ahead), then `NV_DefineSpace`.
4. **Collision and outcome handling:**

   | `NV_DefineSpace` outcome | Action |
   | --- | --- |
   | Success | Confirm the pre-write Name. |
   | `TPM_RC_NV_DEFINED` (raced) | The TPM rejected the command, so nothing was created. Confirm via `NV_ReadPublic` that the existing Name matches **neither** journaled Name; that resolves it as "not ours". Abort by the normal rollback (6.6), which deletes the journal, then restart preparation with a **new** journal. The journal's index fields are never rewritten in place. |
   | Definite TPM error (e.g. `NV_SPACE`) | Nothing was created: roll back and report. |
   | Unknown outcome (transport error, timeout, process killed) | The index may exist. Stop and **keep** the journal. `fsck` resolves it by Name: a journaled Name means delete under 9.2b; absent or a foreign Name means resolved. |

**Proposed tests:** F87 (a handle raced between probe and define) and F88 (an unknown define outcome, then `fsck` resolution).

**Keeping track of indices that cannot be resolved here (added in 7.1 for F25).** Under the same-TPM rule, `fsck` on another machine, or on a TPM whose identity cannot be established, must not delete a journaled index. The vault-side resolution must still finish, so that the vault is usable. Options:
- **(a) Keep the journal.** The vault stays blocked until `fsck` runs on the original TPM. That is a severe loss of availability; rejected.
- **(b) A per-user local record.** It is machine-local and lost when the vault moves; rejected.
- **(c) Recommended: an authenticated `tpm_cleanup` list in the core.**
  - Entries hold the handle, permitted Names, policy nonce and the scope-5
    encrypted TPM-identity token (SI-36).
  - `fsck` resolves the vault side, then moves the unresolved index into this list as part of its commit (`core_mac`, generation + 1), and deletes the journal.
  - Any later `fsck` with an unlock on a matching TPM deletes the index under 9.2b, and the entry is removed in the next commit.
  - `status` lists pending entries.

  This is a core format change, so it must be decided before Milestone 3. With (c), F25 holds as "no index left untracked".

**Core-state journal binding added for review (2026-10-05).** Every transition
journal authenticates the precise core states it permits, using the existing
header digest definition:

`SHA-512("pvault/v1/core" || canonical_cbor(CoreFields))`.

Each value is a CBOR `bytes(64)` covered by the journal MAC. `prepared` has
`old_core_digest`; `committing` has `old_core_digest` and `new_core_digest`;
`rollback_tracking` has `old_core_digest` and `tracking_core_digest`. The
single-MAC encoding omits `mac`; the dual-MAC encoding omits both `mac_old` and
`mac_new`. Generation, mode and filenames never classify a restart side.
Restart requires the applicable journal MAC, the candidate core's `core_mac`,
and a constant-time match between the recomputed actual core digest and the
corresponding journal field.

Crash order is strict: durable `prepared` precedes every target side effect;
durable dual-MAC `committing` follows all new-core dependencies and precedes
header replacement; durable `rollback_tracking` follows construction of the
complete tracking core and precedes its header replacement. A post-replacement
directory-flush failure retains the journal and all dependencies for restart;
it is not a pre-commit abort.

Rollback tracking keeps the exact authenticated old `SlotFields` but changes
`CoreFields`. It therefore recomputes both
`core_mac = HMAC-SHA-512(K_mac_old, "pvault/v1/core-mac" ||
canonical_cbor(TrackingCoreFields))` and
`slots_mac = HMAC-SHA-512(K_mac_old, "pvault/v1/slots-mac" ||
tracking_core_digest || canonical_cbor(OldSlotFields))`. This is allowed only
after the old slots MAC verifies. If it does not and the target index cannot
be resolved on the present TPM, retain the journal and block; never re-MAC
provisional slot data.

The proposed cleanup list is capped at 32 entries. An operation that may add a
record must reserve capacity before writing its journal, defining an index or
creating its target key table. At 32 distinct unresolved records it refuses;
it never evicts or overwrites an entry and never creates an untracked index.

**Readiness-audit completion (2026-10-05, for review):**
- The remote-rollback path gains a `tracking_created` phase that journals the tracking key-table temp identity before any bytes.
- Its `old_gen + 2` generation step is recorded as a glossary exception.
- Transition journals gain `old_keytable_digest` and the `target_created` phase (see SI-40).
- **Header-temp resolution (2026-10-05):** `tracking_created` retains a replaced `committing` record's `header_*` identity. Before the tracking header temp is created, an existing `vault.hdr.tmp` is unlinked only if its identity matches, and the retained identity stays until the directory flush succeeds. A mismatch, missing identity or non-regular file blocks reuse of the name (owner confirmation only). See spec 8.1.
- **Transition journal-temp promotion (2026-10-05):** the permitted transitions are prepared → target_created or tracking_created; target_created → committing or tracking_created; committing → tracking_created (old side only); tracking_created → rollback_tracking.
  - Single-MAC phases verify under the old journal key; `committing` verifies under `mac_old` or `mac_new`.
  - Immutable fields and retained identities are preserved byte-for-byte.
  - Invalid temps are unowned residue that block further rewrites until owner confirmation.
  - Spec 8.2 holds the rules and a crash table for committing → tracking_created → rollback_tracking.
  - Tracking artifacts are **resumed in place** through their identity (truncate and rewrite), never recreated under a new identity.

**Approval needed:** the protocol.

**Affected:** Milestones 3 (journal), 5 and 6.

### SI-36 Cross-machine and TPM-less recovery — Accepted + Pending (design)

- **Accepted (applied):**
  - `recover --to-portable` (6.8), with no TPM needed.
  - The same-TPM deletion rule (9.2b step 3): never delete merely because handle, Name and policy match.
  - Remote old-index limitations documented.
- **Proposed replacement (pending): encrypted, rekeyable identity tokens.** The
  earlier keyed-MAC proposal is rejected as a recommendation: away from the old
  TPM, a MAC under `K_mac_old` cannot be transformed into a new-bundle cleanup
  value or survive another rotation. The exact proposal is in
  `docs/M3_READINESS.md` D6 and is summarized here so the decision record and
  governing schema cannot drift:
  1. `tpm_id_template = 1` means TCG EK Credential Profile 2.5 R2 template H-2,
     ECC NIST P-256 storage EK, with the exact public template enumerated in D6.
     `ek_digest = SHA-256(MU-marshal(returned TPMT_PUBLIC))`, including the
     populated unique point and excluding the outer `TPM2B_PUBLIC.size`.
     Unknown template enums are parse failures.
  2. A token encrypts the exact 32-byte digest with XChaCha20-Poly1305, fresh
     24-byte nonce, 48-byte ciphertext-and-tag. Its 32-byte key is
     `HKDF-SHA-512(base_key, salt=empty, info=label, L=32)`. Exact scopes are:

     | Scope | Label | Base key |
     | ---: | --- | --- |
     | 1 | `pvault/v1/tpm-id/slots` | current `K_mac` |
     | 2 | `pvault/v1/tpm-id/init` | `init_journal_key` |
     | 3 | `pvault/v1/tpm-id/new-index/old-side` | `journal_key(old_bundle)` |
     | 4 | reserved; never used in v1 (decision N4) | none |
     | 5 | `pvault/v1/tpm-id/cleanup` | current `K_mac` |

     The exact AAD is `ASCII("pvault/v1/tpm-id-token\0") || u8(scope) ||
     vault_id[16] || u8(tpm_id_template) || u32_be(tpm_index) ||
     u8(name_prewrite_present) || optional name_prewrite[34] ||
     name_postwrite[34] || policy_nonce[32]`. Presence is exactly 0 or 1.
  3. Flattened schema fields are exact: bound slots use `tpm_id_template`,
     `tpm_id_nonce`, `tpm_id_ct`; init `IDX` uses
     `new_tpm_id_template`, `new_tpm_id_nonce_i`, `new_tpm_id_ct_i`;
     transition `IDX` uses `new_tpm_id_nonce_o`, `new_tpm_id_ct_o`. The
     `committing` record carries no old-index fields (decision N4): an
     authenticated bound old index is tracked only by the scope-5 cleanup
     entry pre-staged in the new core. All templates equal 1; nonce and
     ciphertext lengths are 24 and 48 bytes. Conditional fields are absent,
     never `null`.
  4. `CoreFields.tpm_cleanup` is a required array, empty when unused and capped
     at 32. Each map has `tpm_index`, optional `name_prewrite`,
     `name_postwrite`, `policy_nonce`, `tpm_id_template`, `tpm_id_nonce`, and
     `tpm_id_ct`, with the exact types and sorting rule in D6. Bundle rotation
     decrypts every authenticated old cleanup token and re-encrypts it under
     the new `K_mac` scope 5 with a fresh nonce before creating new files.
     Failure aborts before side effects. Capacity is reserved before an
     operation can create an index; overflow refuses without eviction.
  5. Decrypt only after the containing slots/core/journal MAC verifies. An AAD,
     scope or AEAD failure is corruption and never authorizes deletion. Before
     actual deletion, measure the live TPM, compare the decrypted digest in
     constant time, and then perform all 9.2b Name/public-area checks. Rewraps
     use fresh nonces and immediately zeroize plaintext digests.
  6. The bound duress tag continues to bind the live `ek_digest` directly, as
     specified in 9.6. The token lets remote recovery verify an old re-entered
     duress passphrase after authenticating and opening the old token.
- **Author-selected PCR direction:** P1, nonce-policy only in v1. PCR binding
  requires a future reviewed format revision; it is not pending as a v1
  runtime branch.
- **Remaining uncertainty:** capability/latency evidence for the fixed H-2
  template and the still-pending adoption of this token format. An EPS change
  invalidates the identity along with the owner indices.
- **Readiness-audit findings (2026-10-05):**
  - Because the token is required in bound slots and `IDX`, a TPM whose H-2 EK cannot be measured cannot receive a bound index at all. C4 therefore gates bound creation, not only duress. **Decided N2 (2026-10-05):** bound `init`, recovery and `convert` measure the identity before any write. On failure they refuse and explicitly offer portable mode (`recover --to-portable` for recovery), leaving the vault unchanged (spec 9.3; proposed F91).
  - **Decided N4 (2026-10-05):** the committing record's old-index fields and scope-4 token are removed. This was decided after verifying that every restart path that may act on the old index authenticates and opens the staged scope-5 entry without the old TPM. The new side, and every later `fsck` or rotation, has `K_mac_new`; on the old side the old index is still live; an indeterminate header deletes nothing. Scope 4 is reserved.
- **Approval needed:** the encrypted-token mechanism, exact H-2 template and
  duress integration. P1 itself is already selected.
- **Affected:** Milestone 3 (format), Milestones 5, 6 and 9; F25, F80, F83, F38, F81.

### SI-37 Object keys not rotated — Accepted (modified)

- **Resolution:** documented (6.11). `recover --rekey-files` is deferred until a full protocol is reviewed.
- **Remaining uncertainty:** none for v1.

### SI-38 Safe `init` (both modes) — Pending (design)

*Re-evaluated "Decision: No". The author moved it to design.*

**Proposal:**
1. **Target directory T** (bootstrap and preflight order: spec 8.3, "Init bootstrap and preflight order"; only T and its two lock files may be created before the completed preflight, and `init` never creates `objects/`):
   - It must not exist (pvault creates it, mode `0700`, after the parent's file system passes 8.5) or must be an empty directory, opened without following symlinks.
   - Zero-length regular lock files left by an earlier pvault attempt count as empty.
   - Anything else → refuse ("directory not empty").
2. **Both modes write an init journal before any other vault artifact.** The
   common fields are the exact 8.1 schema. The key is
   `HKDF-SHA-512(master_pw, salt=empty,
   info="pvault/v1/init-journal", L=32)` from the same one Argon2id result.
   Bound init carries the complete index context and scope-2 encrypted identity
   token. Every phase retains immutable fields byte-for-byte and is re-MACed.
3. **Four exact phases and crash order:**
   1. `prepared`, directory-flushed before an index definition or artifact.
   2. Securely create empty `keytable.1.pv.tmp`; record its authenticated
      platform file identity in durable `keytable_created` **before** writing
      bytes. Continue through the same handle, flush, rename, directory-flush,
      then write `keytable_written` with `keytable_digest` and the exact
      `new_core_digest`.
   3. After card/type-back/duress work, securely create empty `vault.hdr.tmp`;
      record its authenticated identity in durable `committing` before writing
      bytes. Its header must contain the core matching `new_core_digest`.
   4. Flush, rename and perform the platform post-replacement flush. Remove the
      journal only after the core, slots and journal MACs and `new_core_digest`
      verify and the post-replacement flush succeeds. `header_file_id` owns only
      `vault.hdr.tmp` residue; a mismatch on the committed header is reported,
      not blocking (corrected 2026-10-05; spec 8.3). A post-replacement flush
      failure retains the journal and artifacts for restart; it is not
      reported as a normal pre-commit abort.
4. **Identity, not filename, proves file ownership.** Unix identity is
   `u64_be(st_ino) || i64_be(birth_sec) || u32_be(birth_nsec)` (20 bytes),
   checked on the same `st_dev` as the held directory at restart. Windows
   identity is `u64_be(FILE_ID_INFO.VolumeSerialNumber) ||
   FILE_ID_128.Identifier || u64_be(FILE_BASIC_INFO.CreationTime)`
   (32 bytes). (Revised by the readiness audit; the draft's
   `st_dev || st_ino` was unstable across reboots and open to inode reuse.)
   Capture it from the open, securely created regular file. Restart reopens
   relative to T without following symlinks and rechecks type and identity
   immediately before unlink. Thus an authenticated `keytable_created`
   identity owns the matching file even if it is complete and the crash
   preceded the digest journal update.
5. **Interrupted journal rewrites:** `vault.journal.tmp` is never owned by its
   name. After the canonical journal authenticates, promote a temp only if it
   independently authenticates with the same init key, has identical immutable
   fields and is the same phase or its one permitted successor. Incomplete,
   invalid, divergent or skipped-phase temps are unauthenticated residue.
6. **Owner-confirmed residue:** after authenticating the canonical journal,
   pvault may offer only otherwise-unauthenticated regular files at the exact
   protocol locations `keytable.1.pv.tmp`, `keytable.1.pv`, `vault.hdr.tmp`,
   and `vault.journal.tmp`. Display relative name, platform identity and byte
   length. Deletion requires `DELETE INIT LEFTOVERS
   <first-8-hex-of-setup_id>`, followed by a no-follow reopen that matches the
   displayed type, identity and length. The name only defines the offer set;
   it never authorizes deletion. Decline, non-interactive use, missing/wrong
   passphrase, changed/unverifiable identity or length, or an inability to
   perform the reopen leaves the canonical journal and init blocked. Symlinks,
   directories, special files and other names are never offered or deleted;
   the owner must handle them manually. Lock files remain; external cards use
   `cards.cbor`.
7. **Bound restart:** resolve the journaled index first. On a matching TPM,
   verify the token and both permitted Names and then clean files. If the
   original TPM is unavailable, retain the journal and every artifact and
   leave init blocked; there is no authenticated old core in which to track a
   remote init index. No filename-only cleanup is allowed.
8. **Create-before-identity window:** a temp created before the identity phase
   becomes durable is not automatically owned, nor is a final key table with a
   `prepared` journal. It requires the exact confirmation above or leaves init
   blocked. A malformed/unauthenticated journal authorizes no deletion. If the
   canonical journal is absent, a `vault.journal.tmp` or other init-looking
   artifact has no authenticated ownership root: it is not promoted or offered
   for automatic cleanup, and init remains blocked until manual owner removal.

The full restart state table is normative in spec 8.3 and mirrored in
`docs/M3_READINESS.md` D6.

**Remaining uncertainty:** the platform file-identity limits recorded in spec 8.1 (identity cannot be verified after a move or restore; that case is confirmation or block, never deletion). Author approval of the whole safe-init protocol is still required.

**Readiness-audit revisions (2026-10-05, for review):**
- **File identity is revised** to Unix `st_ino || birth time` (20 bytes), compared on the same `st_dev` as the held directory, and Windows volume serial `|| FileId || CreationTime` (32 bytes). The draft's `st_dev || st_ino` changes across reboots for btrfs subvolumes and removable media, and is open to inode reuse.
- **Per-platform support and refusal rules** (spec 8.1) are decided at run time: Linux `statx` mask with `STATX_INO` and `STATX_BTIME`; macOS a non-zero `st_birthtimespec`; Windows `FileIdInfo` and `FileBasicInfo`. Unsupported means a preflight refusal; a failure at creation stops before any byte; a failure or mismatch at restart deletes nothing.
- **The identity is not universally unique.** HFS+ has one-second creation dates; macOS and Windows let writers set creation times; ReFS ID reuse is undocumented. It prevents deletion by name and accidental confusion, not attacks by local writers to the vault directory, which 8.4 already puts out of scope.
- **The committed header** is accepted by digest and MACs; `header_file_id` only owns `vault.hdr.tmp` residue.
- **The same identity handoff applies to transition artifacts** (SI-40).

**Approval needed:** the four-phase protocol, identity encoding, confirmation
phrase and block cases. These are recommendations, not approvals.

**Affected:** Milestones 3 (journal schema) and 4; F26, F59, F60, F69.

### SI-39 Journal schemas — Accepted

*Re-evaluated "Decision: No".* Accepted, with the exact schemas in 8.1. Two parts remain open:
- the proposed init phases/identity fields of SI-38, the explicit expected-core
  digests and `rollback_tracking` state of SI-35, and the encrypted
  TPM-identity-token fields of SI-36;
- the Revoke and Erase schemas, deferred to the Milestone 8 review.

**Affected:** Milestone 3; F27, F71.

### SI-40 Leftover files in a live vault — Pending (design)

*Re-evaluated "Decision: No". The author moved it to design.*

**Proposal — authenticated ownership, checked after an unlock:**

| File | Deleted when |
| --- | --- |
| `keytable.<g>.pv`, g ≠ current | It decrypts and verifies under the current bundle with `context = g` (ownership proven by AEAD), or an authenticated journal names it. |
| `objects/<id>.pv` not in the current key table | Its `file_id` is listed in a present, authenticated older or uncommitted key table, or in an authenticated journal. |
| `*.tmp` | An authenticated journal names it, or (objects) its ID is listed in an authenticated uncommitted `keytable.<g+1>.pv`. |
| Anything else | **Reported only.** It may be deleted after the owner confirms an exact list, and only for regular files opened without following symlinks under the vault-directory handle. Never directories. |

**Reordering so crashes leave authenticatable leftovers:**
- **`add`:** generate the ID and keys → write `keytable.<g+1>.pv` (with the new entry) → write the object (tmp → flush → rename) → commit → delete the old key table.
- **`rm`:** write `keytable.<g+1>.pv` (without the entry) → commit → delete the **object** → delete the old key table. The old table therefore keeps authenticating the object until the object is gone.

**Proposed test:** F89, crash injection at each step of the reordered `add` and `rm`, checking that every leftover is either authenticated and deleted or reported.

**Remaining uncertainty:** the confirmed deletion of unauthenticated files is an owner decision on a listed set. That is acceptable under "no deletion by pattern alone", but it needs the author's agreement.

**Schema impact found by the readiness audit (2026-10-05).** The transition part of this issue cannot wait for Milestone 4 or 6:
- Abandoned transition artifacts were "authenticated" by nothing. `keytable.<new_gen>.pv` is under the new bundle, which an old-side restart does not have, and the earlier rule deleted it by name.
- The proposal (spec 8.1, `docs/M3_READINESS.md` D6 audit item 1) journals the identities `target_kt_*`, `header_*`, `track_kt_*` and `track_hdr_*` before any bytes are written, and adds `old_keytable_digest`, so that `keytable.<old_gen>.pv` is deleted only on a content match.
- These are journal **fields**, so they must be decided before Milestone 3.
- `add` and `rm` stay schema-free only if ownership remains AEAD-based (object IDs listed in an authenticated key table). Identity handoff for objects would add an `add` journal record.

**Approval needed:** the rules and the reordering.

**Affected:** Milestones 3 and 4; F25, F26.

### SI-41 Message table — Accepted (modified)

*Re-evaluated "Decision: No".*
- **Change from the first proposal:** header parse failures print `Unlock failed.` (required by F7). Structural details go only to `status` and to `fsck` without unlock.
- **Table:** 5.8.
- **Remaining uncertainty:** the exact message wording, to be finalized in `docs/CLI.md`.

### SI-42 Owner authorization and bound duress — Accepted + Pending (design)

- **Accepted (applied):**
  - `tpm-harden` is removed.
  - pvault never sets owner authorization, and prompts for an externally configured one when it must define or delete an index.
  - Bound duress is available only when deletion needs no prompt; otherwise it is reported as unavailable and never promised.
- **New evidence:** `TPMA_PERMANENT.inLockout` is defined as "commands that require authorization with other than Platform Authorization or Lockout Authorization will not succeed". DA lockout therefore also blocks owner-authorized deletion: an attacker can disable bound duress by triggering lockout. Documented in 9.3.
- **Capability checks prepared for review** (all via `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`):

  | Check | Property |
  | --- | --- |
  | C1 | `TPM_PT_PERMANENT & 0x00000001` (`ownerAuthSet`) == 0 |
  | C2 | `TPM_PT_STARTUP_CLEAR & 0x00000002` (`shEnable`) == 1 |
  | C3 | `TPM_PT_PERMANENT & 0x00000200` (`inLockout`) == 0 |
  | C4 (only if SI-36 is adopted) | `TPM_PT_STARTUP_CLEAR & 0x00000004` (`ehEnable`) == 1 and `TPM_PT_PERMANENT & 0x00000002` (`endorsementAuthSet`) == 0, so `ek_digest` can be measured without a prompt |

  | When | Behavior |
  | --- | --- |
  | `duress set` (bound) | C1 to C3 (and C4, if adopted) must hold, or the command is refused. |
  | `status` | Reports each check. |
  | Duress match | Evaluate C1 to C3. (C4 is already implied by the match: without the measurement there can be no match.) If any fails, make no deletion attempt and return `Unlock failed.`. If the undefine itself fails (the state changed after the check), treat duress as unavailable, with the same output. |
- **Open question:** should an owner's ordinary unlock warn when a configured duress tag has become unavailable? A warning shown during a coerced unlock would reveal that duress exists. The recommendation is to report it in `status` only.
- **Affected:** Milestone 5; F81.

### SI-43 Erase confirmation — Accepted (modified)

- **Resolution:**
  - Confirmation `ERASE <folder basename> <first 8 hex digits of vault_id>`.
  - Erase deletes only authenticated vault files: objects listed in the authenticated key table, the current key table, the header and the journal.
  - It never deletes unrelated files, never recurses, and never removes the directory.
- **Remaining uncertainty:** the length of the ID prefix. 8 hex digits is proposed.
- **Affected:** Milestone 9; F84.

### SI-44 K2 — Pending (design, Milestone 8 review)

- **Applied constraints:**
  - No self-escalation.
  - No privileged helper or override without review.
  - The firmware step is never executed in tests.
- **Proposals for the review:**
  - **Platform support:** Linux only in v1; macOS and Windows report "unsupported".
  - **Privilege boundary:** the device step needs root. pvault never calls `sudo` or `pkexec`; the owner must start K2 explicitly with privileges. Open: whether running the file-level vault Erase as root is acceptable, given that the per-user records then belong to root. The alternative is a two-invocation flow, which would itself need review.
  - **Test coverage:**
    - **Mocked `DeviceBackend`:** classification (NVMe, SATA SSD, HDD, USB/SD), refusal of system or mounted devices, dry-run output, the countdown and cancellation (F49), and partial-failure reporting.
    - **Loopback images** (Linux CI with `sudo`): overwrite plus sample verification, and the unmount-failure message.
    - **Hardware:** never.
  - **Partial-failure reporting:** a per-stage report covering each vault (erased, or failed with the reason), the unmount (the spec's exact message on failure), and the device method (not started, completed, or failed, with a summary of the tool's status). No success text for a stage that did not complete.
  - **Unauthenticatable vaults** (another laptop's bound vault, an unknown passphrase): K2 refuses. There is no override.
- **Affected:** Milestones 8 and 10; F43, F49.

### SI-45 Mount — Pending (design, before Milestone 11)

**The problem under the current AAD:** every chunk's AAD binds `plain_size` and `chunk_count`. A final object can therefore be encrypted only once its size is known, which rules out unknown-size streaming and in-place random writes.

**Proposal for review:**
1. **Overlay:** each file opened for writing gets an **encrypted overlay**. Written regions are kept as chunk-sized records, encrypted with XChaCha20-Poly1305 under an **ephemeral key held only in memory**. They stay in memory up to a cap, or spill to `objects/<new_id>.pv.overlay`, which is ciphertext only.
2. **Close or `fsync`:** compose the final object chunk by chunk, taking overlay chunks where present and decrypting the original object's chunks elsewhere. The final size is now known, so the object is encrypted under fresh `fk_*` keys and a new `file_id`. Then commit (new key table) per 7.7 and 8.3.
3. **Crash:** the overlay key is lost, so the overlay is undecryptable garbage, and is handled under SI-40 rules (reported, or deleted on confirmation). Plaintext never reaches disk.
4. **Rejected for now:** changing the AAD to drop `plain_size`. That would be a format change needing review.

**Other open points:**
- `fuser` with FUSE-T on macOS: untested; it needs a feasibility spike.
- A WinFsp binding crate needs approval.
- Sleep and lid detection need a dependency per platform (`zbus`, IOKit bindings, Windows power notifications), each needing approval.
- Behavior when an upgrade is busy (SI-14 step 5).

**Affected:** Milestone 11; F56b.

### SI-46 Card milestone — Accepted

- **Resolution:** `card.rs`, its vectors, PNG input, card files, F61 and F65 (portable parts) move to Milestone 4. The bound-card parts stay in Milestone 5.
- **Remaining uncertainty:** none.

### SI-47 CLI document — Accepted

- **Resolution:** `docs/CLI.md` is drafted and approved before Milestone 4.
- **Remaining uncertainty:** its content, which is the author's review.

### SI-48 Failpoints — Accepted

*Re-evaluated "Decision: No".* Accepted, with the release guard made explicit:
- The `fault-injection` feature is non-default.
- The release build refuses it (a `compile_error!` under `cfg(all(feature = "fault-injection", not(debug_assertions)))`, or a build-script check).
- CI scans release artifacts for failpoint names (F85).

**Remaining uncertainty:** the exact mechanism is chosen in Milestone 3.

### SI-49 Guarantee table — Accepted

*Re-evaluated "Decision: No".* Accepted: two rows added ("copy + one card"; "copy + passphrase + card", readable in bound mode), plus the crash-safety statement in Section 2.

### SI-50 Minor items — Accepted

*Re-evaluated "Decision: No"*, item by item:
- `clean-partials` is the only spelling (7.9). It also cleans stale card records.
- F17 is defined precisely.
- The `partials.cbor` and `cards.cbor` path metadata is documented.
- The rollback record (`rollback.cbor`) format, locking and limits are defined (9.7). *Refined 2026-10-05:* the 9.7 "map from `vault_id`" conflicts with the 4.4 text-key rule; the proposed entry-list schema is in `docs/M4_READINESS.md` section 7.4.
- `fsck` wording for other vaults' indices: to be handled in `docs/CLI.md` (the message wording).
- The layout gains `platform/`, `lock.rs`, `partials.rs` and `paths.rs`. `pvault-app` stays out of `default-members` until Milestone 14.
- TPM randomness mixing is **off by default** (7.1).


### SI-51 Passphrase options — Accepted (final design); metadata schemas pending

**Decisions (author, 2026-10-04):**
- **Main passphrase:** two options, generated (user-selected word count) or **custom** (user-written), available in both bound and portable modes.
- **Duress passphrases:** **generated only**, fixed at 12 words (clarification 3).
- **Estimator:** `zxcvbn = "=3.1.1"` is **approved**, for creation-time use in a child process only, with the documented memory limitations. The bands 10^14 and 10^18 are **provisional product policy**. Results are always labeled "Estimated".
- **Terminal input:** bounded terminal input replaces `rpassword`. The 7.6a scope is extended narrowly to terminal input and echo control.
- **Pending:** the metadata schema changes stay pending until the exact schemas are reviewed.

**Final approval (author, 2026-10-04), with these clarifications.** Where the text below differs, the clarification wins, and the text has been corrected:
1. **Main generated passphrases:** selectable 10–16 words, default 12.
2. **Main custom passphrases:** as specified, with creation-time estimation only.
3. **Duress passphrases:** generated only, **fixed at 12 words** for now (not selectable).
4. **Verification-only authentication** (5.5) skips the duress check **and the duress-only Argon2id derivation**.
5. **"Collision"** means that the actual main credential, after generated-word processing, equals the generated duress credential: `H_w(main input) == duress words`. It is checked at setup and whenever either credential changes. It does not imply checking every possible input.
6. **Signal and console handlers** must use platform-safe operations. Terminal restoration is tested after cancellation and errors.
7. **Timing:** two derivations do not establish timing equivalence. The complete paths are measured at the applicable later milestones.

**Milestone 2 implements** sections 1 (handling, generation, collision rule), 3, 4 and 5 and the tests in section 9 that need no vault. Header, journal and lifecycle work (sections 2, 6 and 7) is not implemented. See Section 10 of this file.

#### 1. Credentials and handling

| Credential | Kinds | Handling (derivation input) | Limits |
| --- | --- | --- | --- |
| Main passphrase | `words` (generated) or `custom` (user-written) | `words`: H_w = NFKC → trim → collapse whitespace runs to one U+0020 → Unicode lowercase (7.3). `custom`: H_c = NFC only (section 3) | Raw input ≤ 1,024 bytes. H_w output ≤ 1,024 bytes. H_c output 1–256 bytes |
| Duress passphrase | `words` only, fixed at 12 words | H_w | As for `words` |

- **Generated `words` credentials** (main or duress): 10 to 16 words, default **12**. Each word is drawn uniformly (`getrandom` with rejection sampling). Creation shows the word count and the **calculated classical entropy**, `n × log2(7776)`: 129.2 bits for 10 words, 155.1 for 12, 206.8 for 16.
- **Policy ratings** for generated passphrases: Medium for 10–11 words, Strong for 12–16. These are policy ratings, not guarantees. The effect of quantum search (A2) is explained only in documentation.
- **Derivation:** `master = Argon2id(handled bytes, core.salt, core.argon2_m/t/p)`; subkeys as in 5.1.
- **Main kind `words`:** the duress passphrase uses the same handling, so **one** Argon2id run serves both the main keys and `duress_key`, as in spec 7.2.
- **Main kind `custom`, with a duress tag present:** two derivations in this fixed order on every unlock whose input generated-word handling accepts (see the N3 exception below):
  - (1) `master_main = Argon2id(H_c(input), …)` gives the main keys;
  - (2) `master_duress = Argon2id(H_w(input), …)` gives `duress_key` for the tag check.

  The runs are **sequential**. Each run's block buffer is wiped and freed before the next starts, so **peak memory stays one `argon2_m` buffer** (the 4.3 resource check applies to each run). Both runs happen even when H_c and H_w give identical bytes. That alone does **not** establish timing equivalence; the complete paths are measured later (clarification 7).
- **Exception (decision N3, 2026-10-05):** if generated-word handling refuses the typed input, the duress check is a non-match and run (2) is skipped. The refusal classes are an empty result after trimming, more than 1,024 bytes after NFKC, and, under the proposed `H_w_v1`, a code point unassigned in Unicode 17.0.0. Such input can never equal the generated duress words. The unlock then runs one Argon2id. A timing observer learns only that the typed text is in a refused class; for the correct passphrase, that is a property of the passphrase. The full statement is in spec 5.6.
- **Verification-only authentication** runs only the main derivation, H_c for a custom main. It skips the duress check and the duress-only run (clarification 4).
- **Collision rule** (clarification 5): a collision is `H_w(main input) == duress words`, the actual main credential after generated-word processing equal to the generated duress credential. That is exactly when typing the main passphrase would also match the duress tag, because the duress derivation always uses H_w. It is checked at duress setup and whenever either credential changes. The main passphrase is available at those moments, because `duress set` requires an ordinary unlock. (The earlier draft also compared `H_c(main input)`; that comparison is irrelevant to the duress tag and was dropped.)

#### 2. What runs at creation and what runs at unlock

| Step | Creating or replacing a main credential (`init`, portable recovery, `recover --to-portable`, `convert` bound → portable) | Duress setup or replacement (`init` step, `duress set`, recovery/convert choice 6.7-2) | Unlock, verification, and recovery that keeps the passphrase |
| --- | --- | --- | --- |
| Bounded input read (section 4) | Yes (custom: entered twice) | Type-back once | Yes, once |
| Generation, word count and entropy display | `words` only | Yes | No |
| Custom character rules (refuse and warn) | `custom`: yes, with warnings shown | n/a | `custom`: the refusal rules apply. Invalid input gets a specific, input-only message, before any Argon2id |
| NFC notice (section 3) | `custom`: shown if NFC changed the input | n/a | No |
| Confirmation (constant-time on handled bytes) | Yes | Yes | No |
| **Estimator (child process)** | **`custom` only.** On failure, **the new custom credential is refused** (retry, or choose generated) | **Never** | **Never** |
| Word-list check (input only) | Type-back of `words` | Type-back | Only when the main kind is `words` |
| Collision rule | When a duress tag exists | Yes | No |
| Argon2id runs | 1 (new salt) | 1 (`words` main) or 2 (`custom` main) | 1, or **2** for a `custom` main with a duress tag (1 if generated-word handling refuses the input; N3) |

Estimator failure never affects access to an existing vault, because the estimator does not run when an existing passphrase is used.

**Expected unlock cost** (default Argon2id 1 GiB, t = 4, p = 4, single-threaded; measured on Apple M4 at **1.95 s per run**, including pvault's allocation and wipe):

| Vault | Argon2id runs | Approximate time (M4) | Peak Argon2 memory |
| --- | --- | --- | --- |
| `words` main, with or without duress | 1 | ≈ 2.0 s | 1 GiB |
| `custom` main, no duress | 1 | ≈ 2.0 s | 1 GiB |
| `custom` main, with duress | 2 (1 if generated-word handling refuses the input; N3) | ≈ 3.9 s (≈ 2.0 s for refused input) | 1 GiB (sequential) |

The bound-mode TPM work (salted session, `NV_ReadPublic`, `NV_Read`) is extra and not yet measured (Milestone 5). Key-table decryption runs at about 720 MiB/s. Slower machines scale proportionally.

#### 3. Custom input rules (H_c)

- **Line boundary (all input):** a line ends at the first LF (U+000A). One CR immediately before it is removed as part of a CRLF line ending. Nothing else is removed.
- **Order:** raw ≤ 1,024 bytes → valid UTF-8 → **Unicode NFC** (pinned `unicode-normalization`) → checks → 1 to 256 bytes.
  - **No** trimming, lowercasing, whitespace collapsing or NFKC.
  - **Permitted spaces are preserved exactly:** leading, trailing and repeated.
- **Refused** (message names the problem; nothing is silently altered):
  - an empty result;
  - C0 controls U+0000–U+001F (including tab, LF, CR and ESC);
  - DEL (U+007F) and the C1 controls U+0080–U+009F (including NEL);
  - U+2028 and U+2029;
  - the bidirectional controls U+061C, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069;
  - U+FEFF;
  - the noncharacters U+FDD0–U+FDEF and U+xFFFE / U+xFFFF;
  - more than 256 bytes after NFC.
- **Allowed with a warning at creation** (the warning names the character kind and position):
  - leading or trailing whitespace from U+0020, U+00A0, U+1680, U+2000–U+200A, U+202F, U+205F, U+3000;
  - the invisible characters U+200C, U+200D, U+2060 and U+00AD.
- **NFC notice before confirmation:** if NFC changed the bytes, pvault explains this before the confirmation prompt: "pvault stores Unicode text in its standard composed form (NFC). Some characters you typed were converted to that form. They look the same, and typing them the same way will work." The confirmation entry goes through the same handling, and the comparison is in constant time on the handled bytes.
- **Limitation, now a blocker (M2-F4, 10.7):** code points unassigned in the pinned Unicode version are allowed. A later Unicode version could compose them differently, so the normalization crate is pinned, with a regression test using fixed NFC vectors.

#### 4. Bounded terminal input (replaces `rpassword`; 7.6a scope extended)

- **Buffers:** a pre-allocated, zeroize-on-drop raw buffer of 1,024 bytes. The rest of an over-long line is discarded one byte at a time, each byte wiped. Nothing grows. (As implemented; the draft said 1,025 bytes plus a scratch buffer.)
- **Unix (Linux, macOS):**
  - **Opening:** open `/dev/tty` (`O_RDWR | O_NOCTTY | O_CLOEXEC`). No controlling terminal → refused, unless `--secrets-stdin` is given.
  - **Echo off:** save the `termios` settings with `tcgetattr`, then clear `ECHO` (keeping `ICANON` and `ISIG`, so line editing and Ctrl-C still work) and set `ECHONL`, so the newline is still shown.
  - **Reading:** `read()` into the fixed buffer until LF. If a 1,025th byte arrives before an LF, the rest of the line is drained and discarded, and the input is refused ("too long"). EOF before any byte means cancellation.
  - **Restoring the terminal:**
    - A guard restores the saved `termios` on normal return, on errors, and during panic unwinding (the release profile keeps unwinding).
    - Signal handlers for SIGINT, SIGTERM, SIGHUP and SIGQUIT are installed for the duration of the read (`sigaction`). A handler restores `termios` (`tcsetattr` is async-signal-safe), restores the default disposition, and re-raises the signal.
    - SIGTSTP is ignored during the read, so the process cannot be suspended with echo off.
    - The previous dispositions are restored afterwards.
    - **SIGKILL, or a crash before the guard runs, cannot be handled.** The terminal may then be left without echo; the documented remedy is `stty sane` or `reset`.
- **Windows:**
  - **Opening:** open `CONIN$` and `CONOUT$` (`CreateFileW`). No console → refused, unless `--secrets-stdin` is given.
  - **Echo off:** save the mode with `GetConsoleMode`, then clear `ENABLE_ECHO_INPUT`, keeping `ENABLE_LINE_INPUT` and `ENABLE_PROCESSED_INPUT`.
  - **Reading:** `ReadConsoleW` into a fixed UTF-16 buffer of 1,025 units, converted into the fixed UTF-8 buffer. Lone surrogates are refused. The UTF-16 buffer is wiped. Over-long input is handled as on Unix.
  - **Restoring the console:** a guard restores the mode, and a `SetConsoleCtrlHandler` handler restores it on Ctrl-C, Ctrl-Break and close events, then returns `FALSE` so default handling continues. `TerminateProcess` cannot be handled; this is documented.
- **`--secrets-stdin` (explicit only):**
  - **Refused when stdin is a terminal**, because echo cannot be controlled there.
  - Secrets are read one per line, in prompt order, into the same fixed buffer.
  - A line over 1,024 bytes refuses the whole command, and no further secrets are read. EOF ends a non-empty final line; EOF with nothing read is a cancellation.
  - Secrets are never taken from argv or environment variables.
- **Residual (document):** the terminal driver, console host and pipe buffers hold copies that pvault cannot wipe.
- **7.6a scope extension (approved):** terminal input and echo control only:
  - `open` / `tcgetattr` / `tcsetattr` / `read` on `/dev/tty`;
  - `sigaction` for the signals listed above;
  - Windows `CreateFileW` (`CONIN$` / `CONOUT$`), `GetConsoleMode`, `SetConsoleMode`, `ReadConsoleW` and `SetConsoleCtrlHandler`.

#### 5. Estimator (creation of a custom main passphrase only)

- **`zxcvbn = "=3.1.1"`, `default-features = false`.** It is linked into the pvault binary but **called only inside the estimator child process**.
- **Child process:**
  - **Launch:** a re-exec of pvault's own binary (on Linux via `/proc/self/exe`) with one fixed marker argument, a cleared environment, stdin and stdout as anonymous pipes, and stderr discarded.
  - **Hardening before reading anything:** core dumps off (10.3), `RLIMIT_CPU` 5 s, and Linux `RLIMIT_AS` 512 MiB.
- **Transport:** the handled secret is transmitted **locally through an anonymous pipe**. It is **never sent over the network**, and never placed in argv, environment variables or files. The frame is a length prefix plus H_c bytes, followed by the non-secret context (the vault folder name). The child reads into a fixed, wiped buffer sized for the largest frame (514 bytes: 2 + 256 + 1 + 255).
- **Reply:** at most 64 bytes: a format version, `guesses_log10 × 100`, a warning code and suggestion codes.
  - These numbers and codes are **derived from the input**, which is inherent to an estimate, but they **never contain the input or any part of it**.
  - The parent maps the codes to fixed texts.
- **Timeout:** 5 s wall-clock, after which the child is killed and reaped. Any failure (spawn, timeout, non-zero exit, malformed reply) **refuses the new custom credential**. Existing vaults are unaffected.
- **Bands (provisional product policy, not validated security boundaries):**
  - **Estimated weak** (< 10^14): refused, with suggestions.
  - **Estimated medium** (10^14 to < 10^18): accepted after typing `ACCEPT MEDIUM PASSPHRASE`.
  - **Estimated strong** (≥ 10^18): accepted.
- **Every result carries this warning:** "Estimated only. Famous quotations, song lyrics, book or film lines, and well-known phrases can receive falsely high ratings." The measurements behind it: seven famous phrases all hit the 2^64 ceiling, and random character strings are underestimated (section 2 of revision 2's evidence, kept below).
- **Memory limitation (documented):** the child's heap copies, made by `zxcvbn`, and the kernel pipe buffers are not wiped. Process exit does not guarantee erasure from RAM, swap or hibernation files.

#### 6. Lifecycle

| Operation | Main passphrase | Duress |
| --- | --- | --- |
| `init` | Owner chooses `words` (10–16, default 12) or `custom` (estimator) | Optional generated duress (12 words), with the collision rule |
| Bound recovery (passphrase + card), `convert` portable → bound | **Kept**, so the kind is preserved. No estimator | 6.7: re-enter the existing one (verified against the old tag with the old salt, then re-tagged), generate a new one, or disable |
| Portable recovery, `recover --to-portable`, `convert` bound → portable | **New**; owner chooses the kind. A `custom` choice runs the estimator. A warning states that a portable custom passphrase is the only barrier | As above, with the collision rule against the new main passphrase |
| `duress set` / `duress disable` | Unchanged (ordinary unlock) | Generated only; collision rule |

#### 7. Metadata (PENDING; exact schemas for review before Milestone 3)

- **`CoreFields.passphrase_kind`:** a text value, exactly `"words"` or `"custom"`, required. It is covered by `core_mac`. Any other value is a parse failure, giving `Unlock failed.`.
- **No duress kind field:** duress is always `words`, so the duress-tag formula is unchanged.
- **Init journal (`op: "init"`):** gains `passphrase_kind` (same values), covered by the journal MAC.
- **Recovery and convert journals:** no field is needed. The new kind is in the new core, and the old kind in the old core.
- **Not stored:** the word count, the estimated band, or anything estimator-related.
- **Behavior when a kind field is tampered with:**

  | Tampering | Result |
  | --- | --- |
  | `passphrase_kind` changed in the header | Wrong handling, or (even if the handled bytes are equal) a changed core, so `core_mac` fails. **`Unlock failed.`** Recovery also fails, since it verifies `core_mac`; this is the same F7 class as any core corruption |
  | Changed from `custom` to `words` | The input may also be refused early by the word-list check, with "Word N is not in the word list". That message depends only on the typed input and the (tampered) public header, so it reveals no secret. `status` and `fsck` without unlock report the header kind as unauthenticated |
  | An unknown kind value | Parse failure, giving `Unlock failed.` |
  | The init journal's kind | Journal MAC failure: reported, never acted on (8.1) |
  | Anything in the duress tag | The tag binds the duress fields as in 9.6. A tampered tag simply never matches |
- **Visible to an attacker (document):** the header reveals whether the main passphrase is custom.

#### 8. Security claims

- **Generated passphrases** (main and duress, 10 to 16 words) satisfy A3. The conditional guarantees are unchanged.
- **Custom main passphrases:**
  - Strength is **estimated** only. They do **not** establish A3, and **no 50-year or quantum-resistance target applies.**
  - Offline-guessing resistance depends on how unpredictable the chosen text really is.
  - **Portable plus custom** is the weakest combination: the passphrase is the only barrier.
- **Offline guessing:** possible in these situations, each costing one full Argon2id run per guess:

  | Kind of vault | What an attacker needs | What a guess is checked against |
  | --- | --- | --- |
  | Portable | A copy of the vault | The slot and the MACs |
  | Bound | A copy plus the card | S1 + S3, then `core_mac` |
  | Bound | A copy plus an extracted TPM share | `tpm_auth`, or the S2 wrap |
  | Either | A copy with a duress tag | The tag, for the generated duress passphrase only |
  | Either | A leftover init journal | Its MAC |

  A copy of a bound vault alone remains infeasible to attack.
- **Persistence:**
  - pvault never **intentionally persists** a passphrase, its handled forms, or any estimator input, intermediate data or result. Nothing goes to disk, logs, configuration, journals, headers or error messages.
  - **Temporary in-memory copies exist.** pvault-owned buffers are wiped. Library internals, the estimator child, terminal and console drivers, and kernel pipe buffers are not.
  - Those copies can reach persistent storage only through swap, hibernation, or crash dumps if the 10.3 protections fail.
- **Proposed A3 wording:** "A3 (generated passphrases, main and duress): generated by the tool, at least 10 EFF words, not disclosed. Custom main passphrases: no assumption; strength is estimated only."

#### 9. Tests (Milestone 2, plus Milestone 3 for the metadata)

- **Generated mode:**
  - unbiased sampling;
  - the 10–16 range with 12 as the default;
  - the entropy figure;
  - type-back.
- **Custom mode:**
  - every refuse and warn rule;
  - NFC/NFD equivalence and the NFC notice;
  - spaces preserved and exact confirmation required;
  - the 1,024 and 256 limits.
- **Estimator:**
  - runtime on adversarial 256-byte inputs under the 5 s timeout;
  - the reply contains no input bytes;
  - failure refuses the new credential, and existing vaults still unlock;
  - the estimator is never invoked during unlock (an instrumentation test).
- **Duress:**
  - the collision rule;
  - two-run unlock for a custom main with duress, in order, with the buffer wiped between runs.
- **Terminal and stdin input:**
  - the bounded-read state machine, tested through an injected reader;
  - `--secrets-stdin` refused on a TTY;
  - over-long lines refused.
- **Metadata (Milestone 3):** a tampered kind gives `Unlock failed.`

**Supporting evidence:** `zxcvbn` 3.1.1, scratch probe, 2026-10-04.

| Input class | Examples | Estimated guesses (log10) |
| --- | --- | --- |
| Famous phrases, quotes, lyrics | "correct horse battery staple"; "to be or not to be that is the question"; "the quick brown fox jumps over the lazy dog"; "never gonna give you up…"; Genesis 1:1; "may the force be with you"; "i love you forever and always" | **19.27, the ceiling, every time** (false positives) |
| Patterned passwords | `P@ssw0rd2026`, `Password123!Password123!`, `JohnSmith1985!`, `MyVaultPassword2026`, keyboard walks, repeats | 1.7–11.2 (caught) |
| Random characters | 10, 16 and 19 characters | 10.0, 16.0 and 19.0. **Underestimated:** it counts about 10 guesses per character |
| Worst-case runtime at 256 bytes | Nine adversarial shapes | ≤ 265 ms in-process; about 280 ms via the child process |

**Other evidence:**
- `zxcvbn` behavior: published guidance (score 4 means more than 10^10 guesses at 10^4 per second), the 2^64 ceiling, and the measured classification table (famous phrases at the ceiling; patterned passwords caught; random strings underestimated).
- The child-process prototype: 13–18 ms typical, about 280 ms at 256 bytes; the timeout and oversize refusals work.

**Remaining approvals:**
1. ~~The final design as a whole.~~ Approved 2026-10-04, with the clarifications above.
2. The metadata, header and journal schemas in section 7, before Milestone 3.
3. ~~Whether the duress word count should also be selectable.~~ Decided: fixed at 12 for now.
---

## 3. Evidence

### 3.1 MSRV (Rust 1.89.0, installed alongside stable 1.99.0)

- **The current workspace**, as a scratch copy with `rust-version = "1.89"`, ran `cargo +1.89 test --workspace --locked`: all 19 tests pass on macOS. `cargo +1.89 check --all-targets` passes for `x86_64-pc-windows-msvc` and `x86_64-unknown-linux-gnu`.
- **The planned crates**, in a scratch probe resolved with the MSRV-aware resolver, all build and test on 1.89 on macOS. The libraries cross-check on 1.89 for Windows and Linux. Selected versions:

  | Crate | Version | Crate | Version | Crate | Version |
  | --- | --- | --- | --- | --- | --- |
  | aes-gcm-siv | 0.12.1 | chacha20poly1305 | 0.11.0 | chacha20 | 0.10.2 |
  | argon2 | 0.6.0 | hkdf | 0.13.0 | hmac | 0.13.0 |
  | sha2 | 0.11.0 | subtle | 2.6.1 | zeroize | 1.9.0 |
  | secrecy | 0.10.3 | memsec | 0.7.0 | region | 4.0.1 |
  | rand_core | 0.10.1 | getrandom | 0.4.3 | unicode-normalization | 0.1.25 |
  | serde | 1.0.229 | ciborium | 0.2.2 | clap | 4.6.7 |
  | rpassword | 7.5.4 | qrcode | 0.14.1 | rqrr | 0.11.0 |
  | png | 0.18.1 | thiserror | 2.0.21 | directories | 6.0.0 |
  | libc | 0.2.190 | vsss-rs | 6.0.1 | proptest | 1.11.0 |
  | tempfile | 3.27.0 | assert_cmd | 2.2.2 | criterion | 0.8.2 |
- **Cross-check failure:** only `criterion` → `alloca`, whose C build step needs a cross C compiler.
- **Not covered:** `tss-esapi` (needs `tpm2-tss`), `fuser`, Tauri, WinFsp, PQC, and native Linux/Windows test runs.
- **`std::fs::File::lock` / `lock_shared` / `try_lock`:** marked "1.89.0" in the official docs. They correspond to `flock` (Unix) and `LockFileEx` (Windows).

### 3.2 `ciborium` 0.2.2 source

- `de/mod.rs`:
  - `deserialize_bytes`: scratch path, or an error.
  - `deserialize_byte_buf` and `deserialize_string`: growable buffers.
  - Tags are skipped.
  - `from_reader` uses a `[0; 4096]` scratch.
- `ser/mod.rs`: `serialize_bytes` writes directly.
- `ciborium-ll` `hdr.rs`: the encoder chooses minimal heads; the decoder accepts any.
- serde `Unexpected`: `Bytes(_)` prints "byte array"; `Str(s)` prints the string.

### 3.3 `vsss-rs` 6.0.1 source

- `gf256.rs`: a branch-free multiply with `0x1b`; `random_coefficient` is uniform over 0 to 255 (from the low byte of `try_next_u32`).
- `polynomial.rs`: `fill` documents the zero-inclusive coefficients (an audit fix). The polynomial is a plain `Vec` with no wipe on drop.
- `Cargo.toml`: the default features include `bigint`, `curve-serde`, `primitive`, `random-participant-ids`, `std` and `zeroize`.

### 3.4 Primary platform documentation

- **macOS man pages** (local): `fsync(2)`, `fcntl(2)` (`F_FULLFSYNC`), `rename(2)` (crash guarantee, `RENAME_EXCL`, `RENAME_SWAP`, `ENOTSUP`), `flock(2)` (upgrade releases first).
- **man7.org:** `rename(2)` (observer atomicity, `RENAME_NOREPLACE` support list, `RENAME_EXCHANGE`), `fsync(2)` (disk caches, directory fsync), `flock(2)` (conversion not atomic; NFS and CIFS emulation).
- **learn.microsoft.com:** `NtCreateFile` (`RootDirectory`,
  `FILE_OPEN_REPARSE_POINT`, `FILE_WRITE_THROUGH`),
  `FILE_RENAME_INFORMATION` (`RootDirectory`-relative destination), CreateFile
  caching flags (NTFS metadata flush for a write-through rename request),
  `MoveFileExW` (`MOVEFILE_WRITE_THROUGH` copy/delete semantics),
  `FlushFileBuffers` (volume flush needs admin), and `LockFileEx` (no
  overlapping exclusive locks).
- **doc.rust-lang.org (1.89.0):** `std::fs::rename` (Windows uses `MoveFileExW` or `SetFileInformationByHandle`); `File::lock` (re-locking a held handle is unspecified).

### 3.5 TPM constants (`tss-esapi` 7.7.0, `tss-esapi-sys` 0.6.0)

- **`TPMA_NV` bit layout:** see SI-22.
- **Command codes:** `PolicyAuthValue 0x16B`, `PolicyOR 0x171`, `NV_DefineSpace 0x12A`, `NV_UndefineSpace 0x122`.
- **Properties:** `TPMA_PERMANENT_OWNERAUTHSET 0x1`, `INLOCKOUT 0x200`, `TPMA_STARTUP_CLEAR_SHENABLE 0x2`.
- **System library:** `tss-esapi-sys` requires `tpm2-tss` ≥ 2.4.6.

---

## 4. Remaining questions, by the milestone they block

**Before Milestone 1** (the full list, with recommendations, is in Section 8)
1. SI-05: approve MSRV 1.89, the three-OS MSRV CI job, and the timing of toolchain pinning.
2. SI-04: `cargo-deny` in CI (advisories, bans, sources, licenses): **approved and in place** (Milestone 1).
3. Section 8: the RNG source (`rand_core` 0.10 has no `OsRng`), the test-vector sources, the crypto crate versions, and Milestone 0.5 closure.

**Before Milestone 2**
3. SI-04: the license is decided (`GPL-3.0-only`).
4. SI-06 / SI-51: **decided: both**. Generated main passphrases are 10–16 words, default 12.
5. SI-08: **decided: option 1** (`vsss-rs` `=6.0.1`, pvault-owned zeroizing storage).
5a. SI-04: wordlist **decided**: CC BY 4.0, original asset unmodified, attribution (applied in Milestone 2).
5b. SI-51: **final design approved** (2026-10-04); the duress word count is fixed at 12. The metadata schemas are reviewed before Milestone 3.

**Before Milestone 3**
5c. SI-51 section 7: approve the exact header and journal schema changes (`passphrase_kind` and the init-journal field).
5d. SI-51 / M2-F4: approve a stable normalization-version policy for custom credentials (10.7). **Blocks the Milestone 3 schema review.**
6. SI-07: `ciborium` with restrictions and a codec fallback for the key table, or the fixed-schema codec.
7. SI-12: W1 and its limitation wording are selected. Approve the remaining
   durability table and confirm the exact file-system allowlist/detection.
8. SI-14: approve the lock protocol (gate and mount locks, bounded retries).
9. SI-35 / SI-38 / SI-40: approve the handle-allocation protocol, explicit
   old/new/tracking core-digest binding and `slots_mac` recomputation,
   four-phase identity-owned safe `init`, confirmed-residue block rules, and
   the live-vault `add`/`rm` reordering.
10. SI-36: approve the exact five-scope encrypted TPM-identity-token mechanism,
    fixed H-2 EK template, 32-entry cleanup list and duress integration. The
    earlier keyed `tpm_id_mac` proposal is superseded because it cannot be
    rekeyed remotely. P1 is selected separately and needs no further v1 choice.
11. SI-30 / SI-07: confirm the key-table entry layout, the path limits and the decode-time versus input-time check split (F73 now states the split). The **case-folding source** moves to "Before Milestone 4" if the split is approved.
11a. SI-07: approve the path classification (confidential, zeroized, not locked) and the proposed 5.8 message "The key table is damaged."
12. ~~SI-06: confirm the wizard default.~~ Moved to "Before Milestone 14": the desktop wizard is its only user (spec 16 item 3).
13. SI-16: confirm the 64 MiB resource margin and the per-platform definitions (D8).
14. Readiness-audit decisions N1 to N5 (10.9):
    - N1 (decided): W1's risk boundary remains selected; its primitive name is amended to the required handle-relative NT rename. Windows power loss can break a vault, with WO-1 to WO-3 documented as unverified;
    - N2 (decided): bound creation without a measurable EK identity is refused, and portable mode is offered;
    - N3 (decided): a refused generated-word candidate is a duress non-match, and its run is skipped;
    - N4 (decided): the scope-4 redundancy, removed;
    - N5 (decided): the 65,536-entry vault limit (files and directories); exceeding it leaves the vault unchanged.
15. Transition artifact identities, `old_keytable_digest` and `tracking_created` (SI-35, SI-38 and SI-40 schema impact), and the revised file-identity encoding.

**Before Milestone 4** (status 2026-10-05; details in `docs/M4_READINESS.md`)
13a. SI-30: case folding and path input. **Approved:** vendored Unicode 17.0.0 canonical caseless matching, NFC input normalization and refusal of unassigned characters (M4_READINESS section 8).
13b. Windows console interactive validation (M2-F7). **Approved as a manual acceptance gate** (checklist in M4_READINESS section 14); not yet performed.
14. SI-10: card-file lifetime lock and cleaner. **Approved (A6):** no terminal display of card text; completed lifecycle and cleaner design in M4_READINESS section 11.
15. SI-11: `--force`. **Decided:** refused throughout Milestone 4; the exchange design stays pending (F90).
16. SI-47 / SI-19 / SI-41: `docs/CLI.md`, including `--secrets-stdin` and the message wording, **approved (A1)**.
17. SI-40: the live-vault `add`/`rm` protocol. The `update` journal record and 8.4 exception in M4_READINESS section 9 are **approved (A3/A4)**. Required by F26.
18. Per-user record schemas (`rollback.cbor`, `partials.cbor`, `cards.cbor`): the entry-list schemas in M4_READINESS section 7 are **approved (A2/A6)**.
19. `add` source files. **Approved (A5):** regular files only; `created_at` = time added; `modified_at` from the source; exact rules in M4_READINESS section 10.
20. Duress in Milestone 4. **Decided:** no duress setup; a duress match fails without mutation (temporary limitation).
21. New dependencies (`qrcode`, `rqrr`, `png`, `directories`) with three crate-specific license exceptions and notices (M4_READINESS section 12) are **approved (A7)**.

**Before Milestone 5**
17. SI-18 / SI-22: approve the TPM pins, the exact public area and the salted-session design, with its trust assumptions.
18. SI-42: approve capability checks C1 to C3; status-only reporting of unavailable duress.
19. SI-32: confirm the duress-setup draft (6.10).
20. SI-06 PCR is closed for v1: P1, nonce-policy only. Any PCR binding is a
    future reviewed format revision, not a Milestone 5 decision.

**Before Milestone 6**
21. SI-31: confirm the `convert` draft (6.9) and its confirmation phrases.
22. SI-29: approve `recover --use-tpm` (the S2 + S3 path) and proposed test F86.

**At the Milestone 8 review**
23. SI-44: platform support, privilege boundary (root and the per-user records), test coverage and partial-failure reporting.
24. Revoke and Erase journal schemas (SI-39); the Erase ID-prefix length (SI-43).

**Before Milestone 11**
25. SI-45: the encrypted-overlay write model, the macOS FUSE-T feasibility spike, and the WinFsp and power-event crates.

**Before Milestone 14**
25a. SI-06: the wizard default mode.

**Before Milestone 13**
26. SI-04: approve `cargo-about` for release notices; SI-05: pin the release toolchain.

---

## 5. Summary of changed security and availability claims (v6 → v7)

**Security**
- **Single-cipher break:** the margin now covers only file and key-table chunks. Key wraps (XChaCha20) and authentication (HMAC-SHA-512) have no second-primitive margin, and no whole-vault claim is made.
- **Bound duress:** conditional. It works only while TPM owner authorization is empty, the storage hierarchy is enabled, and the TPM is not in lockout. An attacker can disable it by forcing lockout. It is reported as unavailable otherwise.
- **Duress visibility:** whether duress is configured can be seen from the header.
- **Portable duress:** does nothing on read-only (unsupported) file systems.
- **Rollback detection:** cannot detect restoration of a pre-Revoke header, and the local record is unauthenticated.
- **Recovery and conversion:** they do not rotate per-file keys. Old cards plus an old copy still decrypt the objects of that time.
- **Old TPM indices:** an index on another machine's TPM is never removed from here. Deletion now also requires the same TPM, with the mechanism pending.
- **Memory:**
  - Locking is best effort, with an optional strict mode.
  - Argon2 memory is never locked and can reach swap.
  - Windows core-dump suppression is best effort.
  - Linux non-dumpable mode blocks same-user debuggers.
- **Card files:** deletion does not erase remnants (flash, backups, sync, spoolers, terminal history).
- **`tpm-harden`:** removed. The sabotage risk from empty owner authorization remains, and is documented.
- **TPM sessions:** pending. They will defend against passive bus observers only, not active interposers.
- **`--force` (7.1):** refused until SI-11 is approved. As designed, "replace only a regular file" is not atomic. A displaced non-regular entry is never deleted, and a failed rollback is reported, not repaired.
- **F25 (7.1):** an index that cannot be resolved on its own TPM is never deleted elsewhere. It stays tracked and reported. The tracking mechanism is pending.

**Availability**
- **File systems:** vault changes are allowed only on allowlisted file systems. FAT32, exFAT, network and FUSE file systems are **read-only** in v1, which includes typical cross-platform pendrives and SD cards.
- **Crash safety:** claimed only on supported file systems, as process-crash safety. Power-loss safety depends on the device and is not claimed as tested.
- **Header damage:** structural, core or (bound) `s1_*` damage can make recovery impossible. Whole-folder backups are required. A passphrase + TPM + card path is pending.
- **New: recovery without a TPM.** A bound vault can be recovered directly to portable mode on any supported platform.
- **Argon2 limits:** never lowered. A machine without enough memory now gets a specific message instead of `Unlock failed.`.
- **Portable `verify-card`:** needs both cards together.

---

## 6. Corrections to the previous revision of this report

- **SI-07** listed a "card payload envelope" among the CBOR structures. The card payload is a fixed binary layout (7.4a), not CBOR.
- **SI-08** proposed in-house Shamir without examining the coefficient distribution or the RNG mapping. The evidence now shows that `vsss-rs` 6.0.1 has uniform coefficients and allows scripted vectors. Only its wiping gap remains.
- **SI-41** proposed specific messages for header parse failures. That conflicts with F7; parse failures stay `Unlock failed.`.

---

## 7. Spec 7.1 corrections (documentation only)

| Finding | Correction | Status |
| --- | --- | --- |
| Milestone 0.5 acceptance said "every issue resolved", while v7 left milestone-specific items pending | Section 13, row 0.5 (and the header of this file): close on recorded statuses plus all **Milestone 1** blockers resolved. Everything else stays PENDING until the milestone it blocks | Applied |
| SI-07 lacked path handling | Path decoding, storage, zeroization and error design added to SI-07. Spec 7.8 marks the decode-time check scope PENDING. Case-folding source flagged as an evidence gap | Pending |
| Card files had no active-operation lock | Spec 7.4b now marks the lifetime lock and cleaner rules PENDING (SI-10), with the full design in SI-10. F78 extended | Pending |
| `--force` was incomplete | Spec 7.9 marks `--force` PENDING, refused until approved. The success, rollback, failed-rollback and crash cases, plus the real guarantees and limits, are in SI-11. Proposed test F90 | Pending |
| The TPM-identity proposal did not cover duress or remote rekeying | Spec 9.6 and 9.3 (C4) retain PENDING notes. SI-36 keeps `ek_digest` in the duress tag and supersedes keyed identity MACs with exact five-scope encrypted tokens that can be rewrapped across remote bundle rotations | Pending |
| F7 vs the resource messages | F7 now allows the 4.3 / 5.8 policy or resource message for in-cap Argon2 flips. Recovery still fails, and no message depends on a secret | Applied |
| F25 vs the same-TPM rule | F25 now requires "no index left **untracked**". It is deleted only on its own TPM with identity established, otherwise reported and tracked. Mechanism SI-35 (c) / SI-36 pending | Applied (expectation); mechanism pending |
| F75 vs public TPM queries | F75 now forbids authorized or DA-affecting TPM commands before the hint, not public queries. Spec 5.7 states which TPM commands may run before Argon2id | Applied |

---

## 8. Decisions to start Milestone 1 (all approved by the author)

Milestone 1 builds `random`, `kdf` (5.1), `mac`, the chunk `cascade` (7.7, with the 7.1 AAD), known-answer vectors and benches.

| # | Decision | Recommendation | Evidence gap |
| --- | --- | --- | --- |
| M1-1 | Close Milestone 0.5 on the 7.1 criterion | **Approved.** Later pending decisions stay pending | None |
| M1-2 | SI-05: MSRV | **Approved:** 1.89. Milestone 1 is not accepted until the native 1.89 jobs pass. In Milestone 1, add a CI job that builds and tests with 1.89 on Linux, Windows and macOS, and declare `rust-version` in the same change. Keep clippy and rustfmt on stable. Pin the release toolchain by Milestone 13, and pin a dated nightly for `fuzz/` in Milestone 3 | Native Linux and Windows runs on 1.89 have not happened yet; the new CI job closes this. `tss-esapi` on 1.89 is unverified (Milestone 5) |
| M1-3 | RNG source: spec 7.1 names `rand_core::OsRng`, but `rand_core` 0.10 has no `OsRng`; the OS generator is now `getrandom::SysRng` (getrandom 0.4) | **Approved** (spec 7.2): propagate failures, never substitute another source. secrets come from `getrandom::fill`, or `getrandom::SysRng` where an API needs a `rand_core` RNG. `getrandom` is already approved | `memsec` 0.7 pulls in a second `getrandom` (0.2). That is a Milestone 7 memory-locking crate choice, not Milestone 1 |
| M1-4 | Crypto crate lines | **Approved.** `Cargo.lock` is to be committed when a commit is authorized; `cargo-deny` findings are reviewed. Use the current majors resolved under 1.89, all sharing one `rand_core` 0.10 / `crypto-common` 0.2 line with no duplicate `aead`/`cipher`: aes-gcm-siv 0.12.1, chacha20poly1305 0.11.0, chacha20 0.10.2, hkdf 0.13.0, hmac 0.13.0, sha2 0.11.0, argon2 0.6.0 (`zeroize` feature), subtle 2.6.1, zeroize 1.9.0, getrandom 0.4.3 | These are new major versions. Their APIs are confirmed only when Milestone 1 compiles against them. Advisory status is unknown until `cargo-deny` or `cargo audit` runs |
| M1-5 | Test-vector sources | **Approved**, using an isolated virtual environment, recording exact versions and provenance, and never generating expected values with the Rust code under test. **Published:** RFC 9106 (Argon2id, testing the `argon2` crate directly, since its 32 KiB vector is below pvault's caps); RFC 4231 (HMAC-SHA-512); Wycheproof (HKDF-SHA-512, HMAC-SHA-512, AES-GCM-SIV, XChaCha20-Poly1305). **pvault-specific** (5.1 derivations at the 256 MiB minimum, 7.7 records with fixed keys and nonces): generated by an independent offline script in `tools/vectors/`, using Python `cryptography`, `PyNaCl` and `argon2-cffi`. The script is run manually. Its outputs are generated repository files in `testdata/` (checked-in candidates, not yet committed), summarized in `FORMAT.md` | RFC 5869 has no SHA-512 vectors, which is why Wycheproof is needed. Vendored Wycheproof data is Apache-2.0 and needs a NOTICE entry (ties to SI-04). The Python packages are not installed here, and installing them needs your approval |
| M1-6 | SI-04 (optional for Milestone 1): `cargo-deny` | **Approved**, for advisories, bans, sources and dependency licenses. License-compatibility questions are flagged separately, and the project license is not chosen here | Its configuration needs a license allowlist, which depends on SI-04 |
| M1-7 | SI-01 follow-up | **Approved.** Milestone 1 moves the Milestone 0 core-dump FFI out of `secrets.rs` into `platform/`, with no behavior change | None |

Every other PENDING item blocks Milestone 2 or later (Section 4) and does not need to be resolved to start Milestone 1.

---

## 9. Findings during Milestone 1

| # | Finding | Evidence | Handling | Decision needed |
| --- | --- | --- | --- | --- |
| M1-F1 | `argon2` 0.6 frees its own block memory **without wiping it**, even with its `zeroize` feature on. Its `Blocks` drop only deallocates | `argon2-0.6.0/src/block.rs`, `impl Drop for Blocks` | pvault allocates the blocks itself (fallible `try_reserve_exact`), passes them to `hash_password_into_with_memory`, and wipes them in a drop guard on every path. Spec 10.2 updated (7.2) | No |
| M1-F2 | The AES key schedule inside `Aes256GcmSiv` (`aes::Aes256`) is wiped only by the `aes` crate's own `zeroize` feature, and `aes-gcm-siv`'s `zeroize` feature does not enable it | `aes-0.9.3/src/lib.rs` (`Drop` and `ZeroizeOnDrop` under `cfg(feature = "zeroize")`); `aes-gcm-siv-0.12.1/src/lib.rs:125` (`Aes256GcmSiv = AesGcmSiv<aes::Aes256>`) | **Resolved (approved):** `aes = "0.9.3"` is a direct dependency with `default-features = false, features = ["zeroize"]`. `Cargo.lock` holds one `aes` (0.9.3); `cargo tree -d --target all` shows no duplicate; `cargo tree -e features -i aes` shows `zeroize` unified with `aes-gcm-siv`'s use. The compile-time test `aes_key_schedule_is_zeroized_on_drop` requires `aes::Aes256: ZeroizeOnDrop` | No |
| M1-F3 | **Corrected root cause.** The first Milestone 1 report said `cargo-deny` 0.20.2 leaves dev-dependencies out of its graph (59 of 151 packages) and blamed `krates`. That was wrong. The graph had 150 crates all along (`[graph] exclude-dev` defaults to false). The **license check** alone skips crates reachable only through dev or build dependencies, because `[licenses] include-dev` and `include-build` default to false (`cargo-deny-0.20.2/src/licenses/gather.rs:498`). `cargo deny list` uses the same license gathering, and the reported 59 came from there and from the license-note count | `-L debug` shows "gathered 150 crates". A scratch probe config banning `criterion`, `wait-timeout` and `alloca` made `check bans` flag all three. A BSD-only license probe evaluated 147 crates after the fix, versus 56 before | **Resolved with ordinary configuration:** `deny.toml` sets `[licenses] include-dev = true` and `include-build = true`. Now `licenses ok` covers 150 crates: production, test, benchmark and build dependencies on all targets. The promoted-copy workaround is **not** used. Remaining exclusions: (a) pvault's two unpublished, unlicensed crates are skipped by the license check only (`[licenses.private] ignore = true`, pending SI-04); (b) `aho-corasick` 1.1.5 is in `Cargo.lock` but has no dependents on any target with the resolved features (`cargo tree -i aho-corasick --target all -e all` prints nothing), so it is never built and is outside the graph | No |
| M1-F4 | `r-efi` (UEFI targets only, via `getrandom`) is `MIT OR Apache-2.0 OR LGPL-2.1-or-later`. The dev-only `r-efi` 5.3.0 is licensed the same way | `cargo deny list` | **Resolved by the SI-04 decision:** used under its MIT or Apache-2.0 option, both compatible with `GPL-3.0-only`. Not built for pvault's targets | No |
| M1-F5 | Whether RFC test-vector excerpts are covered by the IETF Trust's BSD-style license for Code Components is unconfirmed | IETF Trust Legal Provisions | Attributed in `THIRD_PARTY_NOTICES.md`, and flagged | **Still open**, under SI-04 |
| M1-F6 | Argon2id runs single-threaded: the `p` lanes are computed one after another | Criterion, Apple M4, 2026-10-04: 0.36 s at 256 MiB / t = 3 / p = 4; **1.95 s** at the 1 GiB / t = 4 / p = 4 defaults (including pvault's allocation and wipe) | **Decided:** keep it single-threaded; no `rayon`. Performance is documented in `docs/FORMAT.md`. A default-parameters benchmark was added | No |
| M1-F7 | `criterion` 0.8 builds C code (`alloca`), so benches need a C compiler and cannot be cross-compiled without one | Cross-check failure, Section 3.1 | CI runners have compilers. Local cross-checks cover the library and binaries only | No |
| M1-F8 | `memsec` 0.7 pulls in a second `getrandom` (0.2) | `cargo tree` | Not used in Milestone 1; this is a Milestone 7 memory-locking crate choice | At Milestone 7 |
| M1-F9 | `cargo-deny` versions were inconsistent, and the CI install was not verified. The original CI step (`cargo-deny-action` v2.1.1) bundled 0.20.2, but downloaded it without a checksum, inside a Rust 1.85 image | Action `Dockerfile` at commit `3c63498…` | CI now downloads the official `cargo-deny` **0.20.2** release (`x86_64-unknown-linux-musl`), checks its SHA-256 (`9f12ed4c…8d5f`, matching both GitHub's asset digest and the release's `.sha256` file), and runs `cargo-deny --locked check --show-stats` on the Rust 1.89 toolchain. Locally: 0.20.2 built with `cargo install --locked`, plus the official `aarch64-apple-darwin` release (SHA-256 `fe67d82a…90c3`, verified the same way). Both give identical results: advisories, bans, licenses (150) and sources all ok. The advisory database is fetched fresh on every run by design, so advisory results can change over time while the tool version stays fixed | No |

---

## 10. Milestone 1 acceptance and Milestone 2

### 10.1 Milestone 1: accepted

Accepted by the author on 2026-10-04: commit `bd04bb4` ("Implement core cryptography and verification"), pushed to `main`, CI run 37254330640 green on every job (fmt; clippy, tests and bench smoke on Linux, Windows and macOS; the native Rust 1.89 build-and-test jobs on all three; `cargo-deny` 0.20.2; the swtpm smoke job).

### 10.2 Decisions applied in Milestone 2 (all approved by the author, 2026-10-04)

| # | Decision | Where |
| --- | --- | --- |
| M2-1 | Project license `GPL-3.0-only`, Copyright 2026 Yash Sandeep Tamhane | SI-04; spec 16 item 5 (v7.3) |
| M2-2 | EFF wordlist under EFF's CC BY 4.0 grant, embedded unmodified, TASL attribution, basis and uncertainty documented | SI-04; `THIRD_PARTY_NOTICES.md`; `assets/README.md` |
| M2-3 | SI-08 option 1: `vsss-rs = "=6.0.1"`, pvault-owned wiped storage | SI-08; spec 7.4 |
| M2-4 | SI-51 final design, with the seven clarifications | SI-51; spec 2 (A3), 5.1, 5.5, 5.6, 7.3, 16 item 2 (v7.4) |
| M2-5 | Header and journal schema changes stay **PENDING** until reviewed before Milestone 3 | SI-51 section 7 |

### 10.3 What Milestone 2 built

| Module | Content |
| --- | --- |
| `shamir.rs` | 2-of-3 and 2-of-2 split and combine over 96 bytes (SI-08) |
| `crypto/wrap.rs` | XChaCha20 wraps (7.5) |
| `passphrase.rs` | Generation (10–16 words, default 12; duress 12), H_w, word-list check, H_c with refuse and warn rules, NFC notice, collision rule, entropy and policy ratings |
| `normalize.rs` | NFC and NFKC in one fixed, wiped buffer (finding M2-F1) |
| `input.rs` | Bounded line reading, `--secrets-stdin` source (`StdinSecrets`), UTF-16 decoding for the Windows console |
| `platform/terminal.rs` | Echo-off terminal input: Unix `/dev/tty` + `termios` + signal handlers; Windows `CONIN$` + console mode + control handler |
| `estimator.rs`, `pvault-cli` dispatch | The estimator child process, its framing, bands and hardening |
| `tools/vectors/gen_vectors.py` | Independent Shamir, GF(2^8), XChaCha20, wrap and passphrase vectors |

Nothing in the vault lifecycle was built: no header, journal, unlock, `init`, duress set-up or CLI command uses these pieces yet.

### 10.4 Findings during Milestone 2

| # | Finding | Evidence | Handling | Decision needed |
| --- | --- | --- | --- | --- |
| M2-F1 | **`unicode-normalization`'s iterators leave passphrase characters in freed heap memory.** Their inline buffers (`TinyVec<[_; 4]>` in `Decompositions` and `Recompositions`) spill to the heap when four or more combining marks follow one another, and the spilled blocks are freed unwiped | Counting allocator: with the crate's `nfc()`/`nfkc()`, 4 marks gave 3 allocations and 2 non-zero frees; 80 marks gave 21 and 20. Typical text did not spill | `normalize.rs` runs the UAX #15 algorithm (full decomposition, canonical ordering, canonical composition) over the crate's allocation-free primitives (`decompose_canonical`, `decompose_compatible`, `canonical_combining_class`, `compose`) in **one fixed buffer of 6 × 1,024 characters, wiped on drop**. Tests: identical output to the crate's iterators on known cases and 4,096 generated strings per run (combining marks, Hangul, compatibility forms, any `char`); the Python vectors; `tests/heap_hygiene.rs` now shows only wiped frees, including for 120 combining marks. Spec 10 item 5 records the rule | No (behavior unchanged) |
| M2-F2 | Every `SecretBytes` is a boxed allocation, so "zero allocations" for Shamir holds only inside `vsss-rs` | `tests/heap_hygiene.rs`: exactly 9 allocations, all pvault's own buffers, none freed non-zero; 0 on the error path | Recorded under SI-08. Boxing is intentional: moving a secret never copies it | No |
| M2-F3 | `zxcvbn` 3.1.1 has **14** warning variants, not 12 as listed in earlier notes (`ThisIsATop10Password` and `ThisIsATop100Password` were missing) | `zxcvbn-3.1.1/src/feedback.rs` | Caught by the code-table alignment test; the table now has all 14 | No |
| M2-F4 | **Unicode versions differ by component, and normalization can change between releases.** `unicode-normalization` 0.1.25 uses Unicode 17.0; Rust std's `char::to_lowercase` and `is_whitespace` use 16.0 on Rust 1.89 and 17.0 on Rust 1.99; Python's `unicodedata` (vectors) uses 16.0 | `UNICODE_VERSION` constants; `char::UNICODE_VERSION` printed by each toolchain | **Correction (author, 2026-10-04):** an earlier draft of this row said that pinning the release toolchain removes the issue. It does not. A custom credential is accepted with code points that are unassigned in the current Unicode version, and the H_c result is the Argon2id input. If a later pvault release updates `unicode-normalization` (or the toolchain), and a later Unicode version assigns such a code point as a combining mark or with a decomposition, the same typed text can normalize to different bytes, and an existing custom passphrase would stop unlocking. Pinning a toolchain or crate per release does not keep normalization identical **across releases**. For generated words the risk does not arise in practice: valid H_w credentials are ASCII list words, and characters new in Unicode 17 cannot map to them. Vectors avoid characters whose properties changed | **Yes, blocker for the Milestone 3 schema review:** a stable normalization-version policy (see 10.7) |
| M2-F5 | The estimator child has **no CPU or memory limit on Windows**, and no address-space limit on macOS | Windows has no `setrlimit`; macOS does not enforce `RLIMIT_AS` | **Accepted for Milestone 2 (author, 2026-10-04).** The protections kept on every platform: bounded input (request at most 514 bytes, H_c at most 256 bytes; reply at most 64 bytes), the 5 s wall-clock timeout, and confirmed termination: every failure path after spawn kills the child if it is still running and waits for it (`terminate()`), and a non-zero exit is reaped by `try_wait`. Test `pvault-cli/tests/estimator_reaping.rs` (Unix) shows that no child remains, running or zombie, after timed-out estimates. Measured worst case: about 0.34 s through the child for nine adversarial 256-byte shapes (Apple M4), with a test bound of 2 s. **Deferred hardening:** Windows Job Object CPU and memory limits; not added now, and outside the current 7.6a scope | No (deferred) |
| M2-F6 | On Windows, Ctrl+Z at a secret prompt arrives as the byte 0x1A, not as end of input | `ReadConsoleW` line-mode behavior | Custom handling refuses it (control character); generated-word handling reports an unknown word. Ctrl+C cancels through the console handler | No; document in `docs/CLI.md` (Milestone 4) |
| M2-F7 | **Windows console input is compile-only.** Echo-off, the UTF-16 path and restoration through the console control handler are compiled and linted for `x86_64-pc-windows-msvc`, but never executed by a test, because they need an interactive console | — | See 10.6. Windows interactive runtime validation stays **outstanding**; it must happen before the first command that prompts on Windows (Milestone 4) | No; tracked |
| M2-F8 | `zxcvbn` adds 17 crates to normal builds (`aho-corasick`, `bit-set`, `bit-vec`, `deranged`, `either`, `fancy-regex`, `itertools`, `lazy_static`, `memchr`, `num-conv`, `powerfmt`, `regex`, `regex-automata`, `regex-syntax`, `time`, `time-core`, plus `zxcvbn`). `chrono`, with its `iana-time-zone`, `windows-*`, `js-sys` and `web-sys` dependencies, is reachable only on `wasm32` targets and is not built for pvault's targets (`cargo tree -i chrono` prints nothing for the Linux and Windows targets). `Cargo.lock`: 151 → 177 packages in total, including `vsss-rs`, `unicode-normalization` and their dependencies | `cargo tree`; lock diff | `cargo-deny` 0.20.2 (source build and release binary): advisories, bans, licenses and sources ok. `aho-corasick`, previously unused (M1-F3), is now a real dependency | No |
| M2-F9 | The draft's XChaCha20 vector IV ends `…5455 5658` (it skips 0x57) | draft-irtf-cfrg-xchacha-03, A.3.2.1 | Reproduced exactly; verified independently. Not a pvault issue | No |
| M2-F10 | The IETF draft excerpt has the same open licensing question as the RFC excerpts | `THIRD_PARTY_NOTICES.md` | Attributed and flagged, under SI-04 / M1-F5 | Still open, under SI-04 |
| M2-F11 | `duress_collides` returns "no collision" when the main input fails H_w (invalid UTF-8, too long, empty) | `passphrase.rs` | Correct by definition: such input has no H_w credential, so it can never produce the duress key | No |

### 10.5 SI-51 section 9 tests: status

| Test | Status |
| --- | --- |
| Unbiased sampling; 10–16 with default 12; entropy figure | Done (unit tests, sampling vectors) |
| Every refuse and warn rule; NFC/NFD and the NFC notice; spaces preserved; 1,024 and 256 limits | Done (unit tests, Python vectors) |
| Estimator runtime on adversarial 256-byte inputs; reply contains no input; failure refuses the new credential | Done (`pvault-cli/tests/estimator.rs`, against the real binary) |
| Collision rule | Done (unit test) |
| Bounded-read state machine via an injected reader; `--secrets-stdin` refused on a TTY; over-long lines refused | Done (`input.rs` unit tests; `tests/stdin_secrets.rs` through real stdin) |
| Terminal restoration after normal input, cancellation, a read error, SIGINT, SIGTERM, SIGHUP and SIGQUIT | **Unix only** (pty tests on macOS locally and on Linux and macOS in CI). The Linux-only over-long-line test runs in CI. Windows: compile-only, see 10.6 |
| Type-back flows; "existing vaults still unlock"; "the estimator is never invoked during unlock"; two-run unlock order and wiping | **Not yet possible:** they need unlock and the CLI (Milestones 3 and 4) |
| Tampered `passphrase_kind` gives `Unlock failed.` | Milestone 3, after schema review |

### 10.6 Platform validation status of secret input

| Behavior | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Bounded line reading (`read_line`, injected reader) | Tested in CI | Tested locally and in CI | Tested in CI |
| `--secrets-stdin` through real stdin (pipe) | Tested in CI | Tested locally and in CI | Tested in CI |
| `--secrets-stdin` refused on a terminal | Tested (pty) | Tested (pty) | **Compile-only** (no console in CI) |
| Echo off during input, restored after normal input, cancellation and a read error | Tested (pty) | Tested (pty) | **Compile-only** |
| Restoration on SIGINT, SIGTERM, SIGHUP, SIGQUIT (handlers use only `tcsetattr`, `sigaction`, `sigemptyset`, `raise`) | Tested (pty subprocess) | Tested (pty subprocess) | n/a |
| Restoration on Ctrl-C, Ctrl-Break and close (`SetConsoleCtrlHandler`; the handler calls only `SetConsoleMode`) | n/a | n/a | **Compile-only** |
| UTF-16 console decoding (`Utf16Decoder`, lone surrogates refused) | Tested (unit) | Tested (unit) | Unit-tested logic; `ReadConsoleW` itself compile-only |

**Outstanding:** interactive runtime validation of the Windows console path (echo off, restore on normal return, error, Ctrl-C and window close, CRLF, non-BMP input). It must be done on a real Windows console before Milestone 4 ships any prompting command.

### 10.7 Blocker for the Milestone 3 schema review: normalization-version policy

Custom credentials (H_c) feed Argon2id directly, so their normalization must stay identical for the life of a vault, across pvault releases (M2-F4). Pinning the toolchain or `unicode-normalization` per release does not guarantee that. The Milestone 3 schema review must approve one policy. Options, for the author:

- **(a) Refuse unassigned code points** in new custom passphrases, using a table frozen at a stated Unicode version. Unicode's normalization stability policy then keeps NFC fixed for every accepted character, in every later version. This is a new refusal rule, and needs the table's source and version fixed.
- **(b) Record the normalization Unicode version** in the header (a schema change), and keep pvault able to normalize with that version. That means carrying old tables forever.
- **(c) Freeze pvault's own normalization tables** (vendored, never updated). Simple, but new characters can never be normalized correctly.

Recommendation, for review only: (a), possibly with (b) as a recorded field for diagnostics. Nothing is implemented until the author decides.

**Refinement (2026-10-05; `docs/M3_READINESS.md` D2):**
- Option (a) uses pvault's own, monotonically non-decreasing Unicode tables rather than a frozen table. It applies at creation **and** at every entry, needs no header field, and gives forward stability by Unicode's Strong Normalization Stability. Older releases refuse characters they do not know (fail closed).
- Generated-word handling becomes a frozen `H_w_v1`: Unicode 17.0.0 `Cn` refusal, NFKC, full default case folding and a fixed `White_Space` set, from vendored tables whose six source SHA-256 values were independently re-verified. This changes the approved Milestone 2 H_w for non-ASCII input.
- When `H_w_v1` refuses a custom input, the duress check is a non-match and the duress-only run is skipped (decided N3; timing difference documented in spec 5.6).

### 10.8 Milestone 2 acceptance

**Accepted on 2026-10-04:** commit `a099bb6` ("Implement secret sharing and passphrase handling"), pushed to `main`; CI run 37261091478 green on all nine jobs:

| Job | Tests passed / failed / ignored |
| --- | --- |
| clippy + test, ubuntu-latest (stable; tests plus `--benches`) | 189 / 0 / 3 |
| clippy + test, macos-latest | 187 / 0 / 3 |
| clippy + test, windows-latest | 170 / 0 / 1 |
| Rust 1.89 build + test, ubuntu-latest | 114 / 0 / 2 |
| Rust 1.89 build + test, macos-latest | 113 / 0 / 2 |
| Rust 1.89 build + test, windows-latest | 103 / 0 / 1 |
| rustfmt; cargo-deny 0.20.2; swtpm smoke test | passed |

Linux has one extra test (the over-long-line restoration test); Windows has none of the Unix-only pty, signal, reaping and resource-limit tests (10.6). The ignored tests are the two subprocess helpers. Recorded limitations: M2-F4 (normalization-version policy, a Milestone 3 blocker), M2-F5 (accepted platform limits; Job Object deferred), M2-F7 and 10.6 (Windows console compile-only), M2-F10 (RFC/IETF excerpt licensing, under SI-04), and the SI-51 tests that need unlock or the CLI (10.5).

### 10.9 Milestone 3 readiness audit (2026-10-05)

The full report is `docs/M3_READINESS.md`; its appendix B records the checks performed. Selected or decided by the author: **W1**, **P1**, and **N1 to N5** (2026-10-05). Every other item below is a recommendation and remains **PENDING**.

| # | Finding | Proposed handling | Decision |
| --- | --- | --- | --- |
| A1 | Transition target, tracking and header temps had no ownership mechanism; `keytable.<old_gen>.pv` was deleted by name | Identity handoff for every journaled artifact (`target_created`, `tracking_created`, identity fields in `committing`/`rollback_tracking`); `old_keytable_digest` | Approve or reject (schema) |
| A2 | Draft file identity `st_dev || st_ino` changes across reboots or remounts and is open to inode reuse | `st_ino || birth time` on the live directory's `st_dev`; Windows adds `CreationTime` | Approve or reject (schema) |
| A3 | The remote-rollback commit increments generation by 2, against the glossary | Keep +2; glossary exception recorded | Approve or reject |
| A4 | The scope-4 old-index token duplicates the staged cleanup entry | **Decided N4:** removed after the restart-path check; scope 4 reserved | Decided |
| A5 | A required identity token makes C4 a precondition for any bound index | **Decided N2:** refuse before any write; offer portable mode (spec 9.3, F91) | Decided |
| A6 | D2 cited a nonexistent "approved dummy-derivation timing rule" | Removed. **Decided N3:** a refused candidate is a duress non-match, the run is skipped, and the timing difference is documented (spec 5.6) | Decided |
| A7 | `H_w_v1` changes the approved, implemented Milestone 2 H_w for non-ASCII input | Stated explicitly; Milestone 3 code and vector change if approved | With D2 |
| A8 | Windows SMB shares report `NTFS` | Require that `FileRemoteProtocolInfo` fails | Approve or reject |
| A9 | Post-replacement flush failures could be predictable `ENOTSUP`, against refusal-on-unsupported | Preflight before the first side effect | Approve or reject |
| A10 | W1 covers header replacement only; the protocols need ordered create/delete durability | **Decided N1 (W1-b):** document the risk and the unverified ordering assumptions WO-1 to WO-3 | Decided |
| A11 | `objects/` could be on another mount | Same-mount check | Approve or reject |
| A12 | D8 named `host_page_size`, absent from `libc` 0.2.190; `mach_host_self` is deprecated there | `sysconf(_SC_PAGESIZE)`; scoped allow | With D8 |
| A13 | The 65,536-entry key-table cap is a product limit | **Decided N5:** approved, counting files and directories; refused before any write (spec 7.8, F92) | Decided |
| A14 | Requiring `header_file_id` for a committed init header only reduces availability | The identity owns temp residue only | Approve or reject |
| A15 | Spec 7.6 still listed Shamir as `PENDING SI-08` | Corrected (decided in Milestone 2) | None |
| A16 | A committing header temp could collide with the tracking header temp | Identity retained into `tracking_created`; identity-checked unlink plus directory flush before reuse; a mismatch blocks (spec 8.1) | Approve or reject |
| A17 | Transition journal-temp promotion was undefined (only init had rules) | Permitted transitions, MAC rules, preserved fields, invalid-temp residue, crash table (spec 8.2) | Approve or reject |
| A18 | Stale texts: SI-38 committed-header identity; 6.4 "stay in prepared"; 7.8 unconditional +1; F73 decode/input contradiction | Corrected (2026-10-05) | None (consistency) |
| A19 | The case-folding and wizard deadlines did not match the milestones that use them | Case folding before M4 (if the split is approved); wizard before M14 | Confirm |
| A20 | Init bootstrap order was undefined when T, the lock files or `objects/` are missing | Bootstrap creations limited to T and the two lock files; identify P before creating T; lock before the full preflight; `objects/` created by the first `add` (spec 8.3) | Approve or reject |
| A21 | Windows local-volume detection lacked an exact criterion | Q1–Q4, fail closed, native probe required (spec 8.5) | Approve or reject |

The RFC/IETF test-vector licensing question (SI-04, M1-F5, M2-F10) remains open and does not block Milestone 3.

### 10.10 Milestone 3 approvals (author, 2026-10-05)

The author approved, for Milestone 3, the designs D1–D8 of `docs/M3_READINESS.md`, together with every documented audit correction:

| Item | What is approved |
| --- | --- |
| D1 | `CoreFields.passphrase_kind` and the init-journal field |
| D2 | H_c refuses code points unassigned in pvault's Unicode version, at creation and at every entry. `H_w_v1` is frozen at Unicode 17.0.0 (`Cn` refusal, NFKC, full default case folding, a fixed `White_Space` set) from vendored, hash-pinned tables |
| D3 | The fixed-schema in-house codec, two-pass key-table decode, exact arenas, the 65,536-entry cap (N5) and the decoded-size charge |
| D4 | The G + L lock protocol (mount lock and upgrade remain with SI-45) |
| D5 | Linux mountinfo identification; the macOS and Windows checks, including the Q1–Q4 local-volume criterion; the durability sequences, preflight and failure boundary; W1 and N1 as selected |
| D6 | The schemas: encrypted TPM-identity tokens (scopes 1, 2, 3 and 5; scope 4 reserved, N4); the 32-entry `tpm_cleanup`; expected-core digests; the init and transition phases with artifact identities and `old_keytable_digest`; `tracking_created` and `rollback_tracking` with the +2 generation; the journal-temp promotion rules; header-temp resolution; the init bootstrap order; bound creation refused without identity (N2) |
| D7 | The 7.8 entry layout, the 4096/255 limits and the decode/input split (F73 corrected) |
| D8 | The memory-resource definitions (macOS: `sysconf(_SC_PAGESIZE)` × (free + inactive)) and the 64 MiB margin |

- The revised deadlines are approved: case folding before Milestone 4, and the wizard default before Milestone 14.
- W1, P1 and N1–N5 are unchanged.
- Still pending: SI-04 release notices and the RFC/IETF excerpt question, SI-10, SI-11, SI-14 mount and upgrade, SI-18, SI-22, SI-29, SI-35 handle allocation and overflow, SI-40 live-vault rules, SI-42, SI-44, SI-45, and the N3 creation notice.


### 10.11 Milestone 3: implementation findings (2026-10-05)

Milestone 3 is implemented locally under the 10.10 approvals. Native CI has
not run: it needs an authorized push. No approved format was changed, and
implementation exposed **no missing schema rule**. The findings are:

| # | Finding | Handling | Needs the author? |
| --- | --- | --- | --- |
| M3-F1 | Spec 4.1's `CoreFields` listing omitted the approved D1 field `passphrase_kind`, which 5.1, 7.3, D1 and the init-journal schema already require | Added to the 4.1 listing (documentation consistency; the field, type and values are as approved) | No |
| M3-F2 | Windows child operations must remain relative to the already-held directory and must never follow a substituted reparse point | Replaced the path-based draft with platform-isolated `NtCreateFile` (`RootDirectory`, one validated component, `FILE_OPEN_REPARSE_POINT`) and verified-handle `NtSetInformationFile` rename/delete. Added directory-replacement and child reparse-substitution tests. SAFETY comments cover every pointer, buffer, output structure and owned handle. Native Windows execution remains required | No; directed correction applied |
| M3-F3 | The decode-time reserved-name check sliced a `str` at byte 3, which panics for a four-byte component ending inside a multi-byte character (for example `abé`). An authenticated key table with such a path would have crashed decoding | Fixed (byte comparison); regression test and a fuzz seed with such paths added | No |
| M3-F4 | Restart rule gap, not a schema gap: in `rollback_tracking` with the header still old, the tracking header temp may be **absent**. No single cause can be inferred safely | The state is `Indeterminate`: retain the journal, delete nothing, create no replacement temp, and use the approved fsck message. A new file would have an identity this authenticated phase cannot journal | No; author directed this handling |
| M3-F5 | Windows lock files and artifacts inherit the directory's ACL; pvault sets no owner-only ACL itself yet. Unix uses mode `0600`/`0700` | The owner-only ACL on the vault directory belongs to `init` (Milestone 4, 8.3 step 2) | No (Milestone 4) |
| M3-F6 | Three new user-facing failure classes needed exact wording | Applied the approved strings: replacement outcome unknown; generation changed before replacement; and indeterminate state/no cleanup. Missing tracking-header temp uses the indeterminate string, not a fourth message | No; author supplied wording |
| M3-F7 | The `fuzz/` crate adds exactly pinned `libfuzzer-sys` 0.4.13 (fuzz-only, excluded from the workspace, own `Cargo.lock`). Its manifest says `(MIT OR Apache-2.0) AND NCSA`, while all 55 bundled LLVM source files carry `Apache-2.0 WITH LLVM-exception` headers | Recorded crates.io checksum `a9fd…929d2`, upstream git `719e4e…ed0f`, wrapper and bundled-source license evidence, and the direct `arbitrary`/build-only `cc` graph. `fuzz/deny.toml` grants a version-scoped exception only to `libfuzzer-sys@0.4.13`; CI and local checks cover the fuzz lockfile's advisories, bans, licenses and sources. Product `Cargo.lock` is unchanged | No; 0.4.13 fuzz-only use approved |

**Scope of the executor.** `store.rs` executes the remote-rollback tracking
commit and the old-side and new-side transition restarts on real files.
Deciding between local and remote rollback, resolving a TPM index, and the
forward recovery and `convert` paths are Milestones 5 and 6; the crash tests
drive the forward path with a test harness. `init` (Milestone 4) will use the
same primitives.

**Verification status.**
- **Current macOS host:** stable `cargo test --workspace --locked` has 181
  distinct passing executions, 0 failures and 5 ignored helpers. This includes
  142 passing library tests (4 ignored), 33 passing integration/CLI tests (1
  ignored), and 6 passing documentation tests. Rust 1.89 gives the same
  181/0/5 result. `cargo test --workspace --benches --locked` repeats the 142
  library tests (4 ignored) and runs 8 Criterion functions; those repetitions
  and functions are not additional distinct tests. The focused filesystem
  slice is 8/0/0; journal plus store is 22/0/1.
- **Static and policy checks:** host fmt and workspace/all-target clippy pass;
  Windows and Linux library cross-clippy pass. Release fault injection is
  refused and no failpoint name occurs in release artifacts. `cargo-deny`
  reports product 177 and fuzz 101 license notes, with zero advisory, license
  or source findings (one allowed duplicate-`syn` warning in each lockfile).
  All four fuzz targets build with the pinned nightly and completed a local
  five-second smoke run without a finding.
- **Crash and restart:** 48 child-process crash runs (16 crash points × 3
  starting phases). After every restart, the header is exactly the
  reconstructed tracking core. In the 15 runs where `rollback_tracking` was
  durable, it equals `tracking_core_digest`. A tracking key table re-encrypted
  in place (same file identity, fresh nonces) blocks as indeterminate.
- **Promotions:** every permitted journal-temp promotion and duplicate/residue
  case is tested on real files, on the old side and the new side (the WO-1
  case).
- **Windows locality probe:** written and type-checked; it runs only in
  native CI (`windows_native_locality_probe`, and the mapping probe with
  `--include-ignored`). Unexpected answers refuse; no detection is relaxed.
  Local NTFS, a loopback UNC path, `subst` and a loopback-mapped SMB drive are
  covered. A mounted VHD, a ReFS dev drive and a real remote SMB server remain
  outstanding (8.5 probe list); until then the criterion fails closed.
- **Process crashes only:** power-loss safety is not tested (8.5 "Testing").
- **Native Windows remains an acceptance gate:** the Windows test binaries did
  not run on this macOS host. Cross-checking their dev-test graph also stops at
  the expected missing MSVC C headers for Criterion's `alloca`; native CI has
  the required toolchain. The NTFS directory-replacement and reparse-point
  branches, Q1–Q4 locality/mapping probes, and runtime rename/delete semantics
  remain unverified until that CI runs. ReFS, mounted VHD and real remote SMB
  coverage remain separate manual gaps; no test claims power-loss safety.

### 10.12 Milestone 3 acceptance

**Accepted on 2026-10-05:** commit `afa6a3f` ("Accept native Windows locality result"), pushed to `main`; CI run 37391563815 green on all twelve jobs. This supersedes the "native Windows remains an acceptance gate" item in 10.11.

| Job | `cargo test --workspace` passed / failed / ignored |
| --- | --- |
| clippy + test, ubuntu-latest (stable) | 182 / 0 / 5 (plus `--benches` rerun: 143 / 0 / 4) |
| clippy + test, macos-latest (stable) | 181 / 0 / 5 (plus `--benches` rerun: 142 / 0 / 4) |
| clippy + test, windows-latest (stable) | 170 / 0 / 5 (plus `--benches` rerun: 134 / 0 / 4; locality-probe step: 2 / 0 / 0) |
| Rust 1.89 build + test, ubuntu-latest | 182 / 0 / 5 |
| Rust 1.89 build + test, macos-latest | 181 / 0 / 5 |
| Rust 1.89 build + test, windows-latest | 170 / 0 / 5 |
| fuzz smoke | passed: four targets, 61 s each, no crash or error |
| release build checks (F85) | passed: release build with `fault-injection` refused; no failpoint name in release artifacts |
| cargo-deny 0.20.2 | passed: 0 errors; one allowed duplicate-`syn` warning |
| Unicode table regeneration; rustfmt; swtpm smoke test | passed |

- **Ignored tests:** the five per run are helper processes or explicit-only tests: `store::tests::crash_child`, `lock::tests::lock_holder_child`, `stdin_helper`, `fuzz_seeds::fuzz_seeds`, and `platform::terminal::tests::signal_helper_reads_from_pty` (Unix) or `platform::fs::tests::windows_native_locality_probe_mappings` (Windows). The mapping probe ran in the dedicated `--include-ignored` step, so no requested Windows case was skipped.
- **Dedicated Windows locality probe** (stable windows-latest, 2 passed, 0 ignored): local NTFS temp directory accepted (NTFS); `subst` drive accepted, matching the underlying volume; loopback UNC path refused (Q2 returned error 3, no volume-GUID path); loopback-mapped SMB drive refused (same). Handle-relative create, rename and delete, the directory-replacement test and the reparse-substitution test also ran natively.
- **Q1 did not discriminate in the observed tests:** `FileRemoteProtocolInfo` returned `ERROR_NOACCESS` (998) for the local NTFS path *and* for both loopback SMB paths. The refusals came from Q2 to Q4. Q1 currently adds no detection; the criterion still refuses unless all four queries accept.
- **Unverified assumptions:** W1 and WO-1 to WO-3 (8.5, N1) remain unverified product assumptions about Windows power loss. Only process crashes are tested; no test claims power-loss safety on any platform.
- **Outstanding coverage:** ReFS (dev drive), a mounted VHD and a real remote SMB server have not been probed (8.5 probe list). Until they are, the criterion fails closed for anything it does not recognize.

### 10.13 Milestone 4 preparation: approved directions (author, 2026-10-05)

| Topic | Decision |
| --- | --- |
| Recovery-card text | No terminal display of card secrets. Hidden Base32 input is allowed. Secrets are never command-line arguments |
| Vault paths at input | Vendored Unicode 17.0.0 canonical caseless matching for collisions; NFC normalization of input; refusal of unassigned characters. The approved Unicode-independent decoding of existing paths is unchanged |
| Duress | No duress setup in Milestone 4. A duress match fails without mutation. Temporary milestone limitation, recorded in spec 5.3 and 8.3 |
| `add` sources | Regular files only. `created_at` is the time added; `modified_at` comes from the source |
| `--force` | Refused throughout Milestone 4 |
| QR photos | Synthetic distortion tests, plus a manual printed-card photo check (a gate; result outstanding) |
| Windows console | A manual checklist as an acceptance gate (prepared in `docs/M4_READINESS.md` section 14; result outstanding) |
| Documentation | Stale text corrected (spec version, 7.3 `H_w_v1` steps, 8.5 Q1–Q4 evidence, the layout, the Milestone 4 test row, this file's section 4 and SI-50). Q1 is investigated without weakening Q2 to Q4 (M4_READINESS section 13) |

Concrete designs awaiting approval: `docs/CLI.md` and `docs/M4_READINESS.md` section 15 (A1 to A7).

### 10.14 Milestone 4 approvals (author, 2026-10-05)

The author approved A1 to A7 of `docs/M4_READINESS.md` as revised, with:
- `FlushConsoleInputBuffer` within the isolated terminal module (an addition to the 7.6a terminal scope);
- exit code 5 for an export whose publication or durability is uncertain;
- `CLOSE UNFINISHED CLEANUP <8 hex>` removing only the authenticated pending `update` journal, after explicit confirmation.

| Item | Approved design |
| --- | --- |
| A1 | `docs/CLI.md`, including the corrected queued-input wording: pending terminal input is discarded before each hidden prompt is displayed and read, and application-side buffered input is cleared and wiped; this does not prove which prompt was visible when input was typed, and does not stop input that arrives after the flush |
| A2 | Per-user records: settings folder, privacy check, the two storage policies (registration on 8.5-supported local settings folders, qualified by the platform flush assumptions; best effort for the rollback record), schemas, caps, identity rule |
| A3 | The `update` journal (phases `staged`, `committing`, `cleaned`), the `add`/`rm` protocol, ownership rules, unresolved-cleanup handling, and the 8.4 exception |
| A4 | `DELETE VAULT LEFTOVERS <8 hex>`, its candidate sets and the journal-temp exception |
| A5 | Source-file rules and their stated limits |
| A6 | Card-file lifecycle, cleaner and destination rules (SI-10 complete) |
| A7 | Dependency pins and features, the crate-specific license exceptions for `rqrr` (ISC), `foldhash` (Zlib) and `option-ext` (MPL-2.0), and their notices |

Manual gates accepted, results outstanding: the Windows console checklist and the printed-card photo check. Milestone 4 is accepted only after its native CI jobs and both manual gates pass.

Decided 2026-10-06 (details and results in `docs/M4_READINESS.md` 17):

| Item | Decision |
| --- | --- |
| O1 | PNG card verification during `init` needs the terminal device, also with `--secrets-stdin`; refused before anything is written without one; photos are opened only after the terminal printing acknowledgment; line counts unchanged. The test-only synchronization marker is removed; the real CLI is tested with a pseudo-terminal (Unix) and in the Windows console gate |
| O2 | The accepted signal and console handlers stay. `docs/CLI.md` 3 distinguishes native termination (Ctrl-C, Ctrl-Break, signals, window close: the platform's status) from application cancellation (exit 7) |
| FAT/exFAT | Real disposable-image tests (`fat_exfat_images`) in native CI on Linux, macOS and Windows; run locally on macOS images. Mocked types do not replace them |
| Native names | Checked against the approved design (7.2, CLI 1.2): handle-relative names are native (`OsStr`) again; vault paths stay strict Unicode. Remaining restrictions come from the platform (Windows `\`, Unix `/` and NUL) or the file system (APFS rejects invalid UTF-8) |
| O3 (2026-10-06) | Owner-only access stays required, fail closed: exported plaintext and card files go only to file systems pvault identifies as local and enforcing owner-only access in their kernel driver (Linux `ext4`, `xfs`, `btrfs`, `tmpfs`; macOS `apfs`, `hfs`; Windows local `NTFS`, `ReFS`). FAT/exFAT, FUSE (`fuseblk`), network, other, unknown and unidentifiable destinations are refused (exit 6) before any secret, destination file or record entry; vaults there stay readable. No permission-setting call is taken as proof. Table and reasons: `docs/M4_READINESS.md` 17, `docs/CLI.md` 1.3 |

**O4** (decided 2026-10-06, option 1): the accepted identity and locking rules stay unchanged. F74 is narrowed: read-only commands work on otherwise unsupported file systems only where the stable file identity required by the locking protocol is available; without it (Windows FAT/exFAT, FUSE) every command is refused with exit 6 and nothing is changed. Workaround: copy the entire vault folder to a supported local file system and open the copy. Existing refusal tests stay. Details: `docs/M4_READINESS.md` 17, `docs/CLI.md` 1.4.

**SI-52** (revision 4 approved in direction 2026-10-06 with corrections; implemented in Milestone 4, unaccepted): paper or digital recovery cards (`docs/RECOVERY_DELIVERY_PROPOSAL.md`; spec 7.4d; `docs/CLI.md` 6.1, 6.7, 6.8; `docs/M4_READINESS.md` 7.6, 11.5, 17). Corrections applied: everyday commands keep passphrase authentication (L1 revised; per-command table in the proposal, 6.3); per-file format validation separate from pair validation (duplicate shares, wrong roles, different vaults or card sets); `discard-card --vault` labels its header comparison as unauthenticated and always asks for the stronger phrase. **Q2 superseded (decided 2026-10-06):** `card_set_id` is not added to the init journal; the init-journal schema accepted in Milestone 3 and its published vectors (`testdata/pvault_journal.txt`) are unchanged. It is not needed: nothing is deleted after a restart (L2), and each card entry records its own `vault_id` and `set_id`, which `init` resume compares with the authenticated header. `cards.cbor` v2 is new in unreleased Milestone 4 and has no published vector. **R5 (decided 2026-10-06):** an optional card check after the commit, offered to an interactive digital `init` once every handle and lock is released; strict reader plus recovery rehearsal; a failure (exit 1) rolls nothing back and deletes nothing (F102). **Native CI:** commit `b6baa13`, run 37541676635, all 12 jobs succeeded (distinct libtest tests, stable and 1.89: Linux 238, macOS 237, Windows 224 passed, 0 failed, 6 ignored; scenario suites 14, 14 and 12 passed, the 2 image suites run in the dedicated image step). Real disposable images refused digital card folders on Linux (`vfat`, `exfat`, `fuseblk`), macOS (FAT32, exFAT, APFS with ownership ignored; the ownership-enforced APFS control accepted one) and Windows (FAT32, exFAT VHDX). The R5 eject is simulated in tests (a card folder removed and recreated); no real device ejection and no physical-separation test was run. Details: `docs/M4_READINESS.md` 17. **Manual gates, outstanding:** the Windows console checklist (with digital steps 16 to 20b) and the printed-card photo check, which covers paper delivery only.

**E1, Milestone 5 preparation exception** (authorized 2026-10-06; `docs/M5_READINESS.md` 1, 11, 12): an isolated, **uncommitted** TPM-library and API probe **outside the repository**, against `swtpm` only, to validate compilation and the proposed SI-18/SI-22 calls in an isolated Linux environment. Not allowed under E1: Milestone 5 product code; changes to shared `init`, card or CLI code; changes to `Cargo.toml`, `Cargo.lock`, `deny.toml` or CI; access to a real TPM or any change to host TPM settings; commits or pushes. Installing tooling or starting Docker needs the setup and its host effects described to the author first. **Milestone 4 is not accepted:** the Windows console checklist and the printed-card photo check remain outstanding and unchanged; E1 does not start Milestone 5. **E1 closed as completed (2026-10-06):** all eight probe checks ran on `swtpm` 0.7.3 in an isolated Ubuntu 24.04 container (Docker Desktop 4.94.0) with `tss-esapi` 7.7.0, Rust 1.89 and stable. Results are **emulator observations only**, not evidence about real TPM hardware (`docs/M5_READINESS.md` 12.2); the recommendations they changed are in 11.2 and 13. No repository code, dependency, `deny.toml` or CI change was made; the probe container and its emulator state were removed; the `ubuntu:24.04` image and an out-of-repository scratch folder remain.

**E2, sequencing exception for Milestone 5** (authorized 2026-10-06): Milestone 5 may be implemented while Milestone 4 remains **unaccepted**. Both Milestone 4 manual gates (the Windows console checklist and the printed-card photo check) remain outstanding and unchanged; neither milestone is accepted by E2; Milestone 6 is not started. Development uses `swtpm` only; **no real TPM access is authorized**. Recorded in `CLAUDE.md` and spec section 0 item 1.

**Milestone 5 decisions D1 to D12** (approved 2026-10-06, with the author's choices; `docs/M5_READINESS.md` 11 and 13):

| # | Decision |
| --- | --- |
| D1 | `tss-esapi = "=7.7.0"` (`tss-esapi-sys` 0.6.0), Linux-only optional dependency behind the default feature `tpm`; `tpm2-tss` ≥ 2.4.6; one crate-specific `deny.toml` exception for `target-lexicon` (Apache-2.0 WITH LLVM-exception, build-only) |
| D2 | SI-22 approved with two amendments: the NULL-hierarchy salting key is created with an empty password session; per-command session attributes are fixed and enforced by pvault (not left to the library); explicit session lifetime |
| D3 | SI-35 handle allocation, collision and unknown-outcome handling and the generation overflow refusal approved; F87 and the Milestone 5 half of F88 adopted |
| D4 | pvault builds the H-2 EK template itself; C1 to C4 approved; **unavailable duress is reported in `status` only**, never during an unlock |
| D5 | Spec 6.10 duress setup approved for both modes |
| D6 | Until the Milestone 9 trigger exists, a duress match is a generic failure with no mutation, and duress is **explicitly described as inactive** (`status`, documentation) |
| D7 | **Conditional** N3 timing notice: only when the main passphrase is custom and falls in a refused generated-word class |
| D8 | Bound card delivery: `--cards paper --cards-dir` or `--cards digital --card-dir` (the single bound digital card); rehearsal S1 + S3 |
| D9 | `--mode` remains required; `--tpm device\|swtpm:PORT`; `--tpm-owner-auth` requests **hidden terminal input or the documented explicit `--secrets-stdin` line**; no authorization secret may appear in arguments, environment or logs |
| D10 | Bound mode on Linux only |
| D11 | Local container recipe plus native Linux CI |
| D12 | Fresh emulator state per test; short lockout parameters where a test drives failures |

**Acceptance-plan amendment (2026-10-06):** parameter encryption for every secret-bearing command (`NV_DefineSpace`, `NV_Write`, `NV_Read`) is verified with controlled emulator transport tests and negative cases; the fields that remain public are documented; this does **not** establish resistance to every active transport attacker. **Before acceptance:** the TPM C library's (`tpm2-tss`) handling of session secrets is investigated and reported for a separate decision. **Before release of bound mode:** authorized real-hardware validation is required; none is authorized now.

**TPM C-library secret memory (decided 2026-10-11, Milestone 5):** the residue that `tpm2-tss` leaves in freed memory (authorization values, session keys, `S2_wrapped`, decrypted response bytes; `docs/M5_READINESS.md` 15) is **accepted as a documented limitation for Milestone 5** (spec 10 item 8). This does not establish complete secret-memory wiping and does not authorize a bound-mode release; real-hardware validation stays required. The library's logging stays **forced off with no debug switch**, verified to be off before the first TPM-library operation (`tpm_library_logging_is_off_from_the_start`). Scope: the `pvault` CLI; direct users of `pvault-core` get the same protection only by calling the now `unsafe` `platform::quiet_tpm_stack` themselves while single-threaded.

**Milestone 5 native CI** (2026-10-11; implemented under E2, **not accepted**): commit `dab6264` implements Milestone 5. Its first CI run did not start (account billing). After the repository was made public, the fuzz smoke job failed at its seed step because it lacked `tpm2-tss` (the seed test builds `pvault-core` with the default `tpm` feature on Linux); commit `c4a4480` installs `libtss2-dev` there, with no test, assertion or timing change. **Run 38157453235** on `c4a44806f7b0`: all 12 jobs succeeded. Substantive libtest tests (stable and 1.89 identical): Linux 266, macOS 246, Windows 233. These exclude the isolated-process runner and its completeness check, and count the isolated tests once: Linux 33 isolated tests, 20 of them on `swtpm` with the emulator required; macOS 13; Windows 9. Scenario suites: 17, 14 and 12 passed, plus the dedicated image step (real FAT, exFAT and Linux `fuseblk` images; macOS APFS with ownership ignored and enforced). Details: `docs/M5_READINESS.md` 14. Still required or open: the Milestone 4 manual gates, the author's Milestone 5 acceptance decision, real-hardware validation before any bound-mode release, E1, V3's cause, the runner's process-start window, the accepted `tpm2-tss` memory limitation, and the open licensing questions in `THIRD_PARTY_NOTICES.md`.

**G1** (decided and implemented 2026-10-06, Milestone 4): on macOS a volume mounted with ownership ignored (`MNT_IGNORE_OWNERSHIP`, common for external drives) reports `apfs` or `hfs` but enforces no ownership or permissions. Export destinations and card folders there are refused (exit 6) before any secret is read or written, and a settings folder there is not private. Tests on mocked flags and on real APFS images (`docs/M4_READINESS.md` 17).
