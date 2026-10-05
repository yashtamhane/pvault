# Specification issues and decisions (Milestone 0.5)

This is the decision record for the Milestone 0.5 consistency pass.

- **Spec reviewed:** `PVAULT_BUILD_SPEC.md` version 6 (SHA-256
  `3832b3645ba360f61492ad54ca167767135d4a50889cde43b285fe1a111ab20e`).
- **Spec produced:** version 7, then 7.1 (documentation corrections; Section 7), then 7.2 (Milestone 1 approvals; Section 8).
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
| SI-04 | License and notices | Open (author) | License undecided. `cargo-deny` approved for CI (advisories, bans, sources, dependency licenses); `THIRD_PARTY_NOTICES.md` added for vendored vectors; `cargo-about` still proposed for M13 | 14, 16 | n/a | M2 |
| SI-05 | MSRV and toolchain pinning | Accepted | `rust-version = 1.89`; native 1.89 build-and-test CI jobs on 3 OSes gate each milestone; release toolchain pinned by M13 | 12, 13 | MSRV CI jobs | M1 |
| SI-06 | Section 16 decisions | Open (author) | Name `pvault` decided; others recommended | 16 | n/a | M2 / M3 / M5 |
| SI-07 | CBOR implementation | Pending (evidence) | Three options compared; secret and path handling designed (decode, storage, zeroization, errors) | 4.4, 7.6, 7.8, 10.1 | F14, F71, F73, fuzz | M3 |
| SI-08 | Shamir implementation | Pending (evidence) | `vsss-rs` fails coefficient wiping; in-house + cross-check proposed | 7.4, 7.6 | F5, F6, F62 | M2 |
| SI-09 | QR input | Accepted | `png` with bounded limits; SVG output; camera deferred | 7.4a, 7.4c, 7.6 | F47, F61 | M4 |
| SI-10 | Card files | Accepted + Pending (design) | Explicit destination, owner-only, recorded identity, identity-checked cleanup, remnants documented (accepted); active-operation lifetime lock and cleaner rules (pending) | 7.4b | F78 | M4 |
| SI-11 | Secure file creation | Accepted + Pending (design) | FFI primitives, refuse when unsupported (accepted); `--force` exchange design and its real guarantees (pending; refused until approved) | 7.6a, 7.9 | F50, F51, proposed F90 | M4 |
| SI-12 | Durability primitives | Pending (evidence) | Primary-doc evidence and a per-platform proposal | 4.3, 8.5 | F25, F26 (process crash only) | M3 |
| SI-13 | FAT/exFAT and crash safety | Accepted (modified) | Mutations refused outside an allowlist; read-only otherwise; no redundant headers | 1, 2, 8.5 | F74 | M3 |
| SI-14 | Lock protocol | Pending (design) | Gate lock + mount lock; no PID markers; no atomic conversion assumed | 4, 8.4 | F56a, F56b, F72 | M3 |
| SI-15 | Memory locking | Accepted (modified) | Best effort, visible, optional strict mode; Argon2 memory wiped, not locked | 10.2 | F77 | M3 / M7 |
| SI-16 | Argon2 memory limits | Accepted (modified) | Hard caps; total-RAM policy; available-memory resource check; specific messages; never lowered | 4.3, 5.8 | F13, F76 | M3 |
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
| SI-30 | Vault paths | Accepted | Unique normalized paths; directory entries; `--replace` | 7.8 | F64, F73 | M3 |
| SI-31 | `convert` | Accepted | Protocol drafted (6.9); confirm before M6 | 6.9 | F32, F68, F82 | M6 |
| SI-32 | Duress setup | Accepted | Protocol drafted (6.10); confirm before M5 | 6.10 | F46, F57, F59, F81 | M5 |
| SI-33 | Duress scope and ordering | Accepted | Command table; duress check before the journal check | 5.7 | F63 | M4 |
| SI-34 | Portable single-card check | Accepted (modified) | Two-card verification kept and documented; no commitments | 7.4a | F63 | — |
| SI-35 | Recovery details, handles, overflow | Pending (design) | Allocation and collision protocol; overflow refusal | 3, 6.3, 8.1 | proposed F87, F88 | M3 / M5 |
| SI-36 | Cross-machine and TPM-less recovery | Accepted + Pending (design) | Recovery to portable and the same-TPM rule applied; identity mechanism pending, including an authenticated check on the duress path (TPM identity bound into the duress tag) | 6.5, 6.8, 9.2b, 9.6 | F25, F80, F83 | M3 (format) / M6 |
| SI-37 | Object keys not rotated | Accepted (modified) | Documented; `--rekey-files` deferred | 6.11 | n/a | — |
| SI-38 | Safe `init` | Pending (design) | Both modes journaled; directory rule; authenticated leftovers | 8.3 | F26, F59, F60 | M3 / M4 |
| SI-39 | Journal schemas | Accepted | Exact schemas in 8.1; Revoke/Erase at M8 | 8.1 | F27, F71 | M3 |
| SI-40 | Leftover files | Pending (design) | Authenticated-ownership rules; add/rm reordering | 4, 8.2, 8.3 | F25, F26, proposed F89 | M3 |
| SI-41 | Message table | Accepted (modified) | Table in 5.8; parse failures stay generic | 5.6, 5.8 | F7, F13, F14 | M3 |
| SI-42 | Owner authorization and duress | Accepted + Pending (design) | `tpm-harden` removed; availability rule; checks C1 to C3 prepared, plus C4 if SI-36 (a) is adopted | 9.3 | F75, F81 | M5 |
| SI-43 | Erase confirmation | Accepted (modified) | Basename + vault-ID prefix; no unrelated deletion | 9.5 | F84 | M9 |
| SI-44 | K2 | Pending (design) | Constraints applied; details at the M8 review | 9.10 | F43, F49 | M8 |
| SI-45 | Mount | Pending (design) | Write model proposed; crates and CI to review | 13 (M11) | F56b | M11 |
| SI-46 | Card milestone | Accepted | Cards move to M4 | 7.4a, 13 | F61, F65 | M4 |
| SI-47 | CLI document | Accepted | `docs/CLI.md` drafted and approved before M4 | 14 | n/a | M4 |
| SI-48 | Failpoints | Accepted | Test-only feature; excluded from release builds | 11 | F85 | M3 |
| SI-49 | Guarantee table | Accepted | Two rows added; crash-safety statement added | 2 | docs | M7 |
| SI-50 | Minor items | Accepted | Itemized below | various | F17, F70 | as noted |

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

### SI-04 License and notices — Open (author)

- **Still needed:** the license choice (MIT, Apache-2.0, GPL-3.0 or a dual license).
- **Notices tooling proposal (needs approval; developer tools only, never linked into pvault):**
  1. **`cargo-deny`** in CI from Milestone 1: a license allowlist, duplicate and banned-crate checks, and security advisories. It can replace a separate `cargo audit` step.
  2. **`cargo-about`** at Milestone 13: generates `THIRD_PARTY_LICENSES` for release artifacts from the locked dependency graph.
  3. **A hand-maintained `NOTICE`** from Milestone 2, for non-crate material: the EFF wordlist under CC BY 3.0 US, with the attribution text.
  4. **Alternative:** no tools, and a manual review at each release, which is error-prone.
- **Affected:** Milestone 2 (wordlist notice); Milestone 13 (release notices); the `license` field in `Cargo.toml`.

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
- **Recommendations awaiting confirmation:**
  - **Passphrase length:** 12 words (~155 bits) in both modes. Under A2 (Grover's algorithm), 12 words leave ~2^77.5 Argon2id evaluations versus ~2^64.6 for 10. Portable mode relies on the passphrase alone. The cost is two more words to type.
  - **Wizard default:** bound on Linux, when a usable TPM 2.0 is present and bound duress or indices can work. Portable on platforms without bound support.
  - **PCR binding:** opt-in, because firmware updates would otherwise force recovery unexpectedly.
- **Affected:** 7.3 (the default length) before Milestone 2; the wizard default (Milestone 14) before Milestone 3, per Section 16; PCR before Milestone 5.

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
  This is an SI-30 decision, before Milestone 3.

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

**Affected:** Milestone 3 (header, journal, key table), the `keytable_parse` fuzz target, F14 and F71.

### SI-08 Shamir — Pending (evidence)

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

**Approval needed:** in-house with cross-checks, or `vsss-rs` as the implementation with the known wiping gap documented.

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
- **Windows `MoveFileExW`:** `MOVEFILE_WRITE_THROUGH` "guarantees that a move performed as a copy and delete operation is flushed to disk". No crash-atomicity statement for same-volume renames was found.
- **Windows `FlushFileBuffers`:** flushes a file. Flushing a volume requires administrative privileges.
- **Rust `std::fs::rename` (1.89):** on Windows it uses `MoveFileExW` or `SetFileInformationByHandle`, so the flags are not under our control. Use explicit calls.

**Proposed primitives:**

| Platform | File flush | Replace | Directory entry | Claim |
| --- | --- | --- | --- | --- |
| Linux (ext4, XFS, Btrfs) | `fsync` | `renameat` / `renameat2` | `fsync(dirfd)` | Crash consistency as provided by these journaling file systems with flush support |
| macOS (APFS, HFS+) | `fcntl(F_FULLFSYNC)` | `renameat` | `F_FULLFSYNC` on the directory fd (to verify) | `rename(2)`'s documented crash guarantee |
| Windows (NTFS, ReFS) | `FlushFileBuffers` | `MoveFileExW(REPLACE_EXISTING \| WRITE_THROUGH)` via `windows-sys` | none available without admin | **Not documented** by Microsoft; an assumption, stated as such |

**Remaining uncertainty:**
- Windows crash atomicity of rename-replace is an undocumented assumption.
- Whether directory `F_FULLFSYNC` is meaningful on APFS.
- Device firmware that ignores flushes.

None of these can be proven by process-crash tests (now stated in 2 and 8.5).

**Approval needed:** the primitive table and the Windows assumption wording.

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
- **(c) Recommended: an authenticated `pending_tpm_cleanup` list in the core.**
  - Entries hold the handle, both Names, the policy nonce and the keyed TPM identity (SI-36).
  - `fsck` resolves the vault side, then moves the unresolved index into this list as part of its commit (`core_mac`, generation + 1), and deletes the journal.
  - Any later `fsck` with an unlock on a matching TPM deletes the index under 9.2b, and the entry is removed in the next commit.
  - `status` lists pending entries.

  This is a core format change, so it must be decided before Milestone 3. With (c), F25 holds as "no index left untracked".

**Approval needed:** the protocol.

**Affected:** Milestones 3 (journal), 5 and 6.

### SI-36 Cross-machine and TPM-less recovery — Accepted + Pending (design)

- **Accepted (applied):**
  - `recover --to-portable` (6.8), with no TPM needed.
  - The same-TPM deletion rule (9.2b step 3): never delete merely because handle, Name and policy match.
  - Remote old-index limitations documented.
- **Proposed mechanism (pending):**
  - **(a) Recommended:** `tpm_id = SHA-256(EK public area)`, from the TCG default ECC P-256 EK template, created transiently in the endorsement hierarchy.
    - It is stored in the bound slots and in the journal `IDX` and old-index fields, and recomputed before any undefine.
    - A mismatch, or an inability to compute it (endorsement authorization set, `ehEnable` clear), means no deletion, and the index is reported.
  - **(b) Not recommended:** proof by authorized read with the old `tpm_auth`. It works only when the passphrase is present, costs a DA count against a decoy, and cannot cover an index that was never written.
- **Revised proposal (7.1), including an authenticated check on the duress path:**
  1. **Measurement.** `ek_digest = SHA-256(marshal(TPMT_PUBLIC))` of the TPM's endorsement key, created transiently from a **fixed** TCG EK Credential Profile template (ECC NIST P-256 preferred) with `CreatePrimary(TPM_RH_ENDORSEMENT)`, then flushed.
     - It is an unauthenticated public query: it carries no authorization and has no DA effect (5.7).
     - It requires the endorsement hierarchy to be enabled and endorsement authorization to be empty.
     - `ek_digest` is **never stored, logged or displayed in plaintext.**
  2. **Normal paths** (an unlock with the bundle, recovery, `fsck`):
     - The bound slots gain `tpm_id_mac = HMAC-SHA-512(K_mac, "pvault/v1/tpm-id" ‖ vault_id ‖ ek_digest)` (64 bytes, also covered by `slots_mac`).
     - Before any undefine (9.2b), the current `ek_digest` is measured and the MAC recomputed and compared in constant time.
     - A mismatch, or a failed measurement, means no deletion, and the index is reported.
  3. **Journals:** `IDX` and the old-index fields carry `tpm_id_mac` values keyed under the same key that authenticates the record (`journal_key` or `init_journal_key`). Dual-MAC records carry both the old-key and the new-key variant. The `pending_tpm_cleanup` entries of SI-35 (c) carry the `K_mac` variant.
  4. **Duress path (no bundle).** The bound tag also binds the identity:

     `duress_tag = HMAC-SHA-512(duress_key, "pvault/v1/duress-tag" ‖ vault_id ‖ "bound" ‖ u32_be(tpm_nv_index) ‖ tpm_nv_name ‖ tpm_policy_nonce ‖ ek_digest)`

     - Before the duress check (5.7, step 6), a bound unlock whose slots contain a tag measures `ek_digest`. It does this on **every** such unlock, so the duress and non-duress paths take the same steps.
     - A match authenticates, in one constant-time comparison, three things: the duress passphrase, the slots' TPM fields, **and** that this is the TPM the tag was made on. Then come C1 to C4 (SI-42), the 9.2b Name and public-area check, and the undefine.
     - **On another TPM:** the tag does not match, and the passphrase continues as a wrong one. The Name check there normally fails, so `NV_Read` is never called. Result: `Unlock failed.`, with nothing deleted.
     - **If the measurement is impossible** (C4 fails): no match is possible, so the behavior is the same as on another TPM. `status` reports duress as unavailable.
  5. **Privacy.** No plaintext identifier is stored. Testing a candidate EK offline needs the bundle (`K_mac`) or the duress passphrase, which is Argon2-gated.
- **Remaining uncertainty:**
  - **Fixed template choice.** Some TPMs may lack ECC P-256. The template must be fixed when the index is created (an RSA-2048 fallback takes seconds), and the choice would need a public slots field `tpm_id_template`: a minor leak of TPM capability.
  - **Latency:** an EK `CreatePrimary` on every bound unlock that has a tag. To be measured in Milestone 5, with the timing documented in Milestone 9.
  - **Formula change:** this changes the 9.6 tag formula and the slots and journal formats, so it must be decided before Milestone 3.
  - An EK can change after `TPM2_ChangeEPS`. All owner indices are lost then anyway.
- **Approval needed:** the revised mechanism, including binding the identity into the duress tag.
- **Affected:** Milestone 3 (format), Milestones 5, 6 and 9; F25, F80, F83, F38, F81.

### SI-37 Object keys not rotated — Accepted (modified)

- **Resolution:** documented (6.11). `recover --rekey-files` is deferred until a full protocol is reviewed.
- **Remaining uncertainty:** none for v1.

### SI-38 Safe `init` (both modes) — Pending (design)

*Re-evaluated "Decision: No". The author moved it to design.*

**Proposal:**
1. **Target directory T:**
   - It must not exist (pvault creates it, mode `0700`) or must be an empty directory, opened without following symlinks.
   - Zero-length regular lock files left by an earlier pvault attempt count as empty.
   - Anything else → refuse ("directory not empty").
2. **Both modes write an init journal before creating anything else.** In v6 only bound mode did.
   - **Fields:** the 8.1 init fields with `salt` (the future `core.salt`) instead of a separate `journal_salt`, plus the Argon2 parameters and `IDX` when bound.
   - **Key:** `init_journal_key = HKDF-SHA-512(master_pw, info "pvault/v1/init-journal", L = 32)`, from the **same** single Argon2id run.
   - **Rewrite after the key table:** after `keytable.1.pv` is renamed into place, the journal is rewritten with the file's SHA-512 digest, keeping the same index fields.
3. **Order:**
   1. Journal.
   2. Bound only: define the index, write S2, and confirm both Names.
   3. `keytable.1.pv` (tmp → flush → rename), then the journal digest update.
   4. Cards, outside T, tracked in `cards.cbor`.
   5. Delivery verification.
   6. Optional duress (6.10).
   7. Header: the commit point.
   8. Delete the journal.
4. **Re-run when T has a journal and no header:**
   1. Ask for that setup's passphrase and validate the journal's parameters against the caps.
   2. Verify the MAC, and match `vault_id` and `setup_id`.
   3. Delete exactly these protocol-defined items:
      - the journaled index (9.2b, including the same-TPM rule);
      - `keytable.1.pv`, only if its digest matches the journal;
      - the transient `keytable.1.pv.tmp`, `vault.hdr.tmp` and `vault.journal.tmp`, as regular files opened without following symlinks inside T.
   4. If T holds anything else (apart from lock files), refuse and report, because T no longer looks as `init` left it.
   5. Delete the journal and start over with a new `vault_id` and `setup_id`.

   Without the passphrase, it only reports.
5. **Re-run when T has a header:** the v6 post-commit rules are unchanged.

**Remaining uncertainty:**
- A partial `.tmp` file cannot be content-authenticated. Deleting it relies on the authenticated journal plus its exact protocol name plus the T-content restriction, which is still a name-based component. The alternative is report-and-confirm for `.tmp` files.

**Approval needed:** the protocol, and the `.tmp` choice.

**Affected:** Milestones 3 (journal schema) and 4; F26, F59, F60, F69.

### SI-39 Journal schemas — Accepted

*Re-evaluated "Decision: No".* Accepted, with the exact schemas in 8.1. Two parts remain open:
- the init-schema changes of SI-38 and the TPM-identity field of SI-36;
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
- The rollback record (`rollback.cbor`) format, locking and limits are defined (9.7).
- `fsck` wording for other vaults' indices: to be handled in `docs/CLI.md` (the message wording).
- The layout gains `platform/`, `lock.rs`, `partials.rs` and `paths.rs`. `pvault-app` stays out of `default-members` until Milestone 14.
- TPM randomness mixing is **off by default** (7.1).

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
- **learn.microsoft.com:** `MoveFileExW` (`MOVEFILE_WRITE_THROUGH` semantics), `FlushFileBuffers` (volume flush needs admin), `LockFileEx` (no overlapping exclusive locks).
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
2. SI-04: approve `cargo-deny` for CI (license, advisory and ban checks), or a manual process.
3. Section 8: the RNG source (`rand_core` 0.10 has no `OsRng`), the test-vector sources, the crypto crate versions, and Milestone 0.5 closure.

**Before Milestone 2**
3. SI-04: choose the license (`Cargo.toml` `license` field, and the NOTICE that embeds the wordlist credit).
4. SI-06: confirm 12 words in both modes, or choose 10.
5. SI-08: in-house Shamir with `vsss-rs` cross-checks, or `vsss-rs` with its wiping gap documented.

**Before Milestone 3**
6. SI-07: `ciborium` with restrictions and a codec fallback for the key table, or the fixed-schema codec.
7. SI-12: approve the durability primitive table and the wording of the Windows assumption; confirm the file-system allowlist.
8. SI-14: approve the lock protocol (gate and mount locks, bounded retries).
9. SI-35 / SI-38 / SI-40: approve the handle-allocation protocol, safe `init` (including the `.tmp` choice), the leftover-ownership rules and the `add`/`rm` reordering.
10. SI-36: approve the revised TPM-identity mechanism: a keyed `tpm_id_mac` in the slots and journals, `ek_digest` bound into the duress tag, and the fixed EK template. SI-35 (c): the `pending_tpm_cleanup` core list. Both change formats.
11. SI-30 / SI-07: confirm the key-table entry layout, the path limits, the decode-time versus input-time check split, and the **case-folding source** (an approved crate, a vendored table, or `to_lowercase`).
11a. SI-07: approve the path classification (confidential, zeroized, not locked) and the proposed 5.8 message "The key table is damaged."
12. SI-06: confirm the wizard default (Section 16 asks before Milestone 3).
13. SI-16: confirm the 64 MiB resource margin.

**Before Milestone 4**
14. SI-10: approve the card-file lifetime lock and cleaner rules. Should any terminal display of card text exist?
15. SI-11: approve the `--force` design and its stated guarantees (proposed F90). Windows `--force` stays refused.
16. SI-47 / SI-19 / SI-41: approve `docs/CLI.md`, including `--secrets-stdin` and the message wording.

**Before Milestone 5**
17. SI-18 / SI-22: approve the TPM pins, the exact public area and the salted-session design, with its trust assumptions.
18. SI-42: approve capability checks C1 to C3; status-only reporting of unavailable duress.
19. SI-32: confirm the duress-setup draft (6.10).
20. SI-06: confirm PCR binding as opt-in.

**Before Milestone 6**
21. SI-31: confirm the `convert` draft (6.9) and its confirmation phrases.
22. SI-29: approve `recover --use-tpm` (the S2 + S3 path) and proposed test F86.

**At the Milestone 8 review**
23. SI-44: platform support, privilege boundary (root and the per-user records), test coverage and partial-failure reporting.
24. Revoke and Erase journal schemas (SI-39); the Erase ID-prefix length (SI-43).

**Before Milestone 11**
25. SI-45: the encrypted-overlay write model, the macOS FUSE-T feasibility spike, and the WinFsp and power-event crates.

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
| The TPM-identity proposal did not cover duress | Spec 9.6 and 9.3 (C4) gain PENDING notes. SI-36 binds `ek_digest` into the duress tag, and adds a keyed `tpm_id_mac` for the normal paths | Pending |
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
| M1-F4 | `r-efi` (UEFI targets only, via `getrandom`) is `MIT OR Apache-2.0 OR LGPL-2.1-or-later`. The dev-only `r-efi` 5.3.0 is licensed the same way | `cargo deny list` | Allowed through its MIT or Apache option; not built for pvault's targets | Flagged under SI-04 only |
| M1-F5 | Whether RFC test-vector excerpts are covered by the IETF Trust's BSD-style license for Code Components is unconfirmed | IETF Trust Legal Provisions | Attributed in `THIRD_PARTY_NOTICES.md`, and flagged | **Still open**, under SI-04 |
| M1-F6 | Argon2id runs single-threaded: the `p` lanes are computed one after another | Criterion, Apple M4, 2026-10-04: 0.36 s at 256 MiB / t = 3 / p = 4; **1.95 s** at the 1 GiB / t = 4 / p = 4 defaults (including pvault's allocation and wipe) | **Decided:** keep it single-threaded; no `rayon`. Performance is documented in `docs/FORMAT.md`. A default-parameters benchmark was added | No |
| M1-F7 | `criterion` 0.8 builds C code (`alloca`), so benches need a C compiler and cannot be cross-compiled without one | Cross-check failure, Section 3.1 | CI runners have compilers. Local cross-checks cover the library and binaries only | No |
| M1-F8 | `memsec` 0.7 pulls in a second `getrandom` (0.2) | `cargo tree` | Not used in Milestone 1; this is a Milestone 7 memory-locking crate choice | At Milestone 7 |
| M1-F9 | `cargo-deny` versions were inconsistent, and the CI install was not verified. The original CI step (`cargo-deny-action` v2.1.1) bundled 0.20.2, but downloaded it without a checksum, inside a Rust 1.85 image | Action `Dockerfile` at commit `3c63498…` | CI now downloads the official `cargo-deny` **0.20.2** release (`x86_64-unknown-linux-musl`), checks its SHA-256 (`9f12ed4c…8d5f`, matching both GitHub's asset digest and the release's `.sha256` file), and runs `cargo-deny --locked check --show-stats` on the Rust 1.89 toolchain. Locally: 0.20.2 built with `cargo install --locked`, plus the official `aarch64-apple-darwin` release (SHA-256 `fe67d82a…90c3`, verified the same way). Both give identical results: advisories, bans, licenses (150) and sources all ok. The advisory database is fetched fresh on every run by design, so advisory results can change over time while the tool version stays fixed | No |
