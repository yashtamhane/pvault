# Milestone 3 readiness report

Prepared 2026-10-05, after Milestone 2 (commit `a099bb6`, CI run
37261091478). Nothing here was implemented when it was written; every
recommendation needed the author's approval before Milestone 3 started. The
issue records it summarizes are in `docs/SPEC_ISSUES.md`.

> **Update (2026-10-05):** the author approved D1–D8 and the audit
> corrections (`docs/SPEC_ISSUES.md` 10.10). Milestone 3 is implemented
> locally; findings are in `docs/SPEC_ISSUES.md` 10.11.

Milestone 3 (spec 13) builds: deterministic CBOR (4.4); the header (core and
slots, two MACs, caps and limits); the chunked stream (already built in
Milestone 1); the key-table file with vault paths (7.8); journal schemas
(8.1); locking (8.4); the file-system support check (8.5); and test-only
failpoints. Its acceptance tests are F7, F9 to F14, F56a, F58, F71, F73
(decode part), F74 (detection part), F76 and F85.

**No pvault release exists until Milestone 18**, so no deployed vault depends
on the format yet. Changing the format later costs vectors and documentation,
not migration. The spec still requires format decisions before the milestone
that first needs them, and this report follows that rule.

---

## 1. Summary

### Decisions needed now (they block Milestone 3 code)

| # | Decision | Issue | Recommendation, in one line |
| --- | --- | --- | --- |
| D1 | Passphrase-kind schemas (header and init journal) | SI-51 §7 | Required `passphrase_kind` in the core and in the init journal; nothing else stored |
| D2 | Normalization stability for custom and generated credentials | SI-51, M2-F4, §10.7 | Preserve assigned-only NFC for H_c; define H_w v1 as Unicode-17 NFKC, full default case fold and a frozen whitespace set, using vendored hash-pinned data |
| D3 | CBOR implementation and secret-buffer handling | SI-07, SI-20 | **Revised:** a fixed-schema in-house codec, with a two-pass key-table decode and architecture-independent semantic allocation charges |
| D4 | Lock protocol (gate and vault lock) | SI-14 | Approve the G + L protocol now; the mount lock (M) with SI-45 |
| D5 | File-system identification and durability | SI-12, SI-13 | Identify the exact Linux mount type; never accept `0xEF53` alone. Use the documented macOS full-flush sequence. **W1 selected:** writable NTFS/ReFS under the explicit assumption, without claiming verified power-loss safety |
| D6 | Init/transition journals, TPM identity and cleanup | SI-38, SI-36, SI-35 (c), SI-06 | **Replace the MAC-only draft** with exact encrypted-token schemas; authenticate exact old/new/tracking core digests; recompute tracking `slots_mac`; use identity-owned safe-init artifacts and confirmed residue; cap cleanup at 32. **P1 selected:** nonce-policy only in v1 |
| D7 | Key-table entry layout and decode-time path rules | SI-30, SI-07 (paths) | Approve the 7.8 layout, the 4096/255 limits and the Unicode-independent decode checks |
| D8 | Memory-resource checks | SI-16 | On macOS use a conservative, precisely defined `host_statistics64` estimate with `sysconf(_SC_PAGESIZE)`; query failure refuses before allocation |
| N1–N5 | Decisions from the final audit | Appendix B | **All decided 2026-10-05:** N1 Windows power-loss risk documented (WO-1 to WO-3 unverified); N2 refuse bound creation without EK identity and offer portable; N3 refused candidate is a duress non-match; N4 scope 4 removed after restart-path verification; N5 65,536-entry limit approved |

### Safely deferred (no Milestone 3 code depends on them)

| Item | Issue | Needed before | Why it can wait |
| --- | --- | --- | --- |
| Live-vault leftover rules for `add`/`rm` and their reordering | SI-40 | Milestone 4 (ordering), Milestone 6 (`fsck` deletion) | No format change as long as object ownership stays AEAD-based. **Not deferrable:** the transition-artifact identities and `old_keytable_digest` (D6 audit item 1), which are journal fields |
| Case-folding source for path collisions | SI-30 | Milestone 4 | Collisions are checked on input only (`add`), never at decode time |
| `--force`, card files, CLI document, `--secrets-stdin` UX | SI-11, SI-10, SI-47, SI-19 | Milestone 4 | Commands only |
| Windows console runtime validation | M2-F7 | Milestone 4 | First prompting command |
| TPM command sessions and capability checks | SI-22, SI-42 | Milestone 5 | They do not change the on-disk layout after the exact public-area and TPM-identity choices in D6 are fixed |
| Handle probing/collision behavior | SI-35 (1–4) | Milestone 5 | The runtime behavior can wait after D6 fixes uncertain outcomes and deferred cleanup; PCR policy is excluded from this deferral |
| Header resilience (`recover --use-tpm`), `convert` | SI-29, SI-31 | Milestone 6 | No format change |
| Revoke and Erase journal schemas | SI-39 | Milestone 8 review | The Milestone 3 parser rejects unknown `op` values |
| Mount lock and write model | SI-14 (M), SI-45 | Milestone 11 | Mount is Milestone 11 |
| Release notices tooling; release toolchain pin | SI-04, SI-05 | Milestone 13 | Release only |
| **RFC / IETF test-vector excerpt licensing** | SI-04, M1-F5, M2-F10 | Before any release (Milestone 13) | Repository test data only; still recorded as open |
| Wizard default mode | SI-06, spec 16 item 3 | Milestone 14 | Spec 16 says "ask before Milestone 3", but nothing in Milestones 3 to 13 depends on it. Recommend moving the deadline |
| Windows Job Object limits for the estimator | M2-F5 | Deferred hardening | Accepted for Milestone 2 |

---

## 2. Decisions needed now

### D1. Passphrase-kind schemas (SI-51 section 7)

**Recommendation.** Record the main passphrase's kind in the authenticated
core and in the init journal. Store nothing else about the passphrase: no word
count, estimate, band or Unicode version.

**Evidence.**
- Unlock must choose H_w or H_c **before** Argon2id, so the kind has to be in
  the header. In the core, `core_mac` covers it.
- Re-running `init` derives `init_journal_key` from the passphrase before the
  journal MAC can be checked, so the journal must carry the kind too. Until
  the MAC verifies it is unauthenticated, but a tampered value only makes the
  MAC check fail, which is then reported (8.1).
- Duress needs no kind field: duress is always generated (fixed at 12 words).
- Tampering outcomes were analyzed in SI-51 §7. Every case ends in
  `Unlock failed.` or a journal MAC failure.

**Exact schema changes.**

`CoreFields`: add one required field. Key order for the fields fixed here
under 4.4 (shortest encoded key first, then bytewise):

```text
CoreFields {
  mode             text  "bound" | "portable"
  salt             bytes(32)
  magic            text  "PVLT"
  version          u64   1
  argon2_m         u32
  argon2_p         u32
  argon2_t         u32
  setup_id         bytes(16)
  vault_id         bytes(16)
  created_at       u64
  generation       u64
  card_set_id      bytes(8)
  keytable_gen     u64
  keytable_digest  bytes(64)
  passphrase_kind  text  "words" | "custom"        NEW, required
}
```

D6 adds the required `tpm_cleanup` array and fixes its entry shape. The block
above fixes the D1 fields and their relative canonical order; `FORMAT.md` must
publish the final whole-map order after inserting `tpm_cleanup`.

Init journal: the same `passphrase_kind` field, required (full schema in D6).

Recovery and `convert` journals need no `passphrase_kind` field. Their TPM-
identity fields still change under D6. The new kind is in the new core.

**Visible to an attacker:** whether the main passphrase is custom (already
documented in SI-51 §7).

**Tests.**
- Round trip for both values. Every other value (`""`, `"Words"`, a 7-byte
  string, a byte string) is a parse failure, giving `Unlock failed.` (F7
  class).
- Flip `passphrase_kind` with the core otherwise intact: `core_mac` fails, so
  unlock and recovery both fail (extends F7).
- Switching `custom` to `words` triggers the word-list hint only from typed
  input (an extended F75).
- Init journal with a tampered kind: MAC failure, reported, nothing deleted
  (extends F69 and F71).
- Known-answer vectors for a header of each kind in `FORMAT.md`.

### D2. Normalization stability for custom and generated credentials (M2-F4, SPEC_ISSUES 10.7)

**Problem.** H_c (NFC) output is the Argon2id input. If a future pvault
normalizes the same typed text differently, an existing custom passphrase
stops working. Pinning a toolchain or crate per release does not prevent that.

**Evidence (primary source).** Unicode Character Encoding Stability Policy,
<https://www.unicode.org/policies/stability_policy.html>, read 2026-10-05:
- *Strong Normalization Stability (Unicode 4.1+):* "If a string contains only
  characters from a given version of Unicode, and it is put into a normalized
  form in accordance with that version of Unicode, then the results will be
  identical to the results of putting that string into a normalized form in
  accordance with any subsequent version of Unicode."
- "Once a character is assigned, its decomposition mapping will not change",
  and the same holds for its canonical combining class.
- The policy's own note names our exact risk: "If an implementation normalizes
  a string that contains characters that are not assigned in the version of
  Unicode that it supports, that string might not be in normalized form
  according to a future version of Unicode."
- `unicode-normalization` 0.1.25 exports `char::is_public_assigned` (assigned
  and not private use), built from the same Unicode 17.0 tables as its
  normalization data.

**Recommendation: option (a) from 10.7, with its compatibility boundary stated
precisely.**
1. **New refusal rule for H_c:** inspect the raw, valid-UTF-8 scalar values
   before NFC. A code point that is unassigned (General Category Cn) in
   pvault's Unicode version is refused. Private-use code points
   (U+E000–U+F8FF, planes 15 and 16) are allowed: Unicode fixes their category
   as Private_Use; they have no decomposition and combining class 0.
   `unicode_normalization::char::is_public_assigned(c)`, plus an explicit
   private-use-range test, implements that rule from the same tables used by
   normalization.
2. **Apply it at creation and at every H_c entry**, before Argon2id, like the
   other input-only refusal rules. The message depends only on typed input:
   "Character N is not supported by this version of pvault."
3. **Forward upgrades are preserved.** Every accepted H_c credential contains
   only characters assigned in its creating release. Strong Normalization
   Stability then makes its NFC bytes identical in every later Unicode
   version.
4. **Downgrades fail closed, but are not universally compatible.** If a vault
   created by a newer pvault uses a character unknown to an older release, the
   older release refuses the input before Argon2id; it cannot unlock that
   vault. If every character existed in the older release, the older release
   produces the same NFC bytes. A requirement that *every* newer custom
   credential remain usable by older binaries would instead require option
   (b), recording a normalization version and shipping old tables, or option
   (c), permanently frozen tables.
5. **Monotonic tables:** a test requires
   `unicode_normalization::UNICODE_VERSION >= (17, 0, 0)`. This prevents an
   accidental table downgrade; regression vectors protect the accepted NFC
   results. It is not the reason forward stability holds--Unicode's assigned-
   character guarantee is.
6. **No header field under this policy.** A `norm_unicode` diagnostic field
   would not make an older binary understand newer characters. It is needed
   only if the author chooses versioned historical tables instead.

**Generated-word normalization is a separate, now-complete recommendation.**
The toolchain's `char::is_whitespace` and `to_lowercase` are not a format:
Unicode explicitly says case folding is not lowercasing, and the language
tables can change. Define `H_w_v1` by this exact algorithm:

1. Accept at most 1024 raw UTF-8 bytes, decode strictly, and reject an empty
   input. Before transforming it, reject General_Category `Cn` under Unicode
   17.0.0; allow the three private-use ranges, matching the approved H_c
   boundary.
2. Apply Unicode 17.0.0 NFKC to the complete scalar sequence.
3. Apply **full default case folding** to that result: use `CaseFolding.txt`
   status `F` when present, otherwise status `C`; ignore `S` and Turkic `T`.
   This is Unicode's `toCasefold(toNFKC(S))`, not `NFKC_Casefold` (the latter
   also removes default-ignorables).
4. Map each maximal non-empty run from this frozen Unicode-17 `White_Space`
   set to one U+0020, and trim a leading or trailing run:
   `0009..000D, 0020, 0085, 00A0, 1680, 2000..200A, 2028, 2029, 202F,
   205F, 3000`. Do not call a toolchain whitespace predicate.
5. Encode UTF-8. Refuse empty output or output over 1024 bytes. For a
   generated-word credential, split only on U+0020 and require every token to
   be an exact ASCII EFF-list word before Argon2id.

**Audit correction (2026-10-05).** An earlier draft of step 5 cited an
"approved dummy-derivation timing rule". No such rule exists in the spec or in
`docs/SPEC_ISSUES.md`; SI-51 only requires both derivations to run when both
are defined. The case it was meant to cover is real and is a **gap**: for a
custom main passphrase with a duress tag, H_c can accept an input that
`H_w_v1` refuses (a character newer than Unicode 17 in a later release, or an
NFKC expansion beyond 1024 bytes). Then `duress_key` cannot be derived.
**Decided N3 (2026-10-05):** a candidate that generated-word handling refuses
is a duress non-match, and its duress-only derivation is skipped. This is
semantically exact, because a refused input can never equal ASCII list words.
- **Refusal classes:** an empty result after trimming; more than 1,024 bytes
  after NFKC; under `H_w_v1`, a code point unassigned in Unicode 17.0.0.
- **Timing difference, documented in spec 5.6:** such an unlock runs one
  Argon2id instead of two. A timing observer learns that the typed text is in
  a refused class, which for the correct passphrase is a property of the
  passphrase; nothing about keys, shares or the duress passphrase.
- **Reconciled statements:** every former unconditional "two runs" statement
  (spec 5.1 and 5.6; SPEC_ISSUES SI-51 sections 1 and 2, the cost table and
  the issue-table row) now names this exception.
- **Still pending:** whether to warn about it when a custom passphrase is
  created.

**`H_w_v1` amends an approved, implemented definition.** Spec 7.3 and the
Milestone 2 code (`passphrase.rs`) define H_w with the toolchain's
`White_Space` predicate and per-character `to_lowercase`. `H_w_v1` replaces
lowercasing with full default case folding, freezes the data at Unicode 17.0.0,
and adds the `Cn` refusal. For every valid generated credential (ASCII list
words) the bytes are identical; for other input they can differ (for example
`ß` folds to `ss`). Approval therefore also schedules, in Milestone 3, a change
to accepted Milestone 2 code and to the Python vector generator
(`tools/vectors/gen_vectors.py`, which uses per-character `str.lower()`), with
regenerated `pvault_passphrase.txt` vectors.

**Pinned-data policy.** `H_w_v1` always means Unicode 17.0.0; a dependency or
toolchain update must not change it. Generate pvault-owned tables offline from
the official `UCD.zip`, check the generated tables and generator manifest into
the repository, and use those tables at runtime. The manifest records the
source URLs, Unicode license, generator version and these SHA-256 values:

```text
UCD.zip                       2066d1909b2ea93916ce092da1c0ee4808ea3ef8407c94b4f14f5b7eb263d28e
UnicodeData.txt               2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c
DerivedNormalizationProps.txt 71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488
CompositionExclusions.txt     2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f
CaseFolding.txt               ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183
PropList.txt                  130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd
```

The build consumes the checked-in generated tables, never downloads or
regenerates them. CI regenerates to a temporary directory from a separately
verified archive and byte-compares. A future Unicode algorithm is `H_w_v2`
and a format revision; it never silently changes v1. No header Unicode field
is needed because v1 is permanent.

This does not alter the already approved H_c boundary: H_c remains raw-length
check, assigned-or-private-use check, then NFC using the implementation's
monotonically non-decreasing Unicode data. Unicode's assigned-character
normalization stability gives forward upgrade compatibility; an older binary
refuses a character it does not know. Freezing H_w does not turn that H_c
fail-closed downgrade boundary into universal backward compatibility.

**Does D2 preserve custom credentials across upgrades and older versions?**
Audit conclusion:
- **Upgrades: yes,** provided the rule runs at creation *and* at every entry,
  and pvault's own `normalize.rs` stays correct (regression vectors). Strong
  Normalization Stability guarantees identical NFC bytes for strings of
  characters assigned in the creating release. Private-use code points have no
  decomposition and combining class 0, permanently.
- **Older versions: only when every character is known to the older
  release.** Then the NFC bytes are identical, by the same guarantee. Otherwise
  the older release refuses the input before Argon2id, so it fails closed and
  never derives a different key. Universal backward compatibility would need
  option (b) or (c) of SPEC_ISSUES 10.7.
- **The duress derivation of a custom input** uses the frozen `H_w_v1`, so it
  is stable in both directions; the refused-input case is decided by N3.
- **Downgrade below the H_w_v1 release:** a release that still implements the
  Milestone 2 H_w (lowercase, toolchain tables) would derive a different
  `duress_key` for non-ASCII custom input. No vault exists before Milestone 18,
  so this matters only if a pre-H_w_v1 build is ever released; it must not be.

**Schema changes:** none. **Spec changes:** 7.3 (new refusal class, and the
`H_w_v1` definition replacing steps 3–4), SI-51 §3 (the "Limitation" bullet
becomes this rule), 5.8 (new input-only message).

**Tests.**
- An unassigned code point (for example U+0378 under Unicode 17) is refused at
  creation and at unlock, before any Argon2id run (counted with a
  test-only failpoint).
- U+E000 and U+F0000 (private use) are accepted.
- Regression vectors: fixed custom inputs (combining sequences, Hangul,
  compatibility characters, characters new in Unicode 16 and 17) with their
  pinned NFC bytes. These must never change across dependency updates.
- `unicode_normalization::UNICODE_VERSION >= (17, 0, 0)`, plus a test that a
  selected Unicode-18-only character is refused by a Unicode-17 fixture.
- The refusal message never contains the input (extends
  `errors_never_contain_the_input`).
- H_w vectors cover `Straße`/`STRASSE`, Cherokee, compatibility characters,
  every frozen whitespace range, Turkic I (default, not Turkic folding), and
  characters assigned after Unicode 17 (refused). The generated table hashes
  and complete Unicode normalization/case-fold conformance files are checked.

### D3. CBOR implementation and secret-buffer handling (SI-07, SI-20)

**Recommendation (revised).** In Milestone 0.5 the recommendation was option 1
(`ciborium` with caller-owned scratch and a comparing sink). It is now
**option 2: a fixed-schema, in-house codec for the 4.4 profile**, used for
every structure (header, key table, journal, `partials.cbor`, `cards.cbor`,
rollback record).

**Evidence.**
- **The profile is small:** unsigned integers, byte and text strings, arrays,
  maps, `true` and `false`; definite lengths; shortest heads; sorted text
  keys; depth at most 4. A decoder that accepts only this, and returns slices
  borrowed from the input, is deterministic by construction. It needs no
  re-encoding comparison and no serde.
- **`ciborium` 0.2.2, as found in SI-07:**
  - its decoder accepts non-shortest heads and indefinite lengths, and skips
    tags silently;
  - `deserialize_byte_buf` and `deserialize_string` grow buffers, leaving
    unwiped copies;
  - `from_reader` uses an unwiped 4 KiB stack scratch;
  - `Unexpected::Str` puts string content (paths) into error text.

  Option 1 is safe only while every one of these is avoided by discipline and
  by tests that depend on `ciborium` internals.
- **Milestone 2 lesson (M2-F1):** `unicode-normalization` leaked secret bytes
  only on an input shape (four or more combining marks) that ordinary tests
  never produced. An in-house decoder removes that class of dependency risk
  from the one parser that handles plaintext key material.
- **Dependencies:** `ciborium` is currently only a benchmark dependency (via
  `criterion`). Option 2 keeps it and serde out of the shipped binary.
- **Cost:** roughly 400 to 600 lines plus fuzzing. Fuzz targets are already
  planned (`header_parse`, `journal_parse`, `keytable_parse`; SI-17). It is
  serialization, not cryptography, so rule 3 allows it.

**Secret-buffer handling and allocation bounds (tightened from SI-07).**
- **Plaintext:** the key-table plaintext lives in one pre-allocated,
  best-effort-locked, zeroize-on-drop buffer only after (1) the authenticated
  core is available, (2) the on-disk file length is no larger than the exact
  ciphertext maximum derived from a 64 MiB plaintext and 7.7's record
  overhead, (3) a streaming whole-file SHA-512 digest has matched the core,
  and (4) the stream header's `plain_size` has passed the 64 MiB hard cap.
  Every size calculation is checked and every allocation is fallible.
  The current `SecretBuf::zeroed` uses `vec![..]` and is not fallible; a
  parser-facing fallible fixed-size allocation path is therefore required
  before it is used for an on-disk length.
- **Two-pass decoding:** pass 1 borrows from that buffer, validates the entire
  deterministic-CBOR structure, and computes with checked arithmetic the exact
  entry count, path bytes and file-key bytes. It allocates nothing. Pass 2
  allocates the approved representation once and fills it. No secret or path
  is copied before pass 1 succeeds.
- **Architecture-independent expanded limits.** A valid v1 key table has at
  most `MAX_KEYTABLE_ENTRIES = 65,536` entries. Pass 1 also computes, using
  checked `u64` arithmetic:

  ```text
  N = total entries
  F = file entries
  P = sum of the UTF-8 byte lengths of every path (no terminators or padding)
  decoded_charge = 4096 + 128*N + 64*F + P
  ```

  It rejects `decoded_charge > 134,217,728` bytes. The 4096 bytes charge all
  container/allocator metadata; 128 bytes per entry charges the descriptor;
  64 bytes per file charges both file keys; `P` charges the path arena. The
  formula and entry cap are v1 validity rules and produce the same answer on
  32- and 64-bit targets. (Audit note: with `P` below the 64 MiB plaintext cap
  and `N ≤ 65,536`, the charge cannot exceed about 76 MiB. The 128 MiB bound
  is therefore defensive and never binding in v1; the binding limits are the
  plaintext cap and the entry cap, decided N5.) They never use `size_of::<Entry>()`, pointer width,
  allocator size classes or page size. Lowering either limit would be a format
  change.
- **Whole parser working set:** let `C` be the authenticated `plain_size`, also
  the exact capacity of the locked plaintext buffer. The streaming decryptor
  has one fixed 131,072-byte charge covering its input/output chunk scratch and
  parser stack; it never buffers the ciphertext file. Before allocation, require
  available memory for
  `keytable_working_charge = C + decoded_charge + 131,072`, with checked `u64`
  arithmetic. Since `C <= 64 MiB` and `decoded_charge <= 128 MiB`, the v1
  parser charge is at most 192 MiB + 128 KiB. This resource charge includes all
  heap capacity retained concurrently by key-table decryption and decoding;
  implementation objects must fit inside their assigned fixed charges.
- **Implementation conformance, separate from validity.** The chosen compact
  descriptor and three exact-capacity arenas must allocate no more than their
  semantic charge. A build-time layout assertion and per-target allocation
  test enforce that implementation property, but their result never decides
  whether a vault is valid. A fallible allocation can still fail below the cap;
  that is the 4.3 resource error, not `KeyTableCorrupt`.
- **Storage recommendation:** one exact entry arena, one zeroizing path arena,
  and one best-effort-locked, zeroizing file-key arena. Entries hold ranges or
  indices into the arenas. All arena lengths come from pass 1; capacities equal
  lengths and never grow. This avoids per-entry `Box` allocations and permits
  one checked, fallible allocation per arena. A representation that exceeds
  the fixed semantic charge is non-conforming even if it happens to fit on the
  developer's architecture.
- **Copies and destruction:** authenticated stream decryption writes directly
  into the single locked plaintext buffer. Pass 2 copies each 64-byte file-key
  pair directly into the locked key arena and each path directly into the
  zeroizing path arena; no temporary `String`, `Vec<u8>` or formatting object
  is permitted. The plaintext, key arena and every partially initialized
  allocation zeroize on every return path, including allocation failure and
  panic. Paths are confidential and zeroized but, by the stated classification,
  are not separately locked after leaving the locked plaintext buffer.
- **Errors:** every key-table decode failure is one payload-free
  `KeyTableCorrupt` error. Proposed 5.8 message: "The key table is damaged.";
  it is reachable only after AEAD authentication.
- **Path classification:** paths are confidential, zeroized, and not locked.
  This classification is part of the approval.
- **Encoding:** writes directly into the caller's fixed, locked output buffer.
  A first sizing pass uses checked arithmetic and enforces the 64 MiB plaintext
  cap before that buffer is allocated.
- **All other parsers:** read at most their document cap (header 64 KiB,
  journal 16 KiB) into a fixed/capped buffer. CBOR lengths are checked against
  remaining input and schema maxima before conversion to `usize`; map/array
  counts never drive a reserve until the schema cap is known. Parser depth is
  tracked in a fixed stack. `partials.cbor`, `cards.cbor` and `rollback.cbor`
  need explicit file-size and entry-count caps before their schema decoders are
  implemented; the generic codec must not make an unbounded allocation for
  them.

**Tests.**
- **F14:** an oversized header (over 64 KiB), non-shortest heads, indefinite
  lengths, tags, floats, `null`, negative integers, unsorted or duplicate
  keys, unknown keys, depth 5, trailing bytes. All rejected without a large
  allocation (allocation-counting test).
- **F71:** journals over 16 KiB, non-canonical, or with out-of-cap Argon2
  parameters; rejected before any derivation.
- **Round trips:** `proptest` round trips for every schema; encoder output
  equals published `FORMAT.md` vectors, cross-checked against an independent
  Python `cbor2` encoder in `tools/vectors`.
- **Key-table decode hygiene:** pass 1 allocates zero bytes; pass 2 performs
  only the three approved exact arena allocations, with no reallocation and no
  non-zero freed block (the Milestone 2 heap-hygiene method). Boundary vectors
  prove the same accept/reject result on 32- and 64-bit targets at `N`, `F`,
  `P`, one entry over the cap and one byte over `decoded_charge`.
- **Errors:** `KeyTableCorrupt` and every decode error contain no input bytes.
- **Fuzzing:** the three fuzz targets build, with smoke runs in CI (the long
  runs are Milestone 7).

### D4. Lock protocol (SI-14)

**Recommendation.** Approve the gate-plus-vault-lock part of SI-14 for
Milestone 3:
- `vault.gate` (G) and `vault.lock` (L): zero-length lock files, created
  without following symlinks, mode `0600`, opened once per process, never
  deleted.
- All tries are non-blocking. The only bounded wait (up to 2 s) is a holder of
  L retrying G.
- A handle that holds a lock is never re-locked; conversion is unlock-then-lock
  under G.
- Exclusive acquire and downgrade as specified in SI-14.

Defer the mount lock M (`vault.mount`) and upgrade-for-commit to SI-45
(Milestone 11), and P and T to Milestone 4 (7.9). Reserve the `vault.mount`
name now, so Milestone 3's directory checks treat it as a pvault file.

**Evidence (SI-14):**
- Linux and macOS `flock(2)` conversion is not atomic.
- `LockFileEx` has no conversion.
- Rust's `File::lock` leaves re-locking the same handle unspecified, possibly
  a deadlock.
- The G + L design forms no wait cycle.
- Open item: Windows `LockFileEx` on zero-length files is expected to work,
  because a lock range may extend past end-of-file, but must be shown by a
  Windows CI test.

**Schema changes:** none (files only). Spec 4 layout gains `vault.gate`.

**Tests.**
- **F56a:** two concurrent mutating processes, where the second is refused
  with "The vault is in use by another pvault process". A child killed while
  holding L releases it, and the next process proceeds.
- **Windows:** `LockFileEx` on a zero-length file, shared and exclusive, in CI.
- **Downgrade under G:** a concurrent exclusive acquirer always fails cleanly
  and never deadlocks (a stress test with bounded time).
- **Lock-file creation:** refuses a symlinked `vault.lock` or `vault.gate`;
  mode `0600` on Unix.
- **One handle per process:** a test-only assertion trips if pvault opens a
  lock file twice.
- **F58:** the generation check aborts a commit when another writer changed
  `core.generation`.

### D5. File-system support and durability (SI-12, SI-13)

**Recommendation.** Approve the Linux and macOS sequences below. Windows needs
one explicit product choice because its public user-mode contract does not
establish the same power-loss property; do not turn that gap into an implicit
read-only platform or an undocumented weaker guarantee.

| Platform | Required sequence | Process-crash consistency | Power-loss durability |
| --- | --- | --- | --- |
| Linux: exactly `ext4`, `xfs`, `btrfs` | write tmp; `fsync(tmp)`; same-directory `renameat`; `fsync(dirfd)` | `renameat` is the visibility commit point | Recommended under the existing 8.5 assumption that every call succeeds and the device honors flushes |
| macOS: exactly APFS or HFS+ | write tmp; `fcntl(tmp,F_FULLFSYNC)`; same-directory `renameat`; `fsync(dirfd)`; `fcntl(dirfd,F_FULLFSYNC)` | Apple documents that an instance of the destination always exists even if the system crashes during `rename` | Recommended under the same device-honors-flushes assumption; both directory calls are required and either failure enters the post-replacement rule below |
| Windows: exactly NTFS or ReFS | write tmp through a `FILE_WRITE_THROUGH` handle; `FlushFileBuffers(tmp)`; reopen the source no-follow and `FILE_WRITE_THROUGH` relative to the held directory with `NtCreateFile`; same-directory `NtSetInformationFile(FileRenameInformation)` replacement; reopen and authenticate `hdr` | A native kill-at-each-step probe can establish observer/process behavior for tested releases, not the power-loss contract | **Author-selected W1, amended to name the required handle-relative primitive:** writable under the explicit assumption below; this is not verified power-loss safety |

For create-without-replacement, use the already specified no-replace primitive
and the same file/directory flush sequence. A primitive that reports
unsupported is a refusal, never permission to substitute a weaker call.

**Primary evidence and focused probes (2026-10-05).** Apple's
[`fsync(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
warns that `fsync` alone need not survive OS or device power loss and directs
durability-sensitive software to `F_FULLFSYNC`; its
[`fcntl(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
describes that command as `fsync` plus a request to drain the drive to permanent
storage. The macOS 27 SDK man page says it is implemented on HFS and APFS.
Apple's [`rename(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/rename.2.html)
states the destination always has an instance even if the system crashes
during the operation.

A disposable C probe in `/private/tmp` on macOS 27.0, APFS, arm64 performed
regular-file `fsync`, regular-file `F_FULLFSYNC`, replacement `rename`,
directory `fsync`, and directory `F_FULLFSYNC`; every call returned success,
including both directory calls before and after rename. This establishes API
support on the tested APFS stack, not simulated power-cut behavior. No HFS+
volume was available; the HFS+ recommendation rests on Apple's documented
implementation and must still get the same CI probe when an HFS+ runner is
available.

Microsoft documents that
[`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
flushes a file, but flushing a whole volume requires administrator privilege.
It marks `REPLACEFILE_WRITE_THROUGH` as
[`not supported`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
For
[`MoveFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw),
the specific `MOVEFILE_WRITE_THROUGH` guarantee says a move implemented as
copy-and-delete is flushed; it does not state that same-volume replacement is
atomic and directory-durable across power loss. Microsoft's CreateFile flag
documentation separately says an NTFS write-through request flushes metadata
changes such as a rename resulting from the request. That supports requesting
`FILE_WRITE_THROUGH` on the verified source handle, but does not establish
ReFS behavior, old-or-new crash atomicity, power-loss safety or
`NtSetInformationFile`/`MoveFileExW` equivalence. This review host cannot run a
native Windows probe. The required Windows CI probe kills the writer before,
during and after replacement, reopens through a fresh process, and accepts
only a fully authenticated old or new header; a VM hard-power-cut campaign is
additional evidence but cannot manufacture a missing platform contract.

**Selected Windows direction (W1), reconciled with the handle-relative
correction.** Keep NTFS/ReFS mutation support and adopt this explicit platform
assumption; the primitive name replaces the earlier path-based draft:

> After the temp-file flush, successful same-volume handle-relative
> `NtSetInformationFile(FileRenameInformation)` replacement leaves either the authenticated old header or
> the authenticated new header after process, OS or power failure.

This assumption is not a Microsoft-documented guarantee and is not verified
power-loss safety. Keep the journal/restart rules below. Native process-crash
and VM power-cut probes are evidence about tested configurations only and must
not upgrade the claim. This is the selected policy amendment to 8.5. The
unselected alternatives were read-only Windows v1 and a redundant-header
format redesign.

**Detection** (7.6a "file-system type queries"), from the open vault-directory
handle:
- **Linux:** obtain the mount ID for the already-open vault-directory handle
  from `/proc/self/fdinfo/<fd>` (or `statx(..., STATX_MNT_ID)`), match that ID
  to field 1 of `/proc/self/mountinfo`. Parse each record by splitting on ASCII
  spaces and, after the six fixed fields, scanning for the first token exactly
  equal to `-`; optional fields make its position variable. Require all six
  fixed pre-separator fields, that separator, and at least the three documented
  post-separator fields. A later `-` can be ordinary post-separator data and is
  not treated as a second separator.
  The file-system type is the token **immediately after `-`**, not “field 9”.
  Accept only the exact byte string `ext4`, `xfs` or `btrfs`. Linux documents
  the format and mount-ID correspondence in its
  [proc filesystem documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html).
  `fstatfs` magic may be a secondary consistency check, never the
  deciding identification. If `/proc` is unavailable, the mount ID has no
  exactly one matching record, the separator or required fields are malformed,
  or the type is anything else, the result is unknown and mutations are
  refused. Numeric IDs are parsed with checked arithmetic; path escape decoding
  is unnecessary because neither path field participates in this join.
- **macOS:** `fstatfs` `f_fstypename` equal to `apfs` or `hfs`.
- **Windows:** `GetVolumeInformationByHandleW` file-system name equal to
  `NTFS` or `ReFS`.

`EXT2_SUPER_MAGIC` and `EXT4_SUPER_MAGIC` are both `0xEF53`; ext3 commonly
shares it as well. Therefore accepting that magic would silently broaden the
allowlist and is rejected. Parsing the kernel's mount record is not trusting a
user-supplied path name: the lookup is joined by the open handle's mount ID and
the type is kernel-reported. A held directory descriptor also avoids a
check-then-use path lookup.

**Audit additions to detection (2026-10-05; recommendations for review).**
- **Windows remote volumes.** Over SMB, `GetVolumeInformationByHandleW`
  reports the *server's* file-system name, commonly `NTFS`. A name check alone
  would therefore make a network share writable, contradicting 8.5 ("network
  file systems are read-only"). **Exact criterion (2026-10-05; spec 8.5):**
  on each held directory handle, all four queries must give the accepting
  result, checked in order:
  - Q1: `FileRemoteProtocolInfo` **fails** with `ERROR_INVALID_PARAMETER` or
    `ERROR_NOACCESS`; native Windows CI run 37390554153 observed
    `ERROR_NOACCESS` (998) on the runner's local NTFS temp directory; success
    means remote, and any other error means unknown;
  - Q2: `GetFinalPathNameByHandleW(VOLUME_NAME_GUID)` returns a
    `\\?\Volume{` path;
  - Q3: `GetDriveTypeW` on that volume root is `DRIVE_FIXED` or
    `DRIVE_REMOVABLE`;
  - Q4: `GetVolumeInformationByHandleW` names exactly `NTFS` or `ReFS`, and
    for `objects/` the serial number equals T's.

  Every other result refuses, with no weaker retry. Microsoft does not
  document one unique Q1 error for a local handle. Q2's SMB behavior remains
  unverified: native probes still need local ReFS, a VHD, a mapped SMB drive
  and an available UNC path. Until every query matches an accepted result,
  the criterion fails closed. The `DRIVE_*`
  constants need the not-yet-enabled `windows-sys` feature
  `Win32_System_WindowsProgramming` (a feature addition at implementation
  time, not a new crate).
  (Linux reports `cifs`/`nfs`/`fuse.*` and macOS `smbfs`/`nfs`/`macfuse`, so
  the exact type allowlists already exclude them there.)
- **Every directory pvault writes in.** `objects/` is a separate directory and
  can be a different mount. Identify it with the same procedure from its own
  held handle, and require it to be the same mount (Linux mount ID; macOS
  `f_fsid`; Windows volume serial number and the remote check) as the vault
  directory. Otherwise refuse.
- **Kernel requirements (Linux).** `/proc/self/fdinfo/<fd>` carries `mnt_id`
  since Linux 3.15, and `statx(STATX_MNT_ID)` exists since 5.8. On older
  kernels identification is "unknown", so mutations are refused.

**Durability capability preflight (consistency with refusal-on-unsupported).**
Section 7.6a requires an unsupported required primitive to be a *refusal*. The
boundary table below instead treats a failed post-replacement flush as
"committed-visible, durability unknown". Both hold only if "unsupported" is
detected **before** any mutation, so that a post-replacement failure can only
be a genuine I/O error, never a predictable `ENOTSUP`. Recommendation: before
the first side effect of every mutating operation, and on the held handles,
perform:
- `fsync(dirfd)` on Linux;
- `fsync(dirfd)` and `fcntl(dirfd, F_FULLFSYNC)` on macOS;
- on Windows, open-with-`FILE_FLAG_WRITE_THROUGH` support (implicit in the
  journal or temp creation, which precedes any other side effect);
- the file-identity primitives of D6, including birth-time support on Unix.

Any `ENOTSUP`, `EINVAL` or equivalent classifies the file system as failing
8.5, and the operation is refused with the 8.5 message before anything is
written. **A passing preflight never weakens post-commit handling.** Any
failure after the header replacement call has been issued, whatever its error
code (even `ENOTSUP` or `EINVAL` after a passing probe), is handled by the
boundary table ("outcome unknown" or "committed-visible, durability unknown").
It is never treated as a refusal or a pre-commit abort. The preflight only
removes *predictable* unsupported cases before any write.

**Scope of the selected W1 assumption: decided N1 (2026-10-05), primitive
amended by the handle-relative correction.** W1 covers the flushed-temp,
handle-relative `NtSetInformationFile` *replacement* of the header. The
write-through source handle has documented NTFS metadata-flush relevance, but
does not establish the rest of W1 or the Windows ordering assumptions.
The protocols also need earlier creations and deletions to be durable in
order, which Linux and macOS get from the directory flush and Windows cannot
(no non-administrator directory flush). The author chose to document the
risk rather than broaden the assumption. Spec 8.5 now names the **unverified**
Windows ordering assumptions:
- **WO-1:** journal first;
- **WO-2:** key table durable before the header that references it;
- **WO-3:** deletions never overtake the commit.

It states that a Windows power loss or OS crash during a commit can leave a
vault **unreadable**. The key table holds the per-file keys, so passphrase and
cards cannot restore it; only a whole-folder backup can. Process-crash tests
cannot exercise these assumptions. Spec Section 2 and the FAILURE_MODES list
(Section 14) carry the same statement.

**The header has two boundaries, not one undifferentiated “abort”.** The
visibility commit point is successful atomic replacement of `vault.hdr`.
Durability is confirmed only after the required directory/full flush succeeds.

| Failure point | Meaning and required action |
| --- | --- |
| Before calling header replacement | Pre-commit abort. The old authenticated header remains authoritative. Retain the journal until rollback of every journaled artifact/index and its directory changes is itself durably flushed; only then durably unlink the journal. |
| Generation check finds a different on-disk generation | Do not call replacement. The already-written temp and journal remain. Report "The vault changed during this operation. The header was not committed." |
| Replacement call reports failure | Outcome is not assumed. Reopen `vault.hdr` relative to the held directory handle. Exact old bytes return the original pre-commit error; exact new bytes follow the post-replacement row; neither, absence or unreadable state retains the journal and temp, performs no cleanup and reports "The header replacement outcome could not be determined. Run fsck before making further changes." |
| Replacement succeeds; required directory/full flush succeeds | Commit and durability confirmation are complete. Post-commit cleanup may run. The journal remains until that cleanup is either resolved or moved into authenticated `tpm_cleanup`, then journal deletion is directory-flushed. |
| Replacement succeeds; required directory/full flush fails | **Committed-visible, durability unknown**, never an ordinary abort. Return a distinct “The new header is visible, but commit durability could not be confirmed; run fsck.” error. Keep the `committing` journal and all old and new dependencies; do not delete an old key table, object, bundle material or TPM index. A retry may repeat the directory flush, but may not replace the header again as an “abort”. |
| Journal unlink succeeds; its directory flush fails | Report durability unknown. A stale journal is harmless: restart authenticates it and resolves it from the header. Never assume it is gone. |

The journal must have been written, file-flushed, renamed and directory-flushed
before header replacement. Ordinary (non-bundle-changing) commits apply the
same boundary: on post-replacement flush failure retain both generations and
all destructive cleanup; the authenticated header and its key-table digest
choose the live generation on restart.

**Restart under the exclusive lock.** Never select a side from a generation
number alone; authenticate the header and the applicable journal MAC, and
compare the expected vault/setup IDs and core state.

| Authenticated state observed | Restart action |
| --- | --- |
| Exact old core and valid old-side journal MAC | Pre-commit side: finish rollback; retain the journal until rollback is durable. |
| Exact new core and valid new-side journal MAC | Post-commit side: first repeat the directory/full flush; only after success perform or defer cleanup, then durably remove the journal. |
| Init journal and no header | Pre-commit init rollback under the safe-init table in D6. |
| Init journal and exact matching committed header | Preserve the live index and dependencies; authenticate as D6 requires, repeat directory/full flush, then durably remove the stale journal. |
| Header absent, malformed, authenticates as neither expected side, or record/header identifiers disagree | Indeterminate. Delete nothing and report for recovery/fsck. |

**Tests.**
- **F74 (detection part):** fixtures for mountinfo/fdinfo and a test-only hook
  distinguish `ext2`, `ext3` and `ext4`; only `ext4` is accepted. Fixtures put
  zero, one and several optional fields before `-`, and malformed records have
  no separator, fewer than six fixed fields, missing post-fields, overflowing
  IDs and duplicate matching mount IDs. A `-` in a post-separator field does
  not shift the file-system type. Unknown, missing and ambiguous mount IDs
  refuse every mutation and write nothing. Read-only commands are unaffected.
  Add an ext2 loop-image integration test wherever CI privileges permit; it
  must be refused even though `fstatfs` reports `0xEF53`.
- **Primitive unit tests:**
  - `tmp → flush → rename → dir flush` replaces atomically for observers;
  - the no-overwrite rename refuses an existing target;
  - no-follow opens refuse symlinks.
- **macOS:** keep the APFS probe in CI and add HFS+ when a runner exists. An
  `ENOTSUP`, `EINVAL` or I/O error is handled by the boundary table, not a
  fallback to `fsync` alone.
- **Windows:** run the native fresh-process probe on both NTFS and ReFS if W1
  is chosen; retain the documented assumption even when the probe passes.
- **Failpoints:** every call before replacement, replacement-return ambiguity,
  the gap after replacement, both directory flushes and journal-unlink flush.
  After restart, only old or new authenticated state is acted on and no old
  dependency is retired while durability is unknown.
- **Documentation:** process-crash tests (F25, F26, F44, F45, F54, F67) do not
  establish power-loss safety.

### D6. Init journal, TPM-identity fields and the cleanup list (SI-38 schema, SI-36, SI-35 c)

**Finding: the proposed MAC-only identity layout is not viable across bundle
rotation.** Do not approve the `tpm_id_mac` fields in the draft.

Suppose recovery occurs away from the TPM that owns the old index. The old
authenticated slots provide only
`HMAC(K_mac_old, vault_id || ek_digest_old)`. HMAC is not invertible, so the
operation cannot compute any of the following:
- the draft's new-key `old_tpm_id_mac_n` in the committing journal;
- a `K_mac_new` identity MAC for `pending_tpm_cleanup`;
- the next new-key MAC when that pending entry survives another bundle
  rotation; or
- the old duress-tag check during remote recovery, because the revised tag
  also needs `ek_digest_old`.

Writing both old-key and new-key MAC fields does not solve this: the new-key
value cannot be created when the old TPM is absent. This is exactly the case
deferred cleanup is meant to support.

**Recommended replacement: a confidential, rekeyable TPM-identity token.**
This section fixes the algorithm, scopes and representation; none is left to
implementation discretion.

`tpm_id_template = 1` means the published TCG EK Credential Profile 2.5 R2,
template H-2, ECC NIST P-256 storage EK: `type=ECC`, `nameAlg=SHA256`,
`fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|adminWithPolicy|
restricted|decrypt`, 32-byte Policy-B-SHA256 value
`ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0`,
AES-128-CFB symmetric definition, null ECC scheme, NIST P-256 curve, null KDF
and empty input `unique`. The definition is from the
[TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-V-2.5-R2_published.pdf),
not “whatever the TPM library currently calls its default.” Unknown enum
values are a parse failure. The enum remains in every token so a later template
cannot silently reinterpret a v1 record.

After `CreatePrimary(TPM_RH_ENDORSEMENT)`, `ek_digest` is
`SHA-256(MU-marshal(returned TPMT_PUBLIC))`: hash the canonical TPM wire
marshalling of the returned public area, including the populated `unique`
point, but excluding the outer `TPM2B_PUBLIC.size`. Flush the transient object.
All pvault NV public areas use `nameAlg=TPM_ALG_SHA256`, so each stored Name is
exactly 34 bytes (the two-byte algorithm identifier plus 32-byte digest).

For each token derive a 32-byte key as
`HKDF-SHA-512(ikm=base_key, salt=empty, info=label, L=32)`. Encrypt the exact
32-byte `ek_digest` with XChaCha20-Poly1305, a fresh random 24-byte nonce and
the AAD below. The ciphertext including tag is exactly 48 bytes.

```text
AAD = ASCII("pvault/v1/tpm-id-token\0")
   || u8(scope)
   || vault_id[16]
   || u8(tpm_id_template)
   || u32_be(tpm_index)
   || u8(name_prewrite_present)       // exactly 0 or 1
   || (name_prewrite[34] if present)
   || name_postwrite[34]
   || policy_nonce[32]
```

| Scope | Value | HKDF label | Base key |
| --- | ---: | --- | --- |
| current bound slots | 1 | `pvault/v1/tpm-id/slots` | current `K_mac` |
| safe-init journal | 2 | `pvault/v1/tpm-id/init` | `init_journal_key` |
| new index, old side of transition | 3 | `pvault/v1/tpm-id/new-index/old-side` | `journal_key(old_bundle)` |
| reserved (decision N4) | 4 | not used in v1 | none |
| core cleanup record | 5 | `pvault/v1/tpm-id/cleanup` | current `K_mac` |

Decrypt only after the containing slots/core/journal MAC verifies. Bind the
token's fields again in that outer MAC. A scope mismatch, AAD mismatch or AEAD
failure is corruption and never falls through to TPM deletion. Every rewrap
uses a fresh nonce and zeroizes the digest immediately.

This token permits old-bundle code to decrypt the authenticated old identity
and re-encrypt it for the new bundle without contacting the old TPM. It also
lets remote recovery verify a re-entered old duress passphrase against the old
tag. The measured live TPM digest is compared in constant time only when an
actual deletion is attempted.

**Exact flattened schemas.** A nested token map would exceed the depth-4 CBOR
profile. Fields shown as conditional are absent, not `null`.

- Bound slots add `tpm_id_template: u8(1)`, `tpm_id_nonce: bytes(24)`, and
  `tpm_id_ct: bytes(48)`. Their AAD uses `tpm_nv_index`, no prewrite Name,
  `tpm_nv_name` as postwrite Name, and `tpm_policy_nonce`.
- Bound init `IDX` adds `new_tpm_id_template: u8(1)`,
  `new_tpm_id_nonce_i: bytes(24)`, and `new_tpm_id_ct_i: bytes(48)` (scope 2),
  alongside `new_tpm_index`, `new_name_prewrite`, `new_name_postwrite` and
  `new_policy_nonce`.
- Bound transition `IDX` adds the same context fields but names its old-side
  scope-3 token `new_tpm_id_nonce_o: bytes(24)` and
  `new_tpm_id_ct_o: bytes(48)`. The `_i`, `_o` and `_n` suffixes mean init,
  old-bundle side and new-bundle side; they are part of the schema.
- A transition `committing` record carries **no** old-index fields (decision
  N4). The old index of authenticated bound old slots is tracked only by the
  scope-5 `tpm_cleanup` entry pre-staged in the new core.
- `CoreFields` gains a required `tpm_cleanup` array, empty when there are no
  records and limited to 32. Each flattened map is:

  ```text
  TpmCleanupEntry {
    tpm_index             u32
    name_prewrite         bytes(34) optional
    name_postwrite        bytes(34)
    policy_nonce          bytes(32)
    tpm_id_template       u8 = 1
    tpm_id_nonce          bytes(24)
    tpm_id_ct             bytes(48)
  }
  ```

  Entries are sorted bytewise by `(tpm_index, name_postwrite, policy_nonce,
  tpm_id_template, tpm_id_nonce, tpm_id_ct)`; exact duplicates are forbidden.
  Semantic duplicates are coalesced only after authenticated decryption proves
  their digests and all AAD context equal. Core-map canonical key order is
  recomputed after adding `tpm_cleanup` and published in `FORMAT.md`.

The future bound header carries the new index token under `K_mac_new` with
scope 1. The committing journal therefore needs no new-side copy of the new
identity. Portable targets have no slots token. Likewise, after N4 the
journal carries no old-index identity: when the old slots were authenticated
and bound, the old index is pre-staged as a scope-5 cleanup entry in the new
core. During every bundle
rotation, authenticate and decrypt every existing cleanup token under old
`K_mac`, then re-encrypt it under new `K_mac` scope 5 with a fresh nonce; one
failure aborts before any new files or header are written.

**Capacity and overflow.** The exact limit is 32 records. Before an operation
that may create a target index or retire an authenticated old index, first
resolve locally inspectable records and coalesce records only when all context
fields and the decrypted digest are identical. If the operation can need a
new record, reserve one free slot before writing a journal, defining an index,
or creating a target key table. If 32 distinct unresolved records remain,
refuse with “TPM cleanup capacity is full; resolve a recorded index on its
original TPM.” Never evict the oldest record, overwrite one, or create an
untracked index. A full vault remains readable and operations that cannot add
a record may proceed. Thirty-two worst-case maps fit below the 64 KiB header
cap; a boundary vector fixes the exact encoding size.

**Successful transition tracking.** If the old slots authenticate as bound,
put the old committed index into the new core's cleanup array, already
rewrapped under `K_mac_new`, in the same header commit that rotates the bundle.
Only then attempt deletion. A successful/absent result remains recorded until
the next ordinary generation-plus-one commit prunes it; this avoids an
untracked window. On another TPM the record simply remains, while the new vault
is usable and can survive any number of later bundle rewraps.

**Remote rollback needs a schema state now.** A target index created before a
transition commit can also be stranded when `fsck` runs on another TPM. The
journal gains phase `rollback_tracking` and required `tracking_gen = old_gen +
2`; starting the operation requires `old_gen <= u64::MAX-2`. The record retains
all original new-index fields, adds `cleanup_tpm_id_nonce: bytes(24)` and
`cleanup_tpm_id_ct: bytes(48)` (scope 5 under old `K_mac`; template and AAD
context are the original new-index fields), and has one `mac` under
`journal_key(old_bundle)`. Before writing the phase, rewrap scope 3 to scope 5.
Then write an old-bundle key table at `tracking_gen` and an old-mode header at
that generation whose `tpm_cleanup` includes the target record. (Audit item 1
below splits this into `tracking_created`, which records `tracking_gen`, the
scope-5 rewrap and the tracking key-table temp identity before any key-table
bytes, followed by `rollback_tracking`, which adds `tracking_core_digest` and
the header-temp identity.) This deliberate
`+2` avoids colliding with the abandoned target key table at `new_gen`. Once
that header and directory are durable, the vault can discard the abandoned
target files and durably remove the journal; the index remains tracked for its
original TPM.

**Exact core-state binding in every journal.** Reuse the header definition,
not a second digest algorithm:

```text
expected_core_digest = SHA-512("pvault/v1/core" || canonical_cbor(CoreFields))
```

Each digest is a CBOR `bytes(64)` field and is covered by the journal MAC. A
single-MAC record is encoded without `mac`; a dual-MAC record is encoded without
both `mac_old` and `mac_new`, exactly as 8.1 already specifies.

| Journal schema | Required expected-core fields |
| --- | --- |
| transition `prepared`, `target_created` | `old_core_digest` (plus `old_keytable_digest`, audit item 1) |
| transition `committing` | `old_core_digest`, `new_core_digest` |
| transition `tracking_created` | `old_core_digest` |
| transition `rollback_tracking` | `old_core_digest`, `tracking_core_digest` |
| init `prepared` / `keytable_created` | none; no complete target core exists yet |
| init `keytable_written` / `committing` | `new_core_digest` |

The transition writer computes `old_core_digest` from the exact authenticated
core read at operation start and durably writes the `prepared` journal before
any target index or artifact. It never updates that field. After every new-core
dependency is durable, it computes the exact `new_core_digest`, writes the
dual-MAC `committing` journal and directory-flushes it before creating or
replacing `vault.hdr`. A rollback-tracking writer first constructs the exact
tracking core (including `generation=tracking_gen`, its key-table digest and
the new cleanup entry), then writes and flushes the journal containing
`tracking_core_digest` before replacing the header.

Restart classification requires both authentications: verify the candidate
bundle's `core_mac`, recompute the actual header `core_digest`, compare it in
constant time to the applicable journal field, and verify the corresponding
journal MAC (`mac`/`mac_old`/`mac_new`). Generation, mode or file names alone
never select a side. A header matching no expected digest is indeterminate and
authorizes no cleanup.

Rollback tracking changes `CoreFields`, so it also changes the value bound by
`slots_mac`. The tracking header keeps the exact old authenticated `SlotFields`
but recomputes both:

```text
core_mac_tracking  = HMAC-SHA-512(K_mac_old,
    "pvault/v1/core-mac" || canonical_cbor(TrackingCoreFields))
slots_mac_tracking = HMAC-SHA-512(K_mac_old,
    "pvault/v1/slots-mac" || tracking_core_digest || canonical_cbor(OldSlotFields))
```

This is permitted only if the old `slots_mac` verified before the tracking
rewrite. Re-MACing unauthenticated provisional slots would promote attacker-
controlled TPM or duress fields to authenticated data. If old slots do not
authenticate and the target index cannot be resolved on the present TPM, keep
the journal and leave the transition blocked until the target's original TPM
can resolve it; do not write a tracking core.

**The duress formula may still bind `ek_digest` directly:**

```text
duress_tag = HMAC-SHA-512(duress_key, "pvault/v1/duress-tag" || vault_id || "bound"
             || u32_be(tpm_nv_index) || tpm_nv_name || tpm_policy_nonce || ek_digest)
```

On ordinary unlock the authenticated slots token supplies the expected digest
after the bundle exists. On the no-bundle duress path, the live TPM measurement
is used in the tag computation. During remote recovery, the old bundle opens
the old token so the old tag can be checked without the TPM.

**Transition/cleanup state table.** Each row runs under the exclusive lock and
the D5 flush boundary. “Old/new/tracking header” means the exact authenticated
core expected by the journal, not merely a matching number.

| Journal phase; observed header | Required action, including remote TPM |
| --- | --- |
| `prepared` or `target_created`; header core matches `old_core_digest` | Verify old core MAC and journal MAC. If the target index is absent, foreign on the matching TPM, or safely deleted under 9.2b, durably remove the target artifacts **whose identity the journal records** (none in `prepared`), then the journal. If it may exist on another TPM and old slots authenticate, write `tracking_created` and continue the `tracking_gen` commit. If old slots do not authenticate, retain the journal and block. |
| `committing`; header core matches `old_core_digest` | Verify `mac_old`; use the same rollback rule as `prepared`. The new-side cleanup has not committed. |
| `tracking_created`; header core matches `old_core_digest` | Verify old core, old slots and journal MACs. Resume the tracking key table **in place** through its recorded identity (truncate and rewrite; never recreate it under a new identity). Resolve the committing header temp retained in `header_*` (identity-checked unlink plus directory flush), then continue to `rollback_tracking`. |
| `rollback_tracking`; header core matches `old_core_digest` | Verify the old core MAC, old slots MAC and journal MAC; repeat/complete the old-bundle `tracking_gen` key-table and header commit only through the recorded tracking-header-temp identity. If that temp is absent, the state is indeterminate: keep the journal, delete nothing, create no replacement, and run `fsck`. No single cause is inferred. A present identity mismatch is unowned residue and stays blocked for owner confirmation. The journal remains through a directory-flush failure. |
| `rollback_tracking`; header core matches `tracking_core_digest` | Verify the tracking core MAC, recomputed tracking `slots_mac` and journal MAC. The cleanup record is authoritative. Repeat the directory flush, remove only authenticated abandoned target artifacts, flush, then durably remove the journal. Do not require the remote TPM. |
| `committing`; header core matches `new_core_digest` | Verify the new core MAC and `mac_new`. Repeat the directory flush. Preserve the pre-staged old-index cleanup record; attempt deletion only on a matching TPM, then finish authenticated non-TPM cleanup and durably remove the journal. |
| Any phase; missing, invalid or unexpected authenticated core | Indeterminate: delete no file or TPM index and report. |

Cleanup inspection itself is deterministic:

| Live observation after unlock | Record action |
| --- | --- |
| TPM identity cannot be measured or does not match token | Do not touch the handle; retain and report “recorded, original TPM unavailable.” |
| Matching TPM; handle absent | Mark resolved; remove the record only in the next durable header commit. |
| Matching TPM; public area/Name equals an allowed prewrite or postwrite state | Apply all 9.2b ownership checks and delete; on success/confirmed absence, prune in the next commit. |
| Matching TPM; handle exists but Name/public area is neither allowed state | It is not this recorded index; do not delete it. The old index is confirmed absent/reused, so prune the record in the next commit and report the reuse. |

**Committing header temp before rollback tracking (2026-10-05; spec 8.1).**
- `tracking_created` retains a replaced `committing` record's `header_*`
  identity byte-for-byte.
- Before the tracking header temp is created, an existing `vault.hdr.tmp` is
  reopened without following symlinks and unlinked only on an exact
  identity match, then the directory is flushed. The retained identity stays
  until that flush succeeds; a flush failure repeats the steps on restart.
- **A mismatch blocks name reuse:** a different or unverifiable identity, a
  non-regular entry, or a rollback that started from `prepared` or
  `target_created` (no recorded identity). The vault stays readable, and the
  file needs owner confirmation.
- The same rule applies before the `committing` header temp is created.

**Transition journal-temp promotion (2026-10-05; spec 8.2).** These rules are
separate from the init rules and run before the header is classified.

| Canonical | Permitted temp | Header |
| --- | --- | --- |
| `prepared` | `target_created`, `tracking_created` | old |
| `target_created` | `committing` (old, or new for the Windows WO-1 case); `tracking_created` (old) | as shown |
| `committing` | `tracking_created` | old only |
| `tracking_created` | `rollback_tracking` | old |
| `rollback_tracking` | none | n/a |

- **MACs:** single-MAC phases use `journal_key(old_bundle)`; `committing` uses
  `mac_old` or `mac_new`. With new material only, a `committing` temp whose
  `new_core_digest` matches the authenticated header may be promoted over a
  canonical record that only parses with equal immutable fields.
- **Preserved fields:** immutable fields, every `IDX` field and every recorded
  identity (`target_kt_*`, `header_*`, `track_kt_*`), plus `tracking_gen` and
  the cleanup token once present. A temp may only add its phase's fields.
- **Invalid temps:** incomplete, unauthenticated, divergent, dropping an
  identity, skipped, backward, or a changed same-phase record. These are
  residue: never promoted or deleted automatically, and they block further
  rewrites until owner confirmation.
- A byte-identical authenticated duplicate is unlinked.

Spec 8.2 tabulates every crash point from `committing` through
`tracking_created` to `rollback_tracking`.

**Init bootstrap (2026-10-05; spec 8.3).**
- Only two creations may precede the completed preflight: T (created relative
  to its parent after the parent's file system passes 8.5) and the two
  zero-length lock files.
- The order is: lock, re-check emptiness, then the full preflight on T.
- The `prepared` journal is the first vault artifact.
- `init` never creates `objects/`; the first `add` creates and checks it.

**Safe-init schema and state table.** Both modes write an init journal before
any other vault artifact. It contains `vault_id`, `setup_id`, `mode`, future
core `salt`, capped `argon2_m/t/p`, `passphrase_kind`, and `phase`. Bound mode
also contains the complete new-index/token fields above. Derive
`init_journal_key = HKDF-SHA-512(master_pw, salt=empty,
info="pvault/v1/init-journal", L=32)` from the same single Argon2id result.
Every rewrite retains those immutable fields and gets a fresh journal MAC.

**Artifact identity encoding.** A journal-owned file has an authenticated
`*_id_kind` plus `*_file_id`:

- `id_kind: "unix"`: `bytes(20) = u64_be(st_ino) || i64_be(birth_sec) ||
  u32_be(birth_nsec)`, plus a restart check that the candidate's `st_dev`
  equals the held target directory's current `st_dev`;
- `id_kind: "windows"`: `bytes(32) = u64_be(FILE_ID_INFO.VolumeSerialNumber)
  || FILE_ID_128.Identifier[16] || u64_be(FILE_BASIC_INFO.CreationTime)`.

(Revised by the audit, item 5 below. The draft's 16-byte
`st_dev || st_ino` value was unstable across reboots and open to inode reuse.)

The value is captured from the already-open, newly created regular file. On
restart, pvault reopens a candidate relative to the held directory without
following symlinks and compares type and identity immediately before unlink.
A protocol filename without an authenticated matching identity is not owned.
Moving an interrupted directory between operating systems makes the identity
unverifiable and therefore requires confirmation or leaves init blocked.

The exact monotonic phases are:

- `prepared`: no artifact identity, `keytable_digest` or `new_core_digest`;
  written and directory-flushed before defining an index or creating a file.
- `keytable_created`: required `keytable_id_kind` and `keytable_file_id`; no
  digest. Securely create an empty `keytable.1.pv.tmp`, capture its identity,
  then durably advance the journal to this phase **before writing any key-table
  bytes**.
- `keytable_written`: retain the identity and add `keytable_digest: bytes(64)`
  and `new_core_digest: bytes(64)`. Write through the same open temp handle,
  flush, rename it to `keytable.1.pv`, flush the directory, compute SHA-512,
  construct the exact future core, then durably write this phase. Thus a crash
  after the completed rename but before this digest update still leaves a file
  owned by the authenticated `keytable_created` identity.
- `committing`: retain all preceding fields and add `header_id_kind` and
  `header_file_id`. Only after cards, type-back and optional duress are final,
  securely create an empty `vault.hdr.tmp`, capture its identity, and durably
  write this phase before writing header bytes. The header written through that
  handle must contain the core whose digest equals `new_core_digest`; flush it,
  rename and apply D5's directory/full-flush boundary.

**Atomic journal rewrite residue.** A complete `vault.journal.tmp` is not
owned by its name. After the canonical journal authenticates, a temp record is
self-authenticating only if its MAC verifies with the same init key, its
immutable fields exactly match, and its phase is the same phase or the single
allowed successor above. In that case finish the journal rename and directory
flush, preferring the successor. An incomplete, invalid, divergent or skipped-
phase journal temp is unauthenticated residue and follows the confirmation rule
below.

**Owner-confirmed residue rule.** After authenticating the canonical init
journal with the setup passphrase, pvault may offer an exact snapshot of
otherwise unauthenticated *regular-file* candidates only at the four protocol
locations: `keytable.1.pv.tmp`, `keytable.1.pv`, `vault.hdr.tmp`, and
`vault.journal.tmp`. The display includes relative name, platform file identity
and byte length. Deletion requires the typed confirmation
`DELETE INIT LEFTOVERS <first-8-hex-of-setup_id>` and a no-follow reopen whose
type, identity and length still equal the displayed snapshot. Decline,
non-interactive use, any mismatch, or absence of the setup passphrase leaves
the canonical journal in place and init blocked. Symlinks, directories,
special files and entries at any other name are never offered or deleted;
they are reported for manual removal. Permanent lock files are retained, not
cleaned up. Cards outside the target remain governed by `cards.cbor`.

| Restart observation | Required safe-init action |
| --- | --- |
| No header; valid authenticated portable journal | Promote a valid successor journal temp. Delete key-table/header artifacts only when their identity is authenticated by the selected journal. Offer only the exact unauthenticated protocol candidates under the confirmation rule. After all artifacts are resolved and the directory is flushed, durably remove the journal; otherwise remain blocked. |
| No header; valid authenticated bound journal; matching TPM | First resolve the index using its token and both allowed Names, then apply the same identity/confirmation rules. Delete the journal only after TPM and file cleanup are both durably resolved. |
| No header; valid authenticated bound journal; original TPM unavailable | Leave the journal and artifacts. Report the handle and that this directory remains blocked until cleanup on the original TPM. There is no existing authenticated core into which remote init cleanup can safely migrate. |
| Header core digest equals journal `new_core_digest`, and core, slots and journal all authenticate | The header committed. Preserve its index and files, repeat the directory/full flush, then durably remove the journal after verification-only authentication. A `header_file_id` mismatch is reported, not blocking (audit item 6); `header_file_id` only owns `vault.hdr.tmp` residue. |
| Header exists but is malformed, foreign, mismatched or does not authenticate | Delete nothing; direct the owner to recovery/fsck. |
| Journal is malformed, over cap, wrong-passphrase or has an unexpected phase/digest combination | Delete nothing. Argon2 caps are checked before derivation; errors reveal no fields. |
| Canonical journal is absent but `vault.journal.tmp` or another init-looking artifact exists | No authenticated ownership root exists. Do not promote, offer or delete it. Treat the target as nonempty and leave init blocked until the owner manually removes or relocates it. |

The create-before-identity-journal window is intentionally not papered over:
an empty or incomplete temp created just before a crash is not automatically
owned. Likewise, an unexpected final key table with a `prepared` journal is not
owned. Both require the exact owner confirmation above or keep init blocked.
A completed key table with an authenticated `keytable_created` identity is
owned even before the digest update and can be removed automatically by
identity. Remote bound init remains blocked because there is no old core into
which its unresolved TPM index can be migrated.

**Deferred-decision schema audit.** TPM transport/session choice, capability
checks, owner-authorization prompting and handle-probing order do not alter any
field above and may remain Milestone 5 work. **Author-selected P1:** v1 is
nonce-policy only, exactly as the current fields specify. PCR binding changes
the NV `authPolicy`, expected Names, cleanup reconstruction, token AAD and
duress tag, so it requires a future reviewed format revision; it is not a
Milestone 5 runtime-only addition to v1.

Revoke/Erase operation records may remain deferred because the Milestone 3
journal parser rejects their `op` values and no current record must carry their
state. Wizard defaults and command UX likewise do not affect these schemas.

**Audit completion of D6 (2026-10-05; recommendations for review).** The
final consistency audit found these gaps in the draft above. Each correction
below is reflected in spec 6, 8.1, 8.2 and 8.3, marked PENDING.

1. **Transition artifacts had no ownership mechanism (gap).** The restart
   tables said to remove "authenticated abandoned target files", but nothing
   authenticated them:
   - `keytable.<new_gen>.pv` is encrypted under the new bundle, which an
     old-side restart does not have;
   - the journal stored only the target *core* digest, not a file identity or
     a file digest;
   - the earlier 6.6 wording deleted "the new keytable file" by name.

   Apply the init identity handoff to transitions too. Every vault artifact a
   journaled operation creates is created empty, with exclusive no-follow
   creation. Its identity is captured from the open handle and made durable in
   the journal **before any bytes are written**. Exact additions, all
   retained byte-for-byte by later phases:

   | Phase (order) | New fields | Written when |
   | --- | --- | --- |
   | `prepared` | `old_keytable_digest` bytes(64): the old core's `keytable_digest` | With `old_core_digest`, before any side effect |
   | `target_created` (new) | `target_kt_id_kind`, `target_kt_file_id` | After the bound index is defined (6.3 f) and empty `keytable.<new_gen>.pv.tmp` is created; before key-table bytes |
   | `committing` | `header_id_kind`, `header_file_id` | After the target key table is final and durable, and empty `vault.hdr.tmp` is created; before header bytes |
   | `tracking_created` (new; old side only) | `tracking_gen`, the scope-5 `cleanup_tpm_id_*` rewrap, `track_kt_id_kind`, `track_kt_file_id` | After empty `keytable.<tracking_gen>.pv.tmp` is created; before key-table bytes |
   | `rollback_tracking` | `tracking_core_digest`, `track_hdr_id_kind`, `track_hdr_file_id` | After the tracking key table is final and durable, the tracking core is built, and empty `vault.hdr.tmp` is created; before header bytes |

   `tracking_created` and `rollback_tracking` carry one `mac` under
   `journal_key(old_bundle)`; `committing` keeps `mac_old`/`mac_new`. All new
   key names are under 24 bytes (appendix A).

   **Ownership on restart:**
   - An artifact is deleted automatically only when the selected
     authenticated journal records its exact identity, and the candidate
     reopens without following symlinks as a regular file with that identity.
     This covers both the `.tmp` and the renamed final file, since a
     same-directory rename keeps the identity.
   - `keytable.<old_gen>.pv` is deleted after a transition commit only if its
     SHA-512 equals `old_keytable_digest` (content-authenticated). This is
     needed because a new-side restart does not have the old core.
   - The live-vault create-before-identity window (a temp created just before
     a crash) is not owned. It is reported, and offered for owner-confirmed
     snapshot deletion under the D6 confirmation rules, with a confirmation
     phrase naming the vault-ID prefix. Mutations that need that name stay
     blocked until it is resolved. Reads are unaffected.
   - A stray `vault.journal.tmp` follows the init promotion rule: same phase or
     single successor only. With no canonical journal, no side effect can have
     happened, but the file itself is still unowned, so it follows the same
     confirmation rule.
   - Ordinary commits (`add`, `rm`, `duress set`) have no journal. Their stray
     temps fall under SI-40 (reported; owner-confirmed); see item 7.

2. **Generation increment of 2.** The `tracking_gen = old_gen + 2` commit
   contradicts the glossary ("incremented by exactly 1 by every commit").
   *Recommendation:* keep +2, because it avoids colliding with an unowned or
   abandoned `keytable.<new_gen>.pv`, and amend the glossary to name this one
   exception (PENDING SI-35). SI-28's `keytable_gen == generation` still holds,
   because the tracking key table is written at `tracking_gen`.

3. **Duplicate old-index identity (scope 4): decided N4, removed.** The
   author required removal only after verifying that every relevant restart
   path can authenticate and open the staged cleanup entry without the old
   TPM. Verification:

   | Restart path | How the old index's identity is obtained | Old TPM needed? |
   | --- | --- | --- |
   | `committing`; header matches `new_core_digest` (including a retried post-replacement flush) | New bundle → `core_mac` → staged scope-5 entry under `K_mac_new` | No |
   | Any later `fsck` or ordinary unlock with new material; Path B with new cards | Same: the entry is in every later authenticated core | No |
   | Any later bundle rotation | Old side of that rotation decrypts the entry and rewraps it as scope 5 | No |
   | `prepared`, `target_created`, `committing` on the old side; `tracking_created`; `rollback_tracking` | The old index is still the live index of the authenticated old slots; no cleanup applies | n/a |
   | Header missing or authenticates as neither side | Indeterminate: no deletion under any design, so scope 4 would add nothing | n/a |
   | Old slots not authenticated | No entry is staged and the old index is never deleted (F55), exactly as with scope 4 | n/a |

   No path needed scope 4, so `committing` carries no old-index fields
   (`old_tpm_index`, `old_name_postwrite`, `old_policy_nonce`,
   `old_tpm_id_*`). `old_slots_authenticated` remains. Scope value 4 is
   reserved.

4. **Creating a bound index requires a measurable TPM identity.** Bound slots,
   init `IDX` and transition `IDX` make the identity token **required**. If the
   H-2 EK cannot be created without a prompt (C4 fails: endorsement hierarchy
   disabled, endorsement authorization set, no ECC P-256), a bound index cannot
   be created at all. That makes C4 a precondition for bound `init`,
   recovery-to-bound and `convert` to bound, not only for duress. Previously
   SI-42 tied C4 to duress alone.
   - **Decided N2 (2026-10-05):** the identity is measured before any journal,
     index or file. On failure, bound `init`, recovery and `convert` are
     refused with a specific message that explicitly offers portable mode (or
     `recover --to-portable`), and the vault is unchanged (spec 9.3; proposed
     F91).

5. **File-identity encoding: platform limitations and revised
   recommendation.** Audit findings:
   - **Unstable `st_dev`.** The value changes across reboots or remounts for
     btrfs subvolumes (anonymous device numbers), for re-plugged removable
     media, and potentially for macOS remounts. A process crash keeps the
     identity; a power loss followed by a reboot can change it. The result is
     a false *mismatch*, which is safe (confirmation or block) but costs
     availability exactly in the power-loss case.
   - **Inode reuse.** ext4 reuses inode numbers after deletion. If an
     unrelated file is created at the same protocol name and receives the same
     inode, the result is a false *match*, which violates "never delete what we
     do not own".
   - **Moving the directory** between systems or volumes, or restoring it from
     a backup, changes every identity. The result is confirmation or block
     (stated already).
   - **Windows.** `FILE_ID_INFO` (Windows 8 / Server 2012 and later, NTFS and
     ReFS) is stable. NTFS embeds a reuse sequence number in its file IDs;
     ReFS reuse behavior is not documented.

   Revised encoding (supersedes the draft's 16- and 24-byte values):
   - `"unix"`: bytes(20) =
     `u64_be(st_ino) || i64_be(birth_sec) || u32_be(birth_nsec)`, from
     `statx(STATX_INO|STATX_BTIME)` on Linux and `fstat` `st_birthtimespec` on
     macOS. On restart the candidate must also have the **same `st_dev` as the
     held target-directory handle at that moment**, not the recorded value. If
     birth time is unavailable, the file system fails the D5 preflight and
     mutations are refused. Availability is decided from the returned
     `statx` mask (Linux) or a non-zero `st_birthtimespec` (macOS), never from
     a version table; the exact per-platform support and refusal table is in
     spec 8.1.
   - `"windows"`: bytes(32) =
     `u64_be(VolumeSerialNumber) || FileId[16] || u64_be(CreationTime)`, from
     `FILE_ID_INFO` and `FILE_BASIC_INFO`.

   Birth time *reduces* the inode-reuse risk, and comparing against the live
   directory's `st_dev` removes the reboot false-mismatch. The identity is
   **not universally unique**:
   - HFS+ creation dates have one-second resolution;
   - macOS (`setattrlist`) and Windows (`SetFileTime`) let any writer set
     creation times;
   - ReFS ID reuse is undocumented.

   It prevents deletion by name and accidental confusion. It is not a defense
   against a local writer to the vault directory, which 8.4 already places out
   of scope (spec 8.1 lists every case).

6. **The committed init header does not need a file-identity match.** A header
   whose recomputed core digest equals `new_core_digest`, and whose core, slots
   and journal MACs verify, is the committed header. Its bytes cannot be forged
   without the keys. Requiring `header_file_id` to match only blocks legitimate
   cases (for example a copied interrupted directory). *Recommendation:* use
   `header_file_id` solely to own `vault.hdr.tmp` residue; report a mismatch on
   the committed header, but do not block journal removal.

7. **Deferred decisions that do affect schemas proposed now.**
   - SI-40 (leftover ownership) is listed as Milestone 4/6 work, but item 1
     makes transition journals carry artifact identities and
     `old_keytable_digest`. Those fields must be decided **now**.
   - `add` and `rm` remain schema-free only if SI-40 keeps AEAD-based
     ownership: an object is owned when its ID is listed in an authenticated
     key table under the current bundle. If the author later wants identity
     handoff for objects, `add` needs a journal record, and that is a format
     change.
   - Revoke and Erase (Milestone 8) can add `op` values without changing
     existing records.
   - SI-22 sessions, SI-35 probing and SI-42 checks change no field.
   - SI-29 reuses the transition schemas.
   - SI-14's mount lock (M) adds files, not fields.

**Tests required by this schema.**
- Known-answer vectors for every token key scope, plus a test that a token for
  one scope/role cannot open in another.
- Remote bundle rotation with the old TPM absent: old identity is rewrapped
  under the new bundle, committed, then rewrapped again by a second rotation.
- Prepared crash rolls back the new index with only old material; post-commit
  crash cleans or defers the old index with only new material.
- Remote recovery verifies the correct old duress passphrase from the old
  token and rejects a wrong one.
- Cleanup lists of 31 and 32 records exercise reservation, local pruning,
  exact coalescing and pre-write refusal without dropping an identity.
- Crash failpoints cover every safe-init phase, both sides of each header
  replacement, `rollback_tracking` before/after `tracking_gen`, journal unlink
  and its directory flush. Remote runs prove a transition with authenticated
  old slots becomes usable while an index remains tracked; unauthenticated old
  slots and remote interrupted init stay explicitly blocked.
- F25, F69, F71, F80, F81, F83, F87 and F88 are updated to the selected
  schema and transitions.
- Transition artifact ownership (audit item 1):
  - a crash at every boundary of `prepared` → `target_created` → `committing`
    and `tracking_created` → `rollback_tracking`;
  - identity-owned removal of both the `.tmp` and the renamed final file;
  - the unowned create-before-identity temp is offered only under
    confirmation;
  - `keytable.<old_gen>.pv` is deleted only on a digest match with
    `old_keytable_digest`.
- File identity (audit item 5): an inode reused for a different file at a
  protocol name is never deleted (birth-time mismatch); a changed `st_dev`
  after remount still matches through the live directory handle; a missing
  birth time refuses mutation at preflight.
- Windows remote volume (D5): an SMB share reporting `NTFS` is refused for
  mutation.
- Bound creation with an unmeasurable EK identity follows decision N2.

### D7. Key-table entry layout and decode-time path rules (SI-30, SI-07)

**Recommendation.**
- Confirm the 7.8 entry layout:
  - file: `kind, path, file_id(16), size u64, created_at, modified_at, fk_aes(32), fk_chacha(32)`;
  - directory: `kind, path, created_at, modified_at`.
- Confirm the limits: 4096 bytes per path, 255 bytes per component.
- Approve the decode-time rule set of SI-07. Every rule there is independent of
  the Unicode version:
  - syntax, lengths, forbidden characters and Windows reserved names;
  - no trailing space or dot;
  - strictly ascending bytewise order (which also rejects duplicates);
  - every parent present as a `dir`;
  - no file/directory clash.
- **NFC and case-fold collisions run on input only** (Milestone 4). An existing
  vault therefore never fails to open after a Unicode update.

**F73 corrected (2026-10-05).** F73 previously said that the "same
violations" inside a decoded key table are rejected, which contradicted this
split. F73 now lists the input checks and the decode checks separately: decode
excludes NFC and case-fold collisions, and adds the order, duplicate and
parent rules. It marks the split as the 7.8 proposal, PENDING SI-07. The
case-folding source is therefore needed before Milestone 4, provided the split
is approved; otherwise before Milestone 3.

**Evidence.**
- SI-07 path analysis.
- Strong Normalization Stability (D2) covers NFC for assigned characters.
- The Case Folding Stability policy applies formally only to NFKC-normalized
  identifiers. Paths are NFC and not identifiers, so a decode-time case-fold
  check could change meaning across versions. That is the reason to keep it
  input-only.

**Deferred to Milestone 4:** the case-folding source for input-time collisions
(an approved crate, a vendored `CaseFolding.txt` table at Unicode 17.0 with a
Unicode-3.0 notice, or "NFC plus `to_lowercase`"). Recommendation for then: the
vendored table, generated by a pinned-hash script in `tools/`.

**Schema changes:** none beyond confirming 7.8.

**Tests.**
- **F73 (decode part):** each rule violated inside an authenticated key table
  gives `KeyTableCorrupt`, mapped to "The key table is damaged.", with no path
  text in any error.
- **F12:** the key-table digest binding.
- **Boundaries:** a 4096-byte path accepted and 4097 refused; a 255-byte
  component accepted and 256 refused.
- **Decode hygiene:** the two-pass, arena and hard-cap tests of D3.

### D8. Memory-resource checks (SI-16, spec 4.3)

**Recommendation.** Fix these definitions (all within 7.6a "memory queries"):

| Platform | Total RAM (policy: `m` ≤ 50%) | Available memory (resource check: `m` + 64 MiB) |
| --- | --- | --- |
| Linux | `sysinfo(2)`: `totalram × mem_unit` | `MemAvailable` from `/proc/meminfo` (Linux 3.14+); if it is absent or malformed, refuse unless 4.3 is explicitly amended to allow a fallback |
| macOS | `sysctlbyname("hw.memsize")` | `sysconf(_SC_PAGESIZE) × (free_count + inactive_count)` from `host_statistics64(mach_host_self(), HOST_VM_INFO64, …)` |
| Windows | `GlobalMemoryStatusEx`: `ullTotalPhys` | `GlobalMemoryStatusEx`: `ullAvailPhys` |

- **Exact macOS definition:** require a successful page-size call and a
  `HOST_VM_INFO64` result long enough to include `inactive_count`. Convert every
  term to `u64`, add and multiply with checked arithmetic, and sample it
  immediately before the Argon2 allocation. `free_count` already includes
  speculative pages, so do not add `speculative_count`. Do not separately add
  active, wired, purgeable or compressor counts; this deliberately limited
  formula is not a claim to reproduce Activity Monitor. Query failure, a short
  result or arithmetic overflow gives the existing resource refusal before
  allocation; there is no silent skip or free-pages-only fallback.
- `os_proc_available_memory()` is not an alternative: the macOS 27 SDK marks
  it `API_UNAVAILABLE(macos)` (it is an iOS-family app API). `TASK_VM_INFO`
  exposes `limit_bytes_remaining`, but the focused command-line probe returned
  zero, consistent with Apple's statement that the app-oriented query returns
  zero when the caller is not an app. The same probe successfully returned
  `hw.memsize`, page size and `HOST_VM_INFO64` counts.
- Confirm the 64 MiB margin; it remains a policy recommendation, not an
  evidence-derived boundary.
- An allocation failure always gives the 4.3 resource message.
- Stored parameters are never lowered.
- Linux overcommit means `try_reserve` rarely fails there, which is why the
  `MemAvailable` estimate matters on Linux.
- *To measure in Milestone 3:* how `ullAvailPhys` behaves under a large
  standby list on Windows CI.

**Evidence.**
- SI-16.
- Apple SDK `mach/vm_statistics.h` defines `free_count`, `inactive_count` and
  explicitly says speculative pages are already included in `free_count`.
- **Audit correction (2026-10-05):** `libc` 0.2.190 provides
  `host_statistics64` and `mach_host_self`, but **not** `host_page_size`, and
  it marks `mach_host_self` `#[deprecated]` (pointing to the unapproved `mach2`
  crate).
  - Take the page size from `sysconf(_SC_PAGESIZE)`, which `libc` provides and
    does not deprecate. It is 16 KiB on Apple-silicon macOS, matching the VM
    page size in which the counts are reported.
  - Call `mach_host_self` inside the `platform` module under a scoped
    `#[allow(deprecated)]`, with its `// SAFETY:` review. No new crate is
    needed.
  - Translated (Rosetta) execution is not relied on. Release builds are
    native, and a mismatch between the two page sizes would need a probe
    before it could be supported.
- `windows-sys` 0.61 provides `GlobalMemoryStatusEx` (`System_SystemInformation`
  feature, not yet enabled).

**Tests.**
- **F13:** out-of-cap parameters are rejected before allocation.
- **F76:** above 50% of total RAM gives the policy message, and above available
  memory (mocked) gives the resource message. Both leave the parameters
  untouched and allocate nothing.
- An injected allocation failure gives the resource message.
- macOS mocks cover query failure, a short count, integer overflow, no double
  counting of speculative pages, and exact equality at `m + 64 MiB`.
- The check order matches 4.3 exactly (failpoint trace).

---

## 3. Other Milestone 3 work with no open decision

- **Test-only failpoints** (SI-48, accepted): the `fault-injection` feature,
  refused in release builds (F85).
- **Header MACs** (4.2), the Argon2 caps (4.3), and F7, F9 to F11 (stream
  tests already exist from Milestone 1).

---

## 4. CI test totals for Milestone 2 (run 37261091478), explained

**Verification performed for this review.** The workflow still contains the
two commands below. On the current macOS checkout,
`cargo test --workspace --locked` produced 113 passed and 2 ignored, and the
`--benches` invocation repeated 74 library tests (1 ignored) before reporting
"Success" for 8 Criterion functions. The `cfg`-gated test inventory accounts
for Linux's one additional passed test and Windows's ten fewer tests. This
matches the accepted CI totals; no benchmark function is being counted as a
distinct test.

Each job ran these commands:
- **stable jobs:** `cargo test --workspace --locked`, then
  `cargo test --workspace --benches --locked`;
- **Rust 1.89 jobs:** `cargo test --workspace --locked` only.

**Why the stable totals are larger.** `--benches` selects every target with
`bench = true`. A library target has that by default, so the second command
runs the `pvault-core` library unit tests **a second time**, plus the
Criterion benchmark binary in test mode. The benchmarks report "Success" for 8
benchmark functions; they are not counted as tests. The repeat inflates the
stable totals without adding distinct tests.

**Distinct tests per platform** (identical on stable and 1.89):

| Binary | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `pvault-core` unit tests | 75 | 74 | 67 |
| `pvault-core/tests/cascade.rs` | 10 | 10 | 10 |
| `core_dumps.rs` | 1 | 1 | 1 |
| `estimator_limits.rs` (Unix only) | 1 | 1 | 0 |
| `heap_hygiene.rs` | 1 | 1 | 1 |
| `stdin_secrets.rs` | 4 | 4 | 3 |
| `pvault-cli/tests/cli.rs` | 3 | 3 | 3 |
| `estimator.rs` | 12 | 12 | 12 |
| `estimator_reaping.rs` (Unix only) | 1 | 1 | 0 |
| Doc-tests (1 example + 5 compile-fail) | 6 | 6 | 6 |
| **Distinct tests passed** | **114** | **113** | **103** |
| Ignored helpers | 2 | 2 | 1 |

- **Linux vs macOS (+1):** the Linux-only `restored_after_an_error` terminal
  test.
- **macOS vs Windows (−10):**
  - 7 Unix terminal tests: echo, cancellation, read error, SIGINT, SIGTERM,
    SIGHUP, SIGQUIT;
  - the pty refusal test in `stdin_secrets.rs`;
  - `estimator_limits`;
  - `estimator_reaping`.

**Stable totals reconciled:**

| Job | First run | `--benches` repeat of the library tests | Reported |
| --- | --- | --- | --- |
| stable ubuntu | 114 | 75 | 189 |
| stable macOS | 113 | 74 | 187 |
| stable Windows | 103 | 67 | 170 |

**Ignored executions.** There are two helper tests, both `#[ignore]`:
- `platform::terminal::tests::signal_helper_reads_from_pty`, in the library,
  Unix only;
- `stdin_helper`, in `stdin_secrets.rs`, all platforms.

On stable Unix the library runs twice, so the terminal helper is reported
ignored twice, plus `stdin_helper` once: **3 executions of 2 helpers**. On
Rust 1.89 (one run) that is 2. On Windows only `stdin_helper` exists: 1.

---

## 5. Still recorded, not blocking Milestone 3

- **RFC / IETF test-vector excerpt licensing** (SI-04, M1-F5, M2-F10):
  RFC 4231, RFC 9106 and draft-irtf-cfrg-xchacha-03 values in `testdata/`.
  Open; must be settled before any release.
- **Windows console runtime validation** (M2-F7): before Milestone 4.
- **Windows Job Object limits for the estimator** (M2-F5): deferred hardening.
- **The Milestone 2 acceptance edits** in `PVAULT_BUILD_SPEC.md` and
  `docs/SPEC_ISSUES.md`: uncommitted, as instructed.

---

## 6. Readiness conclusion and decisions for author review

**Conclusion:** Milestone 2 is accepted and its test accounting is reconciled,
and the remaining Milestone 3 design gaps now have concrete recommended
resolutions. Milestone 3 is **not ready to start until the author reviews and
records them**. This report is not an approval.

| Decision for review | Recommendation |
| --- | --- |
| D1 passphrase kind | Approve required `passphrase_kind` in the authenticated core and init journal; store no estimate, word count or band |
| D2 normalization | Preserve assigned-only/private-use H_c with forward-stable NFC and fail-closed downgrade behavior. Approve the exact frozen Unicode-17 `H_w_v1` algorithm and hash-pinned vendored data policy |
| D3 codec and allocation limits | Approve the fixed-schema codec, two-pass key-table decode, exact arenas, 65,536-entry cap and the architecture-independent `4096 + 128*N + 64*F + P ≤ 128 MiB` rule |
| D4 locking | Approve G + L now; reserve M but leave mount acquisition/upgrade to SI-45 |
| D5 file systems and durability | W1 is selected. Approve or reject the remaining recommendation: separator-based mountinfo parsing, exact Linux types, macOS APFS/HFS+ full-flush sequence, and the pre-/post-header-replacement failure split |
| D6 journals and TPM identity | P1 is selected. Approve or reject the remaining recommendation: fixed H-2 template, exact five token scopes/HKDF labels/AAD, flattened schemas, 32-record refusal, exact old/new/tracking core digests, tracking `slots_mac` recomputation, pre-staged cleanup, `rollback_tracking`, and identity-owned safe-init state table |
| D7 key table paths | Approve the entry layout and Unicode-independent decode checks (F73 already states the split; the case-folding source moves to before Milestone 4) |
| D8 memory resource checks | Approve macOS `sysconf(_SC_PAGESIZE) × (free + inactive)` from `HOST_VM_INFO64`, fail closed on query/arithmetic failure, and retain the 64 MiB policy margin |

**Decisions raised by the final audit (appendix B); all five decided by the author on 2026-10-05:**

| # | Decision | Recommendation |
| --- | --- | --- |
| N1 | Scope of the selected W1 assumption | **Decided (2026-10-05):** W1 unchanged; Windows power loss can break a vault; WO-1 to WO-3 documented as unverified (spec 2, 8.5, 14) |
| N2 | Bound creation when the H-2 EK identity cannot be measured (C4) | **Decided (2026-10-05):** refuse before any write and offer portable mode explicitly (spec 9.3, 5.8, F91) |
| N3 | Duress check when `H_w_v1` refuses a custom input | **Decided (2026-10-05):** non-match, derivation skipped, timing difference documented (spec 5.6) |
| N4 | Committing-record old-index context and scope-4 token | **Decided (2026-10-05):** removed after the restart-path verification in D6 audit item 3; scope 4 reserved |
| N5 | `MAX_KEYTABLE_ENTRIES = 65,536` (D3) | **Decided (2026-10-05):** approved as a v1 product limit counting files and directories; over-limit operations are refused before any side effect, leaving the vault unchanged (spec 7.8, F92) |

Also for review in D6: the transition artifact identity phases
(`target_created`, `tracking_created`), `old_keytable_digest`, the revised
file-identity encoding, and the glossary's +2 generation exception. They
complete the protocol, but they are recommendations, not approvals.

Windows W1 and PCR P1 are now author-selected. The other rows have one
recommended design for accept/reject review rather than an unresolved
implementation menu. In particular, the new expected-core binding and
safe-init artifact-ownership details are fully specified but remain
recommendations until approved. HFS+ and native NTFS/ReFS probes remain
acceptance evidence for the chosen design; they do not change schemas or turn
the Windows assumption into verified power-loss safety.

After those decisions are recorded in `docs/SPEC_ISSUES.md` and the governing
spec, the readiness gate can be reassessed. This report does not authorize
product-code work or Milestone 3.

---

## Appendix A. Canonical key orders of the proposed schemas (computed)

These orders apply the 4.4 rule: keys sorted by their encoded form, which for
keys under 24 bytes means shortest first, then bytewise. They were computed
by script on 2026-10-05; every proposed key is under 24 bytes. A record
contains only the keys its phase and mode require; the order of the keys
present is the subsequence of these lists. `FORMAT.md` must publish these
orders once the schemas are approved.

- **CoreFields** (D1 + D6): `mode, salt, magic, version, argon2_m, argon2_p,
  argon2_t, setup_id, vault_id, created_at, generation, card_set_id,
  tpm_cleanup, keytable_gen, keytable_digest, passphrase_kind`.
- **SlotFields, bound:** `s1_x, s2_x, s1_ct, s1_nonce, s2_nonce, tpm_id_ct,
  duress_tag, tpm_nv_name, tpm_id_nonce, tpm_nv_index, tpm_id_template,
  tpm_policy_nonce`.
- **SlotFields, portable:** `slot_ct, duress_tag, slot_nonce`.
- **TpmCleanupEntry:** `tpm_id_ct, tpm_index, policy_nonce, tpm_id_nonce,
  name_prewrite, name_postwrite, tpm_id_template`.
- **Init journal** (bound, `committing`; superset): `op, mac, mode, salt,
  phase, argon2_m, argon2_p, argon2_t, setup_id, vault_id, new_tpm_index,
  header_file_id, header_id_kind, keytable_digest, new_core_digest,
  new_tpm_id_ct_i, passphrase_kind, keytable_file_id, keytable_id_kind,
  new_policy_nonce, new_name_prewrite, new_name_postwrite,
  new_tpm_id_nonce_i, new_tpm_id_template`.
- **Transition `committing`** (bound target; superset; no old-index fields
  after N4): `op, phase, mac_new, mac_old, new_gen, old_gen, vault_id,
  target_mode, new_tpm_index, header_file_id, header_id_kind,
  new_core_digest, new_tpm_id_ct_o, old_core_digest, new_policy_nonce,
  new_name_prewrite, target_kt_file_id, target_kt_id_kind,
  new_name_postwrite, new_tpm_id_nonce_o, new_tpm_id_template,
  old_keytable_digest, old_slots_authenticated`.
- **Transition `rollback_tracking`** (superset, including the `header_*`
  identity retained from a replaced `committing` record): `op, mac, phase,
  new_gen, old_gen, vault_id, target_mode, tracking_gen, new_tpm_index,
  header_file_id, header_id_kind, new_tpm_id_ct_o, old_core_digest,
  new_policy_nonce, track_kt_file_id, track_kt_id_kind, cleanup_tpm_id_ct,
  new_name_prewrite, target_kt_file_id, target_kt_id_kind,
  track_hdr_file_id, track_hdr_id_kind, new_name_postwrite,
  new_tpm_id_nonce_o, new_tpm_id_template, old_keytable_digest,
  cleanup_tpm_id_nonce, tracking_core_digest, cleanup_tpm_id_template`.

## Appendix B. Final consistency audit record (2026-10-05)

**Read in full:** `CLAUDE.md`; `PVAULT_BUILD_SPEC.md`; `docs/SPEC_ISSUES.md`;
this report; and the complete working-tree diffs of the three documents.

**Checks performed:**
1. The six Unicode 17.0.0 SHA-256 values in D2: `UCD.zip` was re-downloaded
   from `unicode.org/Public/17.0.0/ucd/` and it and the five extracted files
   were hashed. All six match.
2. The Unicode Stability Policy clauses quoted in D2 (Strong Normalization
   Stability; decomposition and combining-class stability; the
   unassigned-character note; case-folding stability limited to
   NFKC identifiers) were re-read from the primary page.
3. The `libc` 0.2.190 sources: `EXT2_SUPER_MAGIC == EXT4_SUPER_MAGIC ==
   0xEF53`; `host_statistics64` present; `mach_host_self` deprecated;
   `host_page_size` absent; `sysconf`/`_SC_PAGESIZE` present (D8 corrected).
4. A computed key order and length check for every proposed schema
   (appendix A).
5. Every restart row of 6.6, 8.2, 8.3 and D6, checked against the phase
   sequences. This found the transition-artifact ownership gap (D6 audit
   item 1).
6. A scan for terms from superseded drafts (`pending_tpm_cleanup`,
   `tpm_id_mac`, `journal_salt`, `old_tpm_name`, a "dummy derivation" rule,
   `host_page_size`). Remaining occurrences are explicitly marked as
   superseded.
7. CI accounting re-verified locally: `cargo test --workspace --locked` gives
   113 passed and 2 ignored on macOS; `--benches` repeats 74 library tests
   (1 ignored) and runs 8 Criterion functions. That matches section 4.
8. Scope: no product code, dependency, CI or lock-file change
   (`git diff --name-only HEAD` lists only the two tracked documents, and this
   report is untracked).

**Corrections made in this audit:**
- D2: the nonexistent "approved dummy-derivation timing rule" was removed and
  replaced by decision N3 (since decided: non-match, run skipped); it is now stated that `H_w_v1` changes approved
  Milestone 2 behavior.
- D5: the Windows SMB false acceptance, the same-mount check for `objects/`,
  the durability preflight and the W1 scope (N1).
- D6: transition artifact identities and `old_keytable_digest`; the
  `tracking_created` phase; the glossary +2 exception; scope-4 redundancy
  (N4); bound creation requiring the EK identity (N2); the revised
  file-identity encoding; the committed-header identity relaxation; deferred
  decisions with schema impact.
- D8: the page-size source and the `mach_host_self` deprecation.

**Author decisions recorded after the audit (2026-10-05):**
- **N1:** W1 unchanged; Windows power loss or OS crash can break a vault; the ordering assumptions WO-1 to WO-3 are documented as unverified.
- **N2:** bound creation without a measurable TPM identity is refused before any write, and portable mode is offered.
- **N3:** a candidate that generated-word handling refuses is a duress non-match; its derivation is skipped; the timing difference is documented, and every unconditional two-run statement is reconciled.
- **N4:** scope 4 is removed, after verifying that every relevant restart path authenticates and opens the staged cleanup entry without the old TPM (D6 audit item 3).
- **N5:** the 65,536-entry limit (files and directories) is approved; exceeding it is refused before any side effect.

They were recorded in the spec (2, 5.1, 5.6, 5.8, 6.3, 6.5, 6.9, 7.3, 7.8, 8.1, 8.5, 9.3, 14, F91, F92), in SPEC_ISSUES (SI-07, SI-12, SI-36, SI-38, SI-51, section 4, 10.9) and in this report. The artifact-identity rules gained an exact per-platform support and refusal table, without any uniqueness claim, and the preflight text now states that passing it never weakens post-commit failure handling.

**Further documentation corrections (2026-10-05, second pass).** All remain
recommendations, PENDING approval. W1, P1 and N1–N5 are unchanged.

| # | Item | Resolution | Where |
| --- | --- | --- | --- |
| C1 | An existing `vault.hdr.tmp` before rollback tracking creates its header temp | The committing `header_*` identity is retained into `tracking_created`. It is reopened without following symlinks and unlinked only on an exact identity match; the identity stays until the directory flush succeeds. A mismatch, missing identity or non-regular entry blocks reuse of the name (owner confirmation only) | Spec 8.1; SI-35 |
| C2 | Transition journal-temp promotion | A separate table of permitted transitions; old-key or `mac_old`/`mac_new` authentication; immutable fields and identities preserved byte-for-byte; invalid temps are blocking residue; crash table for committing → tracking_created → rollback_tracking; tracking artifacts resumed in place | Spec 8.2; SI-35 |
| C3 | Stale texts | SI-38 no longer requires `header_file_id` for the committed header. Spec 6.4 k keeps the journal at its current phase. Spec 7.8 states the +2 tracking exception. F73 separates input and decode checks | Spec 6.4, 7.8, F73; SI-38 |
| C4 | Deadlines | Case-folding source before Milestone 4 (if the split is approved); wizard default before Milestone 14 | Spec 7.8, 16; SPEC_ISSUES section 4 |
| C5 | Init bootstrap | Identify the parent, create T, open and identify T, create the lock files, lock, re-check emptiness, complete the preflight, then write the first journal. `objects/` is created by the first `add` | Spec 8.3; SI-38 |
| C6 | Windows local volume | Q1–Q4 criterion, in order, fail closed; Q1 and Q2 behaviors to be confirmed by a native probe | Spec 8.5; SI-12 |
