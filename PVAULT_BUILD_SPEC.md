# Authorship and Git attribution requirements

**Sole project author: Yash Sandeep Tamhane.**

- List only Yash Sandeep Tamhane as the author of this project and its original code and documentation.
- No AI system, assistant, model, service, or company may be listed as an author, co-author, contributor, or project credit. Do not add AI attribution comments, signatures, or `Co-authored-by` trailers.
- Never commit or push unless Yash explicitly requests it. If a commit is authorized, use only Yash’s verified Git identity for both author and committer. Verify the configured name and email first; ask if either is missing or incorrect. Never invent an email or substitute an AI identity.
- Preserve all required third-party license notices and attribution, including dependency and wordlist credits. These are separate from project authorship.

---

# Personal Vault (`pvault`): Build Specification for an AI Coding Agent

> **How to use this file:** Give this whole file to your AI coding assistant (Claude Code, Copilot, Cursor, etc.) in VS Code. Tell it: *"Read PVAULT_BUILD_SPEC.md fully. Follow it milestone by milestone. Start with Milestone 0."*
>
> **Spec version:** 7.4. Full feature set, built in one pass and released at the end. Destructive features (the duress trigger action, Revoke, Erase, flush, K2) are built last, after a mandatory review gate.
>
> **v7 changes from v6 (Milestone 0.5 consistency pass; the decision record is `docs/SPEC_ISSUES.md`):**
> - `libc` and `windows-sys` are approved for narrowly scoped platform FFI (7.6a).
> - Exact deterministic CBOR (4.4), KDF parameters and units (5.1); the stream AAD now authenticates `version`, and record lengths must be exact (7.7).
> - The dual-cipher claim is narrowed to the chunk layer (A1).
> - Vault paths, directory entries and replacement rules are defined (7.8).
> - File-system support policy: mutations are refused where locking and durability cannot be provided, including FAT/exFAT (8.5).
> - Memory-locking and Argon2 memory policy (4.3, 10.2).
> - Card output, PNG input and passphrase normalization rules (7.3, 7.4a to 7.4c); card work moves to Milestone 4.
> - Command/authentication and error-message tables (5.7, 5.8).
> - Drafted conversion and duress-setup protocols (6.9, 6.10); recovery directly to portable mode (6.8).
> - Same-TPM rule for index deletion (9.2b); automatic `tpm-harden` removed and bound duress availability made explicit (9.3).
> - Journal schemas (8.1); test-only failpoints; new tests F73 to F85.
>
> **v7.4 (Milestone 1 accepted; Milestone 2 approvals):**
> - Milestone 1 accepted on 2026-10-04: commit `bd04bb4`, CI run 37254330640 green on every job (13).
> - SI-51 final design approved, with the author's clarifications: main generated passphrases 10–16 words (default 12); custom main passphrases estimated at creation only; **duress passphrases generated only, fixed at 12 words for now**; verification-only authentication skips the duress check and the duress-only Argon2id derivation (5.5); the collision rule is defined on the actual main credential (7.3); two derivations do not by themselves establish timing equivalence (5.6). Metadata, header and journal schema changes stay **PENDING** for review before Milestone 3.
> - EFF wordlist embedded unmodified under EFF's CC BY 4.0 grant, with attribution (SI-04; `THIRD_PARTY_NOTICES.md`).
> - Shamir uses `vsss-rs = "=6.0.1"` through its public polynomial API with pvault-owned, wiped storage (7.4; SI-08).
> - Passphrase Unicode normalization runs in a pvault-owned, wiped buffer, because the normalization crate's iterators can spill to unwiped heap memory (10).
>
> **Working-tree additions after v7.4 (2026-10-05, not a new version):** author selections **W1** (Windows NTFS/ReFS writable under an explicit, unverified durability assumption) and **P1** (nonce-policy only in v1). Author decisions:
> - **N1:** Windows power loss can break a vault; ordering assumptions WO-1 to WO-3 are unverified (2, 8.5).
> - **N2:** bound creation without a measurable TPM identity is refused, and portable mode is offered (9.3).
> - **N3:** a refused generated-word candidate is a duress non-match, and its run is skipped (5.1, 5.6).
> - **N4:** no scope-4 old-index token (8.1).
> - **N5:** at most 65,536 key-table entries (7.8).
>
> **v7.5 (Milestone 3 approvals, 2026-10-05):** the author approved D1–D8 of `docs/M3_READINESS.md` and their audit corrections, including:
> - the header and journal schema fields;
> - the encrypted TPM-identity tokens;
> - the init and transition identity handoffs;
> - the journal-temp promotion rules;
> - the +2 tracking generation;
> - the F73 decode/input split;
> - the revised deadlines.
>
> W1, P1 and N1–N5 are unchanged. Markers below that these approvals resolve now read "approved for Milestone 3". Everything still marked **PENDING** (SI-04 notices, SI-10, SI-11, SI-14 mount and upgrade, SI-18, SI-22, SI-29, SI-35 handle allocation and overflow, SI-40 live-vault `add`/`rm` and `fsck` deletion rules, SI-42, SI-44, SI-45, the N3 creation notice) stays pending.
>
> **v7.3 (project license):** pvault is licensed under `GPL-3.0-only`, Copyright 2026 Yash Sandeep Tamhane (Section 16, item 5; SI-04).
>
> **v7.2 (Milestone 1 approvals):**
> - Milestone 0.5 closed under the 7.1 criterion.
> - Randomness comes from `getrandom` only (7.1).
> - MSRV 1.89, with native 1.89 CI jobs on all three operating systems (12).
> - Argon2id memory is a pvault-owned buffer, because the `argon2` crate frees its own unwiped (10.2).
> - `cargo-deny` 0.20.2 runs in CI (14), from the checksum-verified release binary. Its license check includes dev and build dependencies.
> - `aes` is a direct dependency, only to enable `zeroize` on the AES key schedule (7.6).
> - Argon2id stays single-threaded, with no `rayon`; measured performance is in `docs/FORMAT.md`.
>
> **v7.1 (documentation corrections only):**
> - Milestone 0.5 acceptance reconciled with milestone-specific PENDING items.
> - Card files get an active-operation lifetime lock (7.4b), and `--force` is fully specified (7.9). Both are **PENDING**.
> - The TPM-identity proposal now covers the duress path (9.6).
> - F7, F25 and F75 are reconciled with the resource-message, same-TPM and public-capability rules.
>
> Items that still await evidence review or an author decision are marked **PENDING (SI-nn)**. They must not be implemented until resolved in `docs/SPEC_ISSUES.md`.
>
> **v6 changes from v5:** journal records both pre-write and post-write expected Names for new TPM indices; old TPM fields are adopted for cleanup only if the old `slots_mac` verifies; exclusive/shared vault locking plus a generation check before every commit; re-entered duress passphrases are verified against the old tag; new failure tests F54 to F72, verification-only authentication (5.5), fresh per-object keys rule, full Base32 and card-combination rules (F56 split into F56a/F56b); GF(2^8) field and card encoding fully specified; narrow key-table serialization path; mounted-session and K2 sequencing defined. This is the final spec revision before Milestone 0.5.
>
> **v5 changes from v4:** separate rules for TPM reads (provisional metadata, TPM-authorized) vs deletions (authenticated target only); dual-MAC "committing" journal record that is verifiable on both sides of the commit point; journal written before any TPM index is defined (no unjournaled orphans); duress handling during recovery; full-share card verification; portable Revoke keeps a valid slots structure; review gate scoped precisely; K2 destroys nothing until the countdown ends; secure creation rules for `.pvpartial`; new Milestone 0.5 (spec consistency pass).
>
> **v4 changes from v3:** header split into an authenticated *core* and a separately authenticated *slots* section (so Revoke never breaks recovery); explicit post-Revoke recovery algorithm; authenticated journal and verified ownership before any TPM cleanup; per-index random policy value so TPM Names are unique, captured after the first write; two-phase recovery with verified card delivery before anything old is retired; bundle rotation on every recovery; key table moved to its own chunked file; `chunk_count` derived from `size`; guarantees rewritten as conditional statements with explicit assumptions.

---

## 0. Instructions to the AI agent (read first, follow always)

You are building a security-critical tool. Correctness matters more than speed.

1. **Work one milestone at a time** (Section 13). Do not start the next milestone until the current one's acceptance criteria pass. At the end of each milestone, stop and give the human a short summary: what was built, test results, open decisions.
2. **Stop at the review gate (Milestone 8).** The gate covers exactly these features: owner Revoke, the duress *trigger action* (what happens when a duress passphrase matches), Erase, the flush step and K2 (everything under `destructive/`). Duress *setup* (generating the duress passphrase, computing and storing the tag) and duress handling during recovery are not destructive and are built before the gate. Do not write that code until the human confirms the review. Routine operations built earlier (`rm`, atomic header replacement, keytable file rotation, recovery cleanup, `fsck`) are allowed before the gate, but any TPM index deletion they perform must go through the ownership verification in 9.2b and pass its tests.
3. **Never invent cryptography.** Use only the primitives and crates in Section 7. The only hand-written crypto-adjacent code allowed is the Shamir module (7.4), and only if no listed crate fits.
4. **Do not add dependencies outside Section 7.6** without asking the human first.
5. **Secrets hygiene is mandatory** (Section 10).
6. **No `unsafe` Rust**, with two exceptions: where a listed crate requires it for FFI or memory locking, and platform FFI through `libc` / `windows-sys` within the scope of 7.6a. All such code lives in isolated `platform` modules. Each `unsafe` block gets a `// SAFETY:` comment, which is reviewed as security-critical code.
7. **Every failure scenario in Section 11 gets an automated test.** If a test cannot be written, say so explicitly.
8. **Never run destructive operations on real hardware.** TPM work uses the `swtpm` emulator; any access to a real TPM during development needs the owner's explicit authorization for that session. Device and flush work uses loopback devices and disk image files only.
9. **When the spec is ambiguous, ask.** Do not guess on anything in Sections 4 to 10.
10. **Never commit or push** unless the human asks. Never commit secrets, real passphrases or vault files.
11. **Wording rules:** never claim "unbreakable", "military-grade" or "512-bit security". State guarantees only in the conditional form used in Section 2.

---

## 1. What we are building

`pvault` is an **offline encrypted vault** for files, on any storage (internal drive, external SSD/HDD, pendrive, memory card). It never uses the network.

When creating a vault, the owner picks one of **two modes**:

| | **Bound mode** (default) | **Portable mode** |
| --- | --- | --- |
| Opens on | The laptop it was created on (elsewhere via recovery, including recovery to portable mode, 6.8) | Any computer with `pvault` installed |
| Daily unlock | Passphrase; the laptop's TPM releases its share automatically | Passphrase only |
| Key protection | Split: passphrase share + TPM share (+ card for recovery) | Passphrase-locked slot on the drive (+ two cards for recovery) |
| Resisting disclosure (theft or leak) | No single stolen item is enough: needs the passphrase **plus** the laptop TPM or the card | The passphrase alone is enough (protected by being randomly generated) |
| Surviving lost credentials | Passphrase + TPM for daily access; passphrase + card for recovery. **Losing the passphrase permanently loses access** (S1 and S2 are both passphrase-wrapped, so TPM + card cannot recover) | Passphrase for daily access; Card A + Card B for recovery (no passphrase needed). Losing the passphrase **and** either card permanently loses access |
| Wrong-guess limit | TPM dictionary-attack lockout | None; relies on passphrase randomness |
| Revoke (recoverable) | Deletes the TPM share (reliable) | Overwrites the slot section (best effort) |
| Duress | Available only while the TPM can delete the index without a prompt (9.3); otherwise reported as unavailable | Overwrites the slot section (best effort); unavailable on read-only file systems (8.5) |
| Changing the vault | Only on file systems that pass 8.5 (FAT/exFAT and network file systems are read-only in v1) | Same |
| Erase (permanent) | Complete only under the conditions in 9.8 | Never complete in software (9.8) |
| Trusts | The math + the TPM manufacturer | The math only |
| Backup cards | 1 | 2 (kept apart) |
| Platforms (v1) | Linux | Linux, Windows, macOS |

### Design principles

1. **Separate disclosure from availability.** Against disclosure, bound mode has no single point of failure (a thief needs the passphrase plus the TPM or the card); portable mode deliberately has one, the passphrase. For availability, the passphrase is essential in bound mode: forgetting it is unrecoverable. Docs must state both properties, never just one.
2. **A copy is frozen in time.** Someone can attack a copy for decades, so all safety margin must exist on day one.
3. **Standard primitives only.** Novelty is in the composition.
4. **Information-theoretic key splitting.** Below the threshold, Shamir shares reveal nothing.
5. **Hardware is a share, never the root of trust.**
6. **Keys live only while needed.**
7. **Erasure is only complete when every key copy and recovery path is gone.** Report honestly which ones survive.
8. **A mode never weakens the other.** A bound vault has no passphrase-only unlock path.
9. **Never act destructively on unauthenticated data.** Every deletion target must be authenticated and its ownership independently verified.
10. **Never retire old recovery material before the new material is verified.**

### Non-goals

Protecting data while a vault is open on a compromised computer; any network feature (except the desktop app's optional, off-by-default, signed update check); inventing cryptography.

---

## 2. Guarantees, stated with their assumptions

**Assumptions (A1 to A6).** All guarantees below hold only if:

- **A1** These primitives have no practical breaks beyond those publicly known today:
  - AES-256 (as AES-256-GCM-SIV, including POLYVAL);
  - ChaCha20 / XChaCha20 (including HChaCha20) and Poly1305;
  - SHA-256 (TPM Names and policies), SHA-512, HMAC-SHA-512 and HKDF-SHA-512;
  - Argon2id.

  The dual-cipher **chunk layer** (7.7) is designed so that file and key-table contents stay protected if **one** of AES-256-GCM-SIV or XChaCha20-Poly1305 is broken. Nothing else has that margin: key wraps (7.5) rely on XChaCha20 alone, and header, journal and duress authentication rely on HMAC-SHA-512 alone. A break that exposes wraps, keys or authentication can expose the vault. Docs must not claim that the whole vault survives a single cipher break.
- **A2** Quantum computers give no better than Grover's quadratic speedup against these symmetric primitives.
- **A3** Generated passphrases (main and duress) were generated by the tool (≥ 10 EFF words, ~129 bits) and are not disclosed. Custom main passphrases: no assumption is made; their strength is estimated only (SI-51).
- **A4** The OS random number generator is sound.
- **A5** The implementation is correct and free of exploitable side channels.
- **A6** For bound mode: the TPM behaves per specification and its secrets have not been extracted.

**Guarantees (conditional):**

| | Bound | Portable |
| --- | --- | --- |
| A copy of the vault alone | Unreadable under A1, A2, A4, A5 (a 256-bit TPM share is missing) | Unreadable under A1 to A5; offline guessing is designed to remain infeasible for 50+ years |
| A copy + the passphrase | Unreadable (TPM share missing) | **Readable.** By design |
| The laptop without the passphrase | Unreadable under A6; TPM lockout limits guesses | n/a |
| One backup card | Unreadable | Unreadable |
| A copy + one card | Unreadable without the passphrase; one full Argon2id run per guess, infeasible under A3 | Unreadable (one card reveals nothing) |
| A copy + the passphrase + the card | **Readable.** This is the recovery path, by design | n/a (a copy + the passphrase is already readable) |
| Both backup cards together | n/a | **Readable.** Keep them apart |
| Extracted TPM share + card | Requires a full Argon2id run per guess; infeasible under A3 | n/a |

The "50+ years" and "quantum-resistant" statements are **design targets under A1 to A3**, not unconditional promises. Docs and UI must use this wording.

**Crash safety** (Sections 6 and 8) is claimed only on file systems that pass 8.5, and only to the extent that the storage device honors the platform flush primitive. The automated crash tests inject process crashes. They do not demonstrate safety against power loss. **On Windows**, consistency after a power loss or OS crash additionally depends on unverified ordering assumptions (8.5, decision N1). If they fail, a vault can be left unreadable and must be restored from a backup.

---

## 3. Glossary

| Term | Meaning |
| --- | --- |
| **Key bundle** | Three independent random 256-bit keys `K_aes`, `K_chacha`, `K_mac` (96 bytes). Rotated on every recovery. |
| **Core** | The authenticated part of the header: metadata + key-table digest. Protected by `core_mac`. Never touched by Revoke. |
| **Slots** | The unlock-material part of the header (passphrase slot or bound S1, TPM pointers, duress tag). Protected by `slots_mac`. Portable Revoke overwrites its values; bound Revoke leaves it unchanged. |
| **Bound shares** | S1 (slots, passphrase-wrapped), S2 (TPM NV index, passphrase-wrapped), S3 (backup card). Any 2 of 3. |
| **Portable slot** | The bundle wrapped under a passphrase-derived key, in the slots section. |
| **Portable recovery cards** | Card A and Card B: Shamir 2-of-2 of the bundle. |
| **Policy nonce** | A random 32-byte value built into each TPM index's policy so its TPM Name is unique to that vault index. |
| **Revoke** | Removes the daily unlock path. Recoverable. Not erasure. |
| **Erase** | Owner-only attempt at full crypto-erasure, with an honest report of what survives. |
| **Flush step** | Fill free space with random data after an Erase, then delete it. Best effort. |
| **K2** | Whole-device destruction, per drive type. |
| **Duress passphrase** | A second generated passphrase that looks like a failed unlock and silently fires Revoke only. |
| **Journal** | `vault.journal`: authenticated record of an in-progress multi-step operation. |
| **Generation** | Authenticated transaction counter in the core. Incremented by exactly 1 by every commit that rewrites the core, which is every write made with the bundle. One approved exception (Milestone 3): the remote-rollback tracking commit uses `old_gen + 2` (8.1). Revoke and duress writes do not change it (9.7). `u64`. Overflow handling is **PENDING (SI-35)**; the proposal is that a commit that would overflow is refused. |
| **Vault path** | The unique, normalized relative path of a key-table entry (7.8). |

---

## 4. On-disk layout

```
my-vault/
  vault.hdr                       header: core + slots (deterministic CBOR, 4.4)
  keytable.<generation>.pv        encrypted key table (chunked, Section 7.8)
  objects/<file_id_hex>.pv        encrypted files (chunked, Section 7.7)
  vault.journal                   present only during multi-step operations (Section 8)
  vault.lock                      lock file (8.4)
  vault.hdr.tmp, keytable.<generation>.pv.tmp, objects/<file_id_hex>.pv.tmp,
  vault.journal.tmp               transient files during atomic replacement
```

- `<generation>` is written in decimal without leading zeros. `<file_id_hex>` is 32 lowercase hexadecimal digits.
- Lock files are zero-length, created without following symlinks, and never deleted or renamed while the vault exists. The gate lock file `vault.gate` is **approved for Milestone 3 (2026-10-05)** (SI-14). The name `vault.mount` is reserved; its use is **PENDING (SI-14 / SI-45)**.
- Card files are never written inside the vault directory (7.4b).
- Which leftover files `fsck` may delete, and on what authenticated basis, is **PENDING (SI-40)**. A file name alone never authorizes deletion.

### 4.1 Header structure (`vault.hdr`)

```
Header = CBOR map {
  "core":      CoreFields,
  "core_mac":  bytes(64),
  "slots":     SlotFields,
  "slots_mac": bytes(64)
}

CoreFields (deterministic CBOR map, 4.4) {
  magic            "PVLT"
  version          1
  vault_id         16 random bytes, fixed for the vault's lifetime
  mode             "bound" | "portable"
  argon2_m         u32, KiB
  argon2_t, argon2_p   u32
  salt             32 bytes
  generation       u64
  created_at       u64 (unix seconds)
  keytable_gen     u64  (which keytable.<gen>.pv is current)
  keytable_digest  64 bytes = SHA-512 of that keytable file
  card_set_id      8 bytes  (current recovery card set, 7.4a)
  setup_id         16 bytes (random, written once by init; matches the init journal)
  tpm_cleanup      array of 0..32 TpmCleanupEntry maps (approved; SI-35/SI-36)
  passphrase_kind  "words" | "custom" (the main passphrase kind; approved for Milestone 3; D1)
}

SlotFields, bound {
  s1_x (u8, must be 1), s1_nonce (24), s1_ct (96)
  s2_x (u8, must be 2), s2_nonce (24)
  tpm_nv_index      u32
  tpm_nv_name       bytes(34) (SHA-256 Name read AFTER S2 is written)
  tpm_policy_nonce  32 bytes
  tpm_id_template   u8 = 1 (approved; SI-36)
  tpm_id_nonce      bytes(24) (approved; SI-36)
  tpm_id_ct         bytes(48) (approved; SI-36)
  duress_tag        optional, 64 bytes
}

SlotFields, portable {
  slot_nonce (24), slot_ct (96)
  duress_tag        optional, 64 bytes
}
```

- The x-coordinate stored with S2 in the TPM index (9.1) must also be 2. Any other value is a parse failure.
- An optional field is absent when unused, never `null`. The presence of `duress_tag` is visible to anyone who can read the header (9.6).
- The exact TPM public area, including the 34-byte Name, is **PENDING (SI-22)**.
- A proposed `TpmCleanupEntry` has `tpm_index` u32,
  `name_prewrite` optional bytes(34), `name_postwrite` bytes(34),
  `policy_nonce` bytes(32), `tpm_id_template` u8 = 1, `tpm_id_nonce`
  bytes(24), and `tpm_id_ct` bytes(48). The exact token, sorting, capacity and
  overflow rules are **approved for Milestone 3 (2026-10-05)** and specified in 8.1.

### 4.2 The two MACs

```
core_digest = SHA-512("pvault/v1/core" || canonical_cbor(CoreFields))
core_mac    = HMAC-SHA-512(K_mac, "pvault/v1/core-mac"  || canonical_cbor(CoreFields))
slots_mac   = HMAC-SHA-512(K_mac, "pvault/v1/slots-mac" || core_digest || canonical_cbor(SlotFields))
```

- `slots_mac` binds the slots to one specific core.
- **Daily unlock verifies both MACs.** Recovery obtains the bundle using at most the share bytes it needs (bound: `s1_*`; portable: none), proves them via `core_mac`, then checks the old `slots_mac` and uses any other old slots field only if that check passes (Section 6.1).
- Portable Revoke overwrites the slots values and `slots_mac` only; bound Revoke deletes the TPM index and leaves the slots unchanged. In both cases `core_mac` and the key table stay valid, which is what makes recovery possible.

### 4.3 Parsing rules

- Header max size 64 KiB. Every field has a fixed or capped length. Reject unknown fields, duplicate keys and anything outside the 4.4 profile.
- **Argon2 limits, checked in this order before any Argon2 allocation:**
  1. **Hard caps** (format validity): `262144 ≤ argon2_m ≤ 4194304` KiB (256 MiB to 4 GiB), `3 ≤ t ≤ 16`, `1 ≤ p ≤ 8`, salt exactly 32 bytes. Out of range → `Unlock failed.`, treated as tampering.
  2. **Policy limit:** `argon2_m ≤ 50%` of **total** physical RAM. Exceeded → refuse with "This vault needs <m> of memory, more than this computer can provide."
  3. **Resource check:** currently available memory must cover `argon2_m` plus 64 MiB. Not met → refuse with "Not enough free memory to open this vault right now (needs <m>)." The 64 MiB margin is provisional (SI-16).
  4. Only then allocate. An allocation failure gives the resource message.

  Stored Argon2 parameters are **never** lowered or substituted to make an unlock fit. Policy and resource messages depend only on public header fields and the local machine (5.8). Memory queries use the platform FFI of 7.6a.
- The header parser is a fuzz target.
- Atomic write: `vault.hdr.tmp` → durable flush → rename → directory flush, using the primitive of 8.5 (the per-platform calls of 8.5, **approved for Milestone 3 (2026-10-05)**). Allowed only on file systems that pass 8.5. Atomic replacement gives consistency, **not erasure**.

### 4.4 Deterministic CBOR profile

Every CBOR structure in this spec uses this profile: the header, key table, journal, `partials.cbor`, `cards.cbor` and the rollback record. Encoders produce exactly this encoding, and decoders reject anything else. The 135-byte card payload (7.4a) is a fixed binary layout, not CBOR.

- **Encoding rules:** RFC 8949 §4.2.1 core deterministic encoding. Lengths are definite only, and every integer and length head uses its shortest form.
- **Allowed items:** unsigned integers (major type 0), byte strings (2), text strings (3, valid UTF-8), arrays (4), maps (5), and the simple values `false` and `true`.
- **Rejected items:** negative integers, tags, floats, `null`, `undefined`, all other simple values, and indefinite lengths.
- **Map rules:**
  - Structures are maps with text-string keys.
  - Keys are sorted by the bytewise order of their encoded form. Every key used here is shorter than 24 bytes, so this equals shortest-first, then lexicographic.
  - No duplicate keys and no unknown keys. Every required key is present; optional keys are absent when unused.
- **Field rules:** every field has a fixed type and a fixed or capped length, given in its schema. Integers are `u64` unless the schema says `u32`, `u16` or `u8`, and larger values are rejected.
- **Document rules:** exactly one top-level item, with no trailing bytes. Nesting depth is at most 4.
- **MAC and digest inputs:** computed over the exact encoded bytes as stored, which after validation are the deterministic encoding. Wherever this spec writes `canonical_cbor(x)`, it means the 4.4 encoding of `x`.
- **Encoder/decoder implementation:** a fixed-schema, in-house codec for every structure, **approved for Milestone 3 (2026-10-05)** (SI-07 option 2; `docs/M3_READINESS.md` D3).

---

## 5. Passphrase derivation and unlock

### 5.1 Derivation

```
master_pw     = Argon2id(version 0x13, password = handled passphrase bytes (7.3: H_w or H_c),
                         salt = core.salt, m = argon2_m KiB, t = argon2_t, p = argon2_p,
                         no secret, no associated data) -> 32 bytes
k_s1wrap      = HKDF-SHA-512(master_pw, info="pvault/v1/s1-wrap")       (bound)
k_s2wrap      = HKDF-SHA-512(master_pw, info="pvault/v1/s2-wrap")       (bound)
tpm_auth      = HKDF-SHA-512(master_pw, info="pvault/v1/tpm-auth")      (bound)
k_slot        = HKDF-SHA-512(master_pw, info="pvault/v1/portable-slot") (portable)
duress_key    = HKDF-SHA-512(master_pw, info="pvault/v1/duress")        (both)
journal_key   = HKDF-SHA-512(K_mac,     info="pvault/v1/journal")       (after unlock)
```

- Every HKDF call uses SHA-512 with **no salt**, which is the RFC 5869 default of 64 zero bytes. The input keying material is the value shown, `info` is the ASCII string shown, and the output length is **L = 32 bytes**.
- `tpm_auth` is therefore 32 bytes, within the limit for a SHA-256 nameAlg index (9.1).
- Milestone 1 publishes known-answer vectors for these derivations in `docs/FORMAT.md`.
- **Password input (7.3, SI-51):** H_w(input) for a generated (`words`) main passphrase, H_c(input) for a custom one. `duress_key` always comes from H_w(input), because duress passphrases are always generated. For a `words` main passphrase one run serves both. For a custom main passphrase with a duress tag, an ordinary unlock runs, in a fixed order, (1) H_c for the main keys and then (2) H_w for `duress_key` only. Each run's block buffer is wiped and freed before the next starts. **Exception (decision N3, 2026-10-05):** if generated-word handling refuses the typed input, the duress check is a non-match and run (2) is skipped, so only run (1) happens. Such input can never equal the generated duress words. The resulting timing difference is documented in 5.6. The kind is recorded as `CoreFields.passphrase_kind` and in the init journal, **approved for Milestone 3 (2026-10-05)** (SI-51 section 7; D1).

### 5.2 Bound unlock

```
1. Parse header; validate Argon2 caps (4.3).
2. Derive keys (5.1).
3. Duress check (9.6). On match: duress Revoke if bound duress is available (9.3), then return
   generic failure.
4. S1 = slots.s1_ct XOR XChaCha20(k_s1wrap, slots.s1_nonce)
5. Provisional read (9.2a): NV_ReadPublic(slots.tpm_nv_index); only if its Name equals
   slots.tpm_nv_name, S2_wrapped = NV_Read(slots.tpm_nv_index, auth=tpm_auth).
   Name mismatch -> generic failure WITHOUT attempting NV_Read (protects the DA counter).
   The session used for NV_Read is PENDING (SI-22). It must never silently fall back to a
   weaker session.
6. S2 = S2_wrapped XOR XChaCha20(k_s2wrap, slots.s2_nonce)
7. bundle = Shamir_combine(S1, S2)          (locked memory)
8. Verify core_mac, then slots_mac. Either fails -> generic failure.
   Only after this step are the slots (including the TPM fields) authenticated.
9. Rollback check (9.7). Open keytable.<core.keytable_gen>.pv, verify SHA-512 == core.keytable_digest, decrypt.
```

### 5.3 Portable unlock

```
1. Parse header; validate Argon2 caps.
2. Derive keys.
3. Duress check (9.6). On match: portable duress Revoke (only on a file system that passes 8.5),
   then return generic failure.
4. bundle = slots.slot_ct XOR XChaCha20(k_slot, slots.slot_nonce)
5. Verify core_mac, then slots_mac.
6. Rollback check; open, verify and decrypt the key table.
```

### 5.4 Guess verification (document accurately)

A passphrase guess can be checked offline in two ways: (a) the MACs after unwrapping or combining, and (b) the duress tag, for duress-passphrase guesses. **Both require a full Argon2id run per guess.** An attacker with an extracted, passphrase-wrapped S2 plus card S3 also needs a full Argon2id run per guess, because S2 cannot be unwrapped without `k_s2wrap`. None of these is a shortcut; all are defeated under A3.

### 5.5 Verification-only authentication

Some operations must prove the owner's secrets without side effects. They use `authenticate_verify_only()`, which has **one set of side-effect rules** and **two authentication paths**.

**Side-effect rules (all variants):**
- No duress check: no tag comparison, no Revoke, no duress action of any kind.
- No vault writes (header, slots, keytable files, objects, journal), and no TPM index creation or deletion.
- Failed TPM authorization may still update the TPM's dictionary-attack state. That is inherent to any TPM authentication attempt and is not a vault write.
- Rollback check: may **read** the local highest-generation record and warn, but must **not update** it.
- If the duress passphrase is entered, it fails like any wrong passphrase (`Unlock failed.`).
- **No duress-only derivation.** For a custom main passphrase, only the H_c derivation runs. The second, duress-only Argon2id run of 5.1 is skipped, because its sole purpose is the duress check.

**Path A: standard (K2 preflight, post-commit `init` completion).** The derivation and checks of 5.2 / 5.3, minus the duress check: bound mode reads S2 from the TPM, and both `core_mac` and `slots_mac` must verify.

**Path B: recovery-style (recovery, `verify-card`).** Follows Section 6.1 exactly: bound uses S1 + card, portable uses Card A + Card B. It needs **no TPM** (it works when the index is missing), requires only `core_mac`, and checks the old `slots_mac` solely to set `old_slots_authenticated`. A failed `slots_mac` does not fail this path.

Only an ordinary unlock runs the duress check. The complete list of commands, with their authentication and locks, is the table in 5.7. Docs must state that duress fires only on ordinary unlocks.

### 5.6 Failure behavior

All unlock failures print exactly `Unlock failed.` and take similar time. Argon2 parameters outside the hard caps fail fast, with the same message. The only exceptions are the conditions in 5.8, which depend solely on public state. Duress adds only a fast operation; the timing difference is measured and documented in Milestone 9, when the duress trigger is built.

For a custom main passphrase with a duress tag, both derivations run in a fixed order whenever generated-word handling accepts the typed input (5.1). That does **not** by itself establish timing equivalence between unlock outcomes. The complete unlock paths are measured at the applicable later milestones (Milestone 7 timing measurements; Milestone 9 for the duress path), and only measured results may be claimed.

**Documented timing difference (decision N3).**
- **When:** a duress tag exists, the main kind is custom, and generated-word handling refuses the typed input. The input-only refusal classes are:
  - empty after trimming;
  - more than 1,024 bytes after NFKC;
  - under the proposed `H_w_v1`, a code point unassigned in Unicode 17.0.0.
- **Effect:** the unlock runs one Argon2id instead of two, and finishes about one run sooner (about 2 s at the defaults on the measured Apple M4).
- **What an observer learns:** someone who can time unlock attempts learns that the typed text is in a refused class. When the typed text is the correct passphrase, that is a property of the secret passphrase. It reveals nothing about the bundle, the TPM share or the duress passphrase.
- **Already public:** whether a duress tag exists (9.6), and whether an unlock succeeded.
- **Avoidance:** an owner avoids the difference by choosing a custom passphrase that generated-word handling accepts. Whether pvault should warn about this at creation is not decided (**PENDING**).
- Verification-only paths never run the duress derivation (5.5), so they are unaffected.

### 5.7 Command authentication table and ordering

| Command | Authentication | Duress check | Vault lock (8.4) |
| --- | --- | --- | --- |
| `init` (new vault) | none; creates the vault | n/a | exclusive |
| `init` (resume, header present) | Path A (5.5) | no | exclusive |
| `init` (resume, no header) | init-journal MAC (8.3) | no | exclusive |
| `list`, `get` | ordinary unlock | yes | exclusive for the unlock, then shared |
| `add`, `rm` | ordinary unlock | yes | exclusive |
| `mount` | ordinary unlock | yes | exclusive for the unlock, then as SI-14 decides (**PENDING**) |
| `fsck` without secrets | none; reports only (8.2) | no | exclusive |
| `fsck` with the passphrase | ordinary unlock | yes | exclusive |
| `fsck` with recovery material | Path B | no | exclusive |
| `recover`, `recover --to-portable` | Path B | no | exclusive |
| `verify-card` | Path B | no | shared |
| `convert` | ordinary unlock | yes | exclusive |
| `duress set`, `duress disable` | ordinary unlock | yes | exclusive |
| owner Revoke, Erase | ordinary unlock | yes | exclusive |
| K2 preflight | Path A, per vault | no | shared |
| `status` | none | no | shared |
| `clean-partials` | none | no | none (7.9) |

**Order for every ordinary unlock:**
1. Take the lock.
2. Parse the header (4.3, 4.4).
3. Check the Argon2 limits (4.3).
4. Read the passphrase and run the word-list check (7.3).
5. Run Argon2id.
6. Run the duress check.
7. Check for a pending journal (8.4).
8. Perform the operation.

A pending journal therefore never prevents the duress check. Verification-only paths (5.5) follow the same order but skip step 6.

**TPM commands before Argon2id.** Before step 5, only unauthenticated public TPM queries may run: `GetCapability` (lockout and capability state, 5.8, 9.3) and `NV_ReadPublic`. Any TPM-identity computation proposed in SI-36 would be one more such query. No TPM command that carries authorization, or that can change the DA state, runs before step 5.

### 5.8 User-facing messages

| Condition | Message |
| --- | --- |
| Any failure decided after passphrase or card material is used: wrong passphrase, MAC failure, TPM authorization failure, Name or public-area mismatch, missing index, duress match. Also an unparseable header and Argon2 values outside the hard caps | `Unlock failed.` |
| TPM in dictionary-attack lockout | A lockout message (the TPM reveals this state) |
| No usable TPM (absent, no device permission, storage hierarchy disabled) | A specific message naming the cause |
| Bound creation without a measurable TPM identity (9.3, decision N2) | The 9.3 refusal, offering portable mode or `recover --to-portable` |
| Argon2 policy limit or resource check (4.3) | The specific messages of 4.3 |
| A word not in the word list (7.3) | "Word N is not in the word list." |
| Lock unavailable, vault mounted, pending journal (8.4); unsupported file system (8.5) | The specific messages of 8.4 and 8.5 |
| Card structure errors before any combination (7.4a) | The specific card messages |

A specific message may depend only on public state: header bytes, lock state, local machine resources, TPM state the TPM itself reports, and the typed input. It never depends on whether a secret is correct. `status`, and `fsck` without unlock, may report structural details such as "the header does not parse", because they reveal nothing an attacker holding the files does not already have.

---

## 6. Recovery (both modes)

Recovery always **rotates the key bundle** and uses a **two-phase commit with verified delivery** before anything old is retired.

### 6.1 Obtaining the old bundle

**Bound (passphrase + card):**

```
1. Parse header; validate Argon2 caps; derive keys from the passphrase.
2. S1 = slots.s1_ct XOR XChaCha20(k_s1wrap, slots.s1_nonce)   (slots_mac NOT required: may be stale after Revoke)
3. S3 = decode card (Base32 text or QR, 7.4a) and verify its `check` field
4. old_bundle = Shamir_combine(S1, S3)
5. Verify core_mac with old_bundle.K_mac. Fail -> generic failure.
6. Verify the OLD slots_mac with old_bundle.K_mac and record the result as
   old_slots_authenticated (true/false). Failure does NOT stop recovery.
```

Steps 2 to 5 use only `s1_x`, `s1_nonce`, `s1_ct`; tampering with them makes step 5 fail. Every other old slots field (TPM index, Name, policy nonce, duress tag) is used **only if `old_slots_authenticated` is true**:

- **true:** the old TPM fields may be journaled for cleanup (6.5) and the old duress tag may be used to verify a re-entered duress passphrase (6.7).
- **false:** recovery proceeds, but the old TPM index is **never deleted** (it is reported by `pvault status` and `fsck` for the owner to handle), and the old duress tag is treated as unavailable.

**Portable (Card A + Card B):**

```
1. Parse header; validate caps.
2. old_bundle = Shamir_combine(CardA, CardB)   (both checksums verified)
3. Verify core_mac. Fail -> generic failure.
4. Verify the OLD slots_mac -> old_slots_authenticated (true/false). Failure does not stop
   recovery. (After a portable Revoke it is always false.)
```

No slots data is used to obtain the bundle. The old duress tag is used only if `old_slots_authenticated` is true (6.7).

**Corruption limits (document):**
- Recovery needs a header that parses (4.4), an intact core, and, in bound mode, intact `s1_*` fields.
- Corruption of the CBOR structure, the core or (bound) `s1_*` can make recovery impossible, even with every credential.
- Owners must keep backups of the whole vault folder (Section 14). A backup is an older copy, with the risks described in 9.8. A portable backup plus the passphrase is readable, just like the live vault.
- A bound recovery path for damaged `s1_*` (passphrase + TPM + card, using S2 + S3) is **PENDING (SI-29)**. No path exists for a header that is lost or unparseable, and none is claimed.

### 6.2 Then, with `old_bundle` verified

```
Open keytable.<core.keytable_gen>.pv, verify its digest against the core, decrypt with old_bundle.
```

### 6.3 Phase 1: Prepare (nothing old is modified)

```
a. Generate new_bundle (three fresh independent keys).
b. Portable: generate a NEW passphrase (shown once) and new salt.
   Bound: keep the owner's passphrase; generate a new salt.
   Argon2 parameters for the new salt: PENDING (SI-35).
c. Bound: new Shamir 2-of-3 split -> S1', S2', S3'. Portable: new 2-of-2 split -> A', B'.
d. Bound: first measure the TPM identity (9.3, decision N2); if it cannot be measured,
   refuse before step e and offer `recover --to-portable`. Then choose a free handle
   (allocation and collision rules PENDING, SI-35) and a fresh
   policy nonce. Precompute BOTH expected Names
   from the index's public area (9.1), which is deterministic:
   new_name_prewrite  (TPMA_NV_WRITTEN clear) and new_name_postwrite (TPMA_NV_WRITTEN set).
e. Write journal {op: "recover", phase: "prepared", old_gen, new_gen, target_mode,
   old_core_digest, and, for a bound target, the complete new-index context plus
   its scope-3 encrypted identity token},
   MAC'd with journal_key(old_bundle). The exact schema is in 8.1.
   The journal is written BEFORE any TPM index exists, so an unjournaled orphan index
   can never be created.
f. Bound: define the new index (9.1) and confirm its Name equals new_name_prewrite; write
   wrapped S2'; confirm its Name now equals new_name_postwrite. Any mismatch -> abort and
   roll back (6.6).
g. Re-encrypt the key table under new_bundle -> keytable.<new_gen>.pv (tmp, fsync, rename).
   Ownership handoff (approved for Milestone 3; SI-38/SI-40, 8.1): create the empty tmp
   exclusively without following symlinks, journal its file identity durably in
   phase "target_created", and only then write key-table bytes.
h. Duress handling for the new slots (6.7).
i. Render the new card(s).
```

### 6.4 Phase 2: Verify delivery (still nothing old modified)

```
j. Owner proves each new card was delivered intact, by EITHER:
   - scanning the card's QR code, which must decode to the complete share, OR
   - typing the complete Base32 text (all 216 characters) from the printed card.
   The decoded share is compared byte-for-byte with the share in memory. A checksum match
   alone is not enough.
   Portable: the owner also types the new passphrase back from memory.
k. Any failure -> the journal is not advanced: it stays in its current phase, which is
   "target_created" once the target key table exists under the proposed 8.1
   phases (approved for Milestone 3), and "prepared" otherwise. The owner may
   re-render and retry, or abort.
   Abort = roll back (6.6). The old passphrase, old card(s) and old TPM index keep working.
```

### 6.5 Phase 3: Commit

```
l. Write a "committing" journal record that carries TWO MACs over the same content:
   mac_old = HMAC(journal_key(old_bundle), ...), mac_new = HMAC(journal_key(new_bundle), ...).
   Content is the exact 8.1 schema: immutable prepared fields including
   old_core_digest; new_core_digest; old_slots_authenticated. It carries no
   old-index fields (decision N4): when the old slots authenticated and were
   bound, the old index is tracked only by the scope-5 tpm_cleanup entry
   pre-staged in the new core (step m).
m. Write the new header atomically: new core (generation = new_gen, keytable_gen = new_gen,
   new digest, new core_mac, and any pre-staged old-index tpm_cleanup entry) and
   new slots (new slots_mac). THIS IS THE COMMIT POINT. Its exact core digest
   must equal the journal's new_core_digest.
n. Bound, only if the authenticated old-index fields exist: the new core already
   tracks the old index. If the matching TPM is present, verify ownership under
   9.2b and attempt to undefine it. If the TPM is remote, leave the cleanup
   entry authenticated in the core and report it. Even successful deletion or
   confirmed absence remains recorded until the next generation-plus-one
   commit prunes it.
o. Delete keytable.<old_gen>.pv. Approved for Milestone 3: only if its SHA-512
   equals the journal's old_keytable_digest; never by name alone.
p. Delete the journal.
q. Tell the owner to shred the old card(s). Old cards cannot open the new vault
   (the bundle rotated), but they remain a risk for older copies of the vault (9.8).
```

### 6.6 Crash and abort handling

Which side of the commit point the vault is on is decided only by an
authenticated **header whose recomputed core digest matches the corresponding
journal field** (`old_core_digest`, `new_core_digest` or
`tracking_core_digest`). Generation and journal phase alone never select a
side.

| Crash point | State | Resolution |
| --- | --- | --- |
| Before (e) | Old vault intact; nothing new written; no TPM index was created | Nothing to clean up |
| After (e), before (m) | Header authenticates and matches `old_core_digest`; journal `prepared`, `committing` or `rollback_tracking` | Owner unlocks with OLD material; `fsck` verifies the applicable journal MAC and follows the exact 8.1/8.2 state table. It deletes an index only after token, TPM identity, public-area and allowed-Name checks. A remote index is committed into authenticated rollback tracking only when old slots authenticate; otherwise the journal remains and the operation blocks. |
| After (m), before (p) | Header authenticates and matches `new_core_digest`; journal `committing` | Owner unlocks with NEW material; `fsck` verifies `mac_new`, repeats any failed post-replacement flush, preserves/resolves the pre-staged cleanup entry, and only then finishes steps n to p. |
| Abort during phase 2 | Same as "after (e), before (m)" | Same resolution, run immediately |

The owner can always open the vault with either the complete old set or the complete new set, never a mix. Because the journal is written before any index is defined, `fsck` can always account for every index the operation created. **Permitted exception:** an old index preserved because the old slots were not authenticated (6.1) is intentionally left in place and reported; it is not an orphan of the operation.

### 6.7 Duress across recovery

Recovery changes the salt and (bound) the TPM target, so the old duress tag cannot be carried over, and recovery material never includes the duress passphrase. If the old slots contained a duress tag, recovery must ask the owner to choose one:

1. **Re-enter the existing duress passphrase.** Offered **only if** `old_slots_authenticated` is true and the old slots contain a duress tag. The entered passphrase is run through Argon2id with the OLD salt and checked against the OLD tag (recomputed per 9.6 from the old, authenticated slots fields; under the proposed SI-36 formula a bound old tag also needs `ek_digest`, which the old bundle obtains by opening the old slots' scope-1 identity token, so no old TPM is needed; approved for Milestone 3, with the TPM work in Milestones 5 and 6). Only on a match is it re-derived with the new salt and a new tag written to the new slots. A mismatch rejects it; typing it twice is not verification.
2. **Generate a new duress passphrase.** Shown once, typed back to verify.
3. **Disable duress.** Requires typed confirmation `DISABLE DURESS`. `pvault status` then reports "Duress: off."

If the old tag is unavailable (old slots not authenticated, or randomized by a portable Revoke), only options 2 and 3 are offered. A stale tag must never be carried into new slots: it would silently stop working.

When the new slots are bound and bound duress is unavailable (9.3), options 1 and 2 are not offered. The owner is told that duress is unavailable on this TPM, and option 3 applies.

### 6.8 Recovery directly to portable mode (bound vaults)

`recover --to-portable` recovers a bound vault on any supported platform, with no working TPM.

1. Obtain and verify the old bundle exactly as in 6.1, bound path (passphrase + card). No TPM is used.
2. Prepare as in 6.3, for portable mode:
   - a new bundle, a new salt and a **newly generated** passphrase (shown once);
   - a new Card A / Card B set with a new `set_id`;
   - no TPM index is created, so the journal carries no new index fields;
   - journal `op: "recover"`, `target_mode: "portable"`.
3. Handle duress as in 6.7, producing a portable-mode tag.
4. Verify delivery of both cards and the new passphrase (6.4).
5. Commit as in 6.5, with `mode = "portable"`. Step n applies only if the old slots were authenticated **and** the old index passes 9.2b on this machine's TPM, including the same-TPM requirement. Otherwise the old index is left untouched and reported. Under the proposed SI-35/SI-36 design, an authenticated old index is also tracked in the new core's `tpm_cleanup` from the commit onward (approved for Milestone 3; implemented with recovery in Milestone 6); an unauthenticated one is never tracked or deleted.

**Remote old-index limitation (document):** an old index on another machine's TPM, or on a TPM that is unavailable, cannot be removed from here. It holds only a passphrase-wrapped share of the *old* bundle. Together with an older copy of the vault, the passphrase and an old card, it remains a risk for older copies (9.8). The owner removes it on that machine, with TPM tools or by clearing that TPM. `status` on that machine reports an index whose vault no longer matches.

### 6.9 Conversion between modes (`convert`): drafted in v7, confirm before Milestone 6

`convert` uses the same two-phase structure as recovery, but starts from an ordinary unlock.

1. **Unlock.** Ordinary unlock of the current vault (5.2 / 5.3), including the duress check. Typed confirmation: `CONVERT TO PORTABLE` or `CONVERT TO BOUND`. Refused on file systems that fail 8.5.
2. **Prepare** (nothing old is modified):
   - Generate a new bundle, a new salt, a new `set_id` and a new card set for the target mode.
   - **bound → portable:** generate a **new** passphrase (shown once), because it becomes the only barrier. No TPM index is created.
   - **portable → bound:** keep the owner's passphrase. Create the new index exactly as in 6.3 d to f, with the write-ahead journal written before the index is defined. This requires a usable TPM on this machine whose identity can be measured (9.3, decision N2); otherwise `convert` is refused before any write.
   - Re-encrypt the key table under the new bundle into `keytable.<new_gen>.pv`.
   - Handle duress as in 6.7, producing a tag for the target mode.
   - Journal `op: "convert"`, `target_mode`, MAC'd with `journal_key(old_bundle)`.
3. **Verify delivery** (6.4) of every new card, comparing the payload including the **new** mode (7.4a). For a portable target, the owner also types the new passphrase back.
4. **Commit:**
   - Write the dual-MAC "committing" record (8.1).
   - Write the header with the new mode. This is the commit point.
   - Retire old material. For bound → portable, delete the old index only under 9.2b: the unlock verified the old slots, and the same-TPM requirement applies. Under the proposed design it is tracked in the new core's `tpm_cleanup` exactly as in 6.5 m–n (approved; Milestone 6). Portable → bound has no old TPM material.
   - Delete `keytable.<old_gen>.pv`, then the journal.
   - Tell the owner to destroy the old cards.
5. **Crash and abort handling:** exactly as in 6.6.

Object keys are not rotated (6.11).

### 6.10 Duress setup: drafted in v7, confirm before Milestone 5

- **`duress set`:**
  1. Ordinary unlock, with the duress check, under the exclusive lock.
  2. Generate a duress passphrase (7.3) that differs from the real one. Show it once, and have the owner type it back.
  3. Compute the tag (9.6) from the current slots.
  4. Commit: write `keytable.<new_gen>.pv`, then the core (generation + 1) and the slots with the new tag, new `core_mac` and new `slots_mac`.
  5. Zeroize.
- **`duress disable`:** ordinary unlock, then typed confirmation `DISABLE DURESS`, then a commit that removes the tag.
- **During `init`:** the same step is offered after card verification and before the header write. In bound mode, the tag uses the new index fields.
- **Bound mode when duress is unavailable (9.3):** refused with a clear message.
- **Status:** `status` reports "Duress: on", "Duress: off" or "Duress: unavailable on this TPM / file system".
- **Read-only file systems:** refused (8.5).

### 6.11 What bundle rotation does not rotate (document)

Recovery and conversion rotate the bundle and re-encrypt only the key table; per-file keys and object files are unchanged. Anyone holding an old card set (or, in portable mode, the old passphrase) plus an older copy of the header and key table can still decrypt every object that existed at that time. That includes objects still present in the current vault. `recover --rekey-files` is deferred until a full protocol is reviewed (SI-37).

---

## 7. Cryptographic specification (do not deviate)

### 7.1 Randomness
OS CSPRNG for all secrets and nonces: `getrandom::fill`, or `getrandom::SysRng` where an API requires a `rand_core` RNG. `rand_core` 0.10 no longer has `OsRng`. An RNG failure is returned to the caller; no other source is ever substituted. Optional in bound mode, and **off by default**: XOR each key with `TPM2_GetRandom` output. Generate each bundle key independently.

### 7.2 Key bundle
`bundle = K_aes || K_chacha || K_mac` (96 bytes, each independently random). `K_aes`/`K_chacha` encrypt the key table; `K_mac` authenticates header and journal.

### 7.3 Passphrase
The full design, including the input rules, the estimator and the lifecycle, is SI-51 in `docs/SPEC_ISSUES.md` (approved).

- **Main passphrase: two kinds**, in both modes.
  - **Generated (`words`):** 10 to 16 words from the EFF large wordlist (7,776 words), selected by the owner, **default 12**. Each word is drawn uniformly: two bytes from `getrandom` as a big-endian `u16`, values of 62,208 or more rejected, the rest reduced modulo 7,776. Displayed as lowercase words separated by single spaces, with the calculated classical entropy `n × log2(7776)` and the policy rating (Medium for 10–11 words, Strong for 12–16; policy ratings, not guarantees).
  - **Custom:** written by the owner, handled by H_c (below). Its strength is **estimated at creation only** (`zxcvbn` 3.1.1 in a child process; SI-51 section 5). The estimate is never run at unlock, verification, or a recovery that keeps the passphrase.
- **Duress passphrase:** generated only, **fixed at 12 words** for now.
- **H_w, generated-word handling**, applied to `words` input (main and duress), including the init-journal key (8.3):
  1. Unicode NFKC.
  2. Trim leading and trailing whitespace.
  3. Replace each run of Unicode whitespace (the `White_Space` property) with one U+0020 space.
  4. Unicode lowercase (full `to_lowercase`, applied per character).

  Words are separated **only** by whitespace. Hyphens are part of words, never separators: the list contains `drop-down`, `felt-tip`, `t-shirt` and `yo-yo`.
- **H_c, custom handling:** Unicode NFC only; no trimming, lowercasing or collapsing. Refused and warned characters are listed in SI-51 section 3.
- **Normalization stability: approved for Milestone 3 (2026-10-05; SI-51; `docs/SPEC_ISSUES.md` 10.7; D2).** H_c output must stay identical for the life of a vault, across releases. Pinning the toolchain or the normalization crate per release does not guarantee that for code points that are unassigned today. A stable normalization-version policy must be approved at the Milestone 3 schema review, before any vault stores a custom credential. The proposal (`docs/M3_READINESS.md` D2) refuses code points unassigned in pvault's Unicode version for H_c, at creation and at every entry. It also replaces the H_w steps above with a frozen `H_w_v1`: Unicode 17.0.0 `Cn` refusal, NFKC, full default case folding, and a fixed `White_Space` set, from vendored, hash-pinned tables. That changes the Milestone 2 H_w code for non-ASCII input. When generated-word handling refuses a custom input, the duress check is a non-match and the duress-only run is skipped (decided N3; 5.1, 5.6).
- **Limits:** raw input ≤ 1,024 bytes; H_w output ≤ 1,024 bytes; H_c output 1 to 256 bytes.
- **Word-list hint (input only, `words` kind):** after H_w and before any key derivation, check each word against the embedded list. If one is missing, print "Word N is not in the word list." for the first such word and stop. No Argon2id run happens and the TPM is not touched. The hint depends only on the typed input.
- **Collision rule:** a collision means that the actual main credential, after generated-word processing, equals the generated duress credential: `H_w(main input) == duress words`. It is checked at duress setup and whenever either credential changes (new main passphrase, new duress passphrase). It is not a check over every possible input.
- Argon2id defaults `m=1 GiB, t=4, p=4`, caps in 4.3.

### 7.4 Shamir
**Field:** GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). A byte's bit *i* is the coefficient of x^i. Addition is XOR. Shares are evaluations of a random polynomial whose constant term is the secret byte; x-coordinates are the bytes 1, 2, 3 (never 0). Combination is Lagrange interpolation at x = 0. Milestone 2 must publish fixed test vectors (secret, coefficients, shares) in `docs/FORMAT.md` and test against them.

GF(2^8), bytewise over 96 bytes. Bound 2-of-3 (x = 1, 2, 3). Portable recovery 2-of-2 (x = 1, 2). Use `vsss-rs = "=6.0.1"` (decided; SI-08) through its public polynomial API, with **pvault-owned, zeroizing** coefficient, share and output storage. Do not use its byte API, which leaves secret-derived heap unwiped. Fresh coefficients per split, drawn uniformly over all 256 field values, including zero. The published vectors are in `docs/FORMAT.md` (Milestone 2).

### 7.4a Recovery card encoding

Binary payload (fixed 135 bytes):

```
magic      4 bytes  "PVC1"
version    u8       1
vault_id   16 bytes
mode       u8       0 = bound, 1 = portable
set_id     8 bytes  random per card set (identifies which recovery generation a card belongs to)
share_x    u8       Shamir x-coordinate
share      96 bytes
check      8 bytes  first 8 bytes of SHA-512("pvault/v1/card" || all preceding bytes)
```

- **QR code:** the raw 135-byte payload in byte mode, error correction level M. Rendered only as SVG (`qrcode` with default features off). QR input comes from a PNG image under the limits of 7.4c. Camera input is deferred to the desktop app (Milestone 14).
- **Typed form:** the payload in Crockford Base32, 216 characters, printed in groups of 4 separated by spaces, 8 groups per line.
  - **Bit order:** the 135 bytes are read as one big-endian bit string (most significant bit of byte 0 first), split into 216 consecutive 5-bit groups, each mapped to the alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (value 0 = `0`, value 31 = `Z`). 135 × 8 = 1080 = 216 × 5, so there is no padding.
  - **Input normalization:** case-insensitive; `I` and `L` read as `1`; `O` reads as `0`. Spaces, hyphens and line breaks are ignored as separators. Any other character (including `U` and Crockford's optional check symbols) is rejected. After removing separators, exactly 216 symbols are required.
  - Output always uses uppercase and the canonical alphabet.
- The parser rejects a wrong magic, version, length or `check`. `vault_id` must match the vault; a `set_id` that does not match the current set is reported as "an old card."
- **Field validation:** `mode` must be 0 or 1. When a card is used to **authenticate** (recovery, `verify-card`), `mode` must equal the vault's `core.mode` and `set_id` must equal `core.card_set_id`. During **delivery verification** of new cards, all fields (including `mode` and `set_id`) are compared against the expected in-memory payload; for `convert` that payload carries the **new** mode, not the old header's `core.mode`. `share_x` must be valid for the mode: bound cards carry x = 3 (S1 is always x = 1 and S2 always x = 2); portable cards carry x = 1 (Card A) or x = 2 (Card B).
- **Before combining any two shares:** both must have the same `vault_id` and the same `set_id` (equal to the current `core.card_set_id`), and their x-coordinates must differ. Duplicate coordinates, mixed card sets, or a mode/x mismatch are rejected before Shamir combination runs, with a specific message (e.g. "These two cards are both Card A.").
- Full-share verification (6.4) compares the whole decoded payload with the expected payload.
- Milestone 4 publishes payload, QR and Base32 test vectors in `docs/FORMAT.md`, before portable `init` relies on cards.
- **Uncommitted cards cannot authenticate a vault.** During an active preparation (recovery, `convert`, `init`), delivery verification (6.4) compares a scanned or typed card against the **expected payload held in memory** for that preparation, not against the header. After an interrupted preparation, those cards must be discarded: the preparation is rolled back (6.6), and a restart generates a new `set_id` and new cards. If the crash happened after the commit, the header already holds the new `card_set_id`, so those cards are current. No journaled card set is ever accepted for authentication.
- `set_id` is stored in the core so the tool can tell current cards from old ones. Add `card_set_id` (8 bytes) to `CoreFields`.
- **Portable `verify-card` needs both cards (document).** One portable card reveals nothing and cannot be checked alone. `verify-card` in portable mode therefore needs Card A and Card B together, which means briefly bringing them into one place. The owner should do this privately and separate the cards again afterwards. Public per-card commitments are not added in v1 (SI-34).

### 7.4b Card files

- **Destination:** card output goes only to a directory the owner names explicitly for that run. There is no default. The vault directory and anything inside it are refused.
- **Content:** one SVG file per card, containing:
  - the QR code;
  - the Base32 text, laid out as in 7.4a;
  - labels for the vault ID (hex), the card role (Bound card / Card A / Card B), the `set_id` (hex) and the creation date.

  A card file never contains a passphrase.
- **Creation:** each file is created relative to an opened handle of the destination directory, with exclusive creation and without following symlinks (the rules of 7.9). Permissions are owner-only: `0600`, or an owner-only ACL on Windows.
- **Tracking:** before any share bytes are written, each created file is recorded in the per-user record `cards.cbor`. The record holds `op_id`, the absolute path, the device and inode / file ID, `vault_id`, `set_id` and `created_at`.
- **Cleanup:**
  - It runs after successful delivery verification, after an abort or rollback, and (with owner confirmation, for stale records) in `fsck` and `clean-partials`.
  - A card file is deleted **only if** it is recorded, reopens as a regular file without following symlinks, and its device and inode / file ID match the record.
  - Anything else is dropped from the record and reported, never deleted. Files are never matched by name or pattern.
- **Active-operation lifetime lock and cleaner rules: PENDING (SI-10, with SI-14).** The design is in `docs/SPEC_ISSUES.md`. In summary:
  - Every operation that writes card files holds an exclusive per-operation lock, `cards/<op_id>.lock`, from before the first card file is created until all of its card files are deleted and its record entries removed.
  - A cleaner considers an entry only if it can take that lock without blocking. Otherwise it skips the entry entirely: not listed, not offered, not deleted.

  Until SI-10 is approved, no cleaner for card files may be implemented.
- **Remnants (document):** deleting a card file does not erase it from flash storage, file-system journals, backups, cloud-sync folders, print spoolers or thumbnail caches. Card text shown on screen can remain in terminal scrollback, terminal logs, screen recordings and shell history. The CLI never prints share material to the terminal unless the owner explicitly asks for it. Whether such a display option exists at all is **PENDING (SI-10)**.

### 7.4c PNG input limits (card QR codes)

- **File checks:** accept PNG only, and reject files larger than 16 MiB before decoding. Reject APNG (animated PNG).
- **Size limits:** reject a declared width or height above 4096 pixels. Reject an image whose decoded buffer (width × height × bytes per pixel, computed with overflow checks before any allocation) would exceed 64 MiB.
- **Decoding:** convert to 8-bit grayscale for `rqrr`, then zeroize every decoded pixel buffer after use, because it contains the share.
- **Payload:** exactly one QR code is decoded. Its payload must be exactly 135 bytes, and it is then validated under 7.4a.

### 7.5 Wraps
`ct = plaintext XOR XChaCha20_keystream(key, 24-byte random nonce)` via the raw `chacha20` crate, with the keystream starting at block counter 0 (draft-irtf-cfrg-xchacha-03). Unauthenticated by design; correctness is proven only by the MACs (5.4). Vectors are in `docs/FORMAT.md`.

### 7.6 Approved crates

| Purpose | Crate |
| --- | --- |
| AES inner layer | `aes-gcm-siv` |
| ChaCha outer layer | `chacha20poly1305` (XChaCha20Poly1305) |
| Raw stream cipher | `chacha20` |
| Password hashing | `argon2` |
| KDF / MAC / hash | `hkdf`, `hmac`, `sha2` |
| Constant-time | `subtle` |
| Shamir | `vsss-rs = "=6.0.1"` through its public polynomial API with pvault-owned storage (decided; SI-08; Milestone 2) |
| Secrets | `zeroize`, `secrecy` |
| Memory locking | `memsec` or `region` |
| RNG | `getrandom` (`fill`, `SysRng`); `rand_core` only as the trait an API requires |
| TPM (bound, Linux) | `tss-esapi` (version pin and features **PENDING SI-18**) |
| Unicode | `unicode-normalization` |
| Serialization | In-house fixed-schema codec for the 4.4 profile (approved for Milestone 3; SI-07 option 2). `serde` and `ciborium` are not used by product code (`ciborium` remains only a benchmark dependency through `criterion`) |
| CLI | `clap`. Terminal secret input uses bounded platform FFI (7.6a), **not** `rpassword` (approved; SI-51) |
| Custom-passphrase strength estimate | `zxcvbn = "=3.1.1"`, default features off, called **only** in the creation-time estimator child process (approved; SI-51) |
| Cards | `qrcode` (render; default features off, SVG only), `rqrr` (decode), `png` (QR image input, 7.4c) |
| Platform FFI (7.6a) | `libc` (Unix), `windows-sys` (Windows) |
| AES key-schedule wiping | `aes`, the same version that `aes-gcm-siv` resolves, used only to enable its `zeroize` feature (approved in Milestone 1) |
| Errors | `thiserror` |
| Platform dirs | `directories` |
| Tests / bench / fuzz | `proptest`, `tempfile`, `assert_cmd`, `criterion`, `cargo-fuzz` |
| Mount | `fuser` (Linux), WinFsp bindings, macFUSE / FUSE-T |
| Desktop app | `tauri` |
| PQC | `ml-kem`, `x25519-dalek`, `ed25519-dalek`, an ML-DSA crate (ask before choosing) |

Wordlist at `assets/eff_large_wordlist.txt`, embedded **unmodified** (SHA-256 `addd3553…903e`, tested), with 7,776 entries. Used under EFF's current **CC BY 4.0 International** grant (decided; SI-04), with attribution in `THIRD_PARTY_NOTICES.md`. The "CC BY 3.0 US" of earlier revisions is unverified history.

**7.6a Platform FFI scope.** `libc` and `windows-sys` may be used only for:
- process hardening (10.3);
- file-system operations required by 4.3, 7.4b, 7.9 and 8.5: handle-relative open, create and rename; no-follow flags; file identity; permissions and ACLs; flush primitives; file-system type queries;
- memory queries and memory locking (4.3, 10.2);
- file locking (8.4);
- terminal input and echo control (approved; SI-51): `/dev/tty` open, `tcgetattr` / `tcsetattr` / `read`, and `sigaction` for restoring the terminal on SIGINT, SIGTERM, SIGHUP and SIGQUIT (with SIGTSTP ignored during reads); Windows `CreateFileW` (`CONIN$` / `CONOUT$`), `GetConsoleMode`, `SetConsoleMode`, `ReadConsoleW` and `SetConsoleCtrlHandler`.

All such calls live in isolated `platform` modules, and their `// SAFETY:` comments are reviewed. If an operation this spec requires is unsupported on the platform or file system, the tool **refuses** that operation. It never substitutes a check-then-act fallback that weakens a no-follow or no-overwrite guarantee.

### 7.7 Chunked encryption format (objects and key table)

One format, two magics: `PVOB` for objects, `PVKT` for the key table.

```
magic        4 bytes   "PVOB" | "PVKT"
version      u16 BE    1
stream_id    16 bytes  (file_id for objects; vault_id for the key table)
context      u64 BE    (0 for objects; keytable_gen for the key table)
plain_size   u64 BE
records      chunk_count = max(1, ceil(plain_size / 65536)) records:
               rec_len  u32 BE
               n2       24 bytes
               c2       rec_len - 24 bytes
```

For record `i`:

```
aad   = "pvault/v1/" || magic || u16_be(version) || stream_id || u64_be(context)
        || u64_be(plain_size) || u64_be(chunk_count) || u64_be(i) || u8(is_last)
n1    = 12 random bytes
c1    = AES-256-GCM-SIV(key_aes, n1).encrypt(chunk_i, aad)
n2    = 24 random bytes
c2    = XChaCha20-Poly1305(key_chacha, n2).encrypt(n1 || c1, aad)
```

Rules:
- `chunk_count` is **derived** from `plain_size`, never stored separately or trusted from input.
- `rec_len` must equal exactly `24 + 12 + len_i + 16 + 16`, where `len_i` is the plaintext length of chunk `i` derived from `plain_size`. Any other value is rejected before decryption.
- Every chunk except the last decrypts to exactly 65,536 bytes. The last decrypts to `plain_size − 65536 × (chunk_count − 1)`, and only the last has `is_last = 1`. An empty stream is one chunk of 0 bytes.
- `version` is authenticated through the AAD. Only `version = 1` is accepted.
- **Reject any bytes after the last record.**
- Verify the outer tag, then the inner tag. Any failure aborts the whole stream.
- Objects use per-file keys `fk_aes`, `fk_chacha`. The key table uses `K_aes`, `K_chacha`.
- **Fresh keys and ID for every object write.** Every `add`, and every rewrite of an existing file (including writes through a mount), generates a **new random 16-byte `file_id`** and **new, independent random 32-byte `fk_aes` and `fk_chacha`** from the OS CSPRNG. Keys and IDs are never reused, never derived from each other, from the file name or content, or from the bundle. A rewrite creates a new object and a new key-table entry; the old entry and object are removed in the same commit (8.3 `rm` ordering). The tool also checks that a newly generated `file_id` is not already present in the key table (regenerate on collision).
- For objects, `stream_id` and `plain_size` must equal the key-table entry's `file_id` and `size`.
- The parser is a fuzz target.

### 7.8 Key table
- File `keytable.<generation>.pv`, format 7.7 with `PVKT`, `stream_id = vault_id`, `context = keytable_gen`.
- **Plaintext:** a deterministic-CBOR (4.4) array of entries, sorted by `path` (bytewise UTF-8), at most 64 MiB. The entry layout below is defined in v7; confirm it before Milestone 3.
  - File: `{ kind: "file", path, file_id: bytes(16), size: u64, created_at: u64, modified_at: u64, fk_aes: bytes(32), fk_chacha: bytes(32) }`
  - Directory: `{ kind: "dir", path, created_at: u64, modified_at: u64 }`
  - Timestamps are unix seconds. No permission bits are stored: exports are owner-only (7.9), and mounts present files as `0600` and directories as `0700`.
- **Parents:** every parent of an entry must itself be a `dir` entry; there are no implicit directories. `add` creates missing parents.
- **Entry limit (decided N5, 2026-10-05):** a key table holds at most **65,536 entries, counting files and directories together**. This is a v1 product limit.
  - An operation that would exceed it (`add`, including the parent directories it would create, and later mount writes) computes the resulting count after unlock and key-table decode, under the exclusive lock, **before any side effect**. It then refuses with "This vault can hold at most 65,536 files and folders." No journal, object, temp file or key table is created, the generation is unchanged, and the vault is byte-for-byte unchanged.
  - A decoded key table with more entries is invalid (`KeyTableCorrupt`).
  - The decode-time allocation bounds that rely on this limit are approved for Milestone 3 (D3).
- **Vault paths** are validated on input. Which checks also run when the key table is decoded, and how decoded paths are stored, zeroized and kept out of error text, is approved for Milestone 3 (SI-07, D7): decode-time validation applies only the rules that do not depend on the Unicode version: syntax, length, characters and duplicates. NFC and case-fold collision checks run on input only, so that a newer Unicode table cannot invalidate an existing vault. The rules are:
  - **Form:** an NFC-normalized text string; components separated by `/`; 1 to 4096 bytes in total; each component 1 to 255 bytes.
  - **Rejected:**
    - absolute paths (a leading `/`, a drive letter, a UNC or device prefix);
    - empty components, `.` and `..`;
    - `\`, NUL and other control characters (U+0000 to U+001F, U+007F);
    - names that cannot be created on every supported platform: the characters `< > : " | ? *`, a trailing space or dot, and the Windows reserved names `CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9` and `LPT1` to `LPT9` (case-insensitive, with or without an extension).
  - **Uniqueness:** two paths collide if they are equal after NFC and Unicode default case folding. No two entries may collide, and a file and a directory may not share a path. This is checked on input only (`add`, Milestone 4). The case-folding source (an approved crate, a vendored table, or `to_lowercase`) is therefore **needed before Milestone 4**, provided the decode/input split above is approved. If it is not approved, it is needed before Milestone 3.
- **Replacement:**
  - Adding a path that exists, or that collides with an existing one, fails unless `--replace` names exactly that path.
  - A replacement is a rewrite (7.7): a new `file_id` and new keys, with the old entry and object removed in the same commit.
  - Replacing a file with a directory, or the reverse, is refused.
- **Addressing:** `get` and `rm` address entries by vault path. `rm` refuses a non-empty directory unless `--recursive` is given.
- **Binding:** the key table is bound to the header by `core.keytable_digest` (SHA-512 of the whole file) under `core_mac`. It is non-circular: the key table never references the core MAC or digest.
- **Generations:**
  - Every commit writes `keytable.<new_gen>.pv`, then commits the header with `keytable_gen = generation = new_gen`, then deletes the old file. `new_gen = generation + 1`, with one approved exception (Milestone 3): the remote-rollback tracking commit uses `tracking_gen = old_gen + 2` (8.1, glossary).
  - `keytable_gen == generation` therefore holds after every commit, including commits that change only the slots; those re-encrypt the unchanged table.
  - The exact write ordering of `add` and `rm` for authenticated leftover handling is **PENDING (SI-40)**.

### 7.9 Decrypted output
- `get` writes to `<destination>.pvpartial` beside the destination, verifying each chunk; on full success fsync and rename; on failure delete it and return the generic error.
- **Secure creation of `.pvpartial`:**
  - Open the destination's parent directory first and operate relative to that handle (`openat`-style), so the directory cannot be swapped mid-operation.
  - Refuse if the destination path, the `.pvpartial` path, or the parent directory itself is a symlink (Windows: reparse point).
  - Create with exclusive creation (`O_CREAT | O_EXCL | O_NOFOLLOW`, mode `0600`; Windows: `CREATE_NEW`, `FILE_FLAG_OPEN_REPARSE_POINT`, owner-only ACL). If it already exists, refuse.
  - **Tracking partials outside the vault, in this exact order:**
    0. Generate a random 16-byte `transfer_id` and acquire an exclusive OS lock on `transfers/<transfer_id>.lock` in the platform config directory. **This transfer lock is held for the entire export**, until step 5 completes or failure cleanup finishes, and the OS releases it automatically if the process dies.
    1. Create the `.pvpartial` exclusively (rules above). It is empty.
    2. Obtain its identity from the **open handle** (`fstat` device + inode; Windows: volume serial + file ID).
    3. Durably record `{transfer_id, vault_id, absolute_path, device_id, inode_or_file_id, created_at}` in the non-secret per-user record `partials.cbor` (platform config directory, via `directories`).
    4. Only then begin writing plaintext.
    5. After the final rename, or after failure cleanup, remove the entry, then release and delete the transfer lock file.
    A crash before step 3 can leave an **empty**, untracked `.pvpartial`, but never untracked plaintext. A later `get` that hits it (exclusive creation fails) may delete it after owner confirmation **only if** it is a regular file (not a symlink) of size 0; otherwise it refuses and reports the path.
  - **`partials.cbor` integrity:** every read-modify-write of the record takes an exclusive OS lock on `partials.lock` beside it, writes `partials.cbor.tmp`, fsyncs, renames and fsyncs the directory. Readers take a shared lock. A malformed record is reported and never used to delete anything.
  - **Stale partials:** on the next `get` for that vault, or on `fsck`, the tool considers each recorded entry and first tries a **non-blocking** exclusive lock on its `transfers/<transfer_id>.lock`. If the lock is held, the export is still running: **skip the entry entirely** (do not list it, offer it or delete it). Only entries whose transfer lock can be acquired are treated as stale; the cleaner holds that lock while it lists and removes them, so the transfer cannot resume concurrently. It then asks the owner to confirm removal. Before deleting, it reopens the path without following symlinks and checks that it is a regular file whose device and inode/file ID match the record. Mismatched or missing files are only dropped from the record, never deleted. `pvault clean-partials` performs the same confirmed cleanup on demand, for both `partials.cbor` and `cards.cbor` (7.4b). It does not open or unlock any vault and takes **no vault lock**: it uses only `partials.lock` and the per-transfer locks, so it can run while a vault is busy. When cleanup runs inside `get` or `fsck`, it happens under the vault lock those commands already hold, with the same transfer-lock check.
  - **Final rename:** relative to the parent handle, using a no-replace primitive: `renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on macOS, and a handle-relative rename with replacement disabled on Windows. If the file system does not support it, `get` refuses. There is no check-then-rename fallback.
  - **`--force`: PENDING (SI-11).** The proposed design is an atomic exchange (Linux `RENAME_EXCHANGE`, macOS `RENAME_SWAP`) followed by inspection of the displaced entry. Its success, rollback, failed-rollback and crash cases, and the guarantees it actually provides, are specified in `docs/SPEC_ISSUES.md`. Until SI-11 is approved, `--force` is refused on every platform.
  - **Metadata in the record (document):** `partials.cbor` and `cards.cbor` hold absolute destination paths in plaintext while an export or card file exists.
  - The final file keeps owner-only permissions; the owner can change them afterwards.
- "No temporary plaintext" means none anywhere except the requested destination.
- Mount mode streams verified chunks and returns an I/O error on the first failure.

---

## 8. Journal and crash safety

### 8.1 Journal format
`vault.journal` is a deterministic-CBOR map (4.4). Each MAC is `HMAC-SHA-512(key, "pvault/v1/journal" || encoding of the record without its MAC field or fields)`. Unless stated otherwise, `key` is the `journal_key` derived from the bundle that is **current at the time of writing** (5.1). The journal is written with tmp, flush and rename (8.5).

**Schemas** (every field is required unless marked optional):
- **Common:** `vault_id` bytes(16), `op` text, `phase` text.
- **`IDX`:** present whenever the operation creates a TPM index. Context fields
  are `new_tpm_index` u32 (owner range), `new_name_prewrite` bytes(34),
  `new_name_postwrite` bytes(34), `new_policy_nonce` bytes(32), and
  `new_tpm_id_template` u8 = 1. Bound init adds
  `new_tpm_id_nonce_i` bytes(24) and `new_tpm_id_ct_i` bytes(48), the proposed
  SI-36 scope-2 token. A transition adds `new_tpm_id_nonce_o` bytes(24) and
  `new_tpm_id_ct_o` bytes(48), the proposed scope-3 token. The suffixes are
  part of the schema; these token fields are **approved for Milestone 3 (2026-10-05)**.
- **`op: "init"` (approved for Milestone 3; SI-38):** every phase has `setup_id` bytes(16), `mode` text, `salt` bytes(32) (the future `core.salt`), `argon2_m`, `argon2_t`, `argon2_p` (each u32, checked against the 4.3 hard caps before any derivation), `passphrase_kind`, `IDX` when bound, and `mac` bytes(64) keyed with `init_journal_key` (8.3). Phase-specific fields are:
  - `prepared`: no artifact identity, digest or expected-core field;
  - `keytable_created`: `keytable_id_kind` (`"unix"` or `"windows"`) and `keytable_file_id` (bytes(20) for Unix, bytes(32) for Windows; encoding below);
  - `keytable_written`: the `keytable_created` fields plus `keytable_digest` bytes(64) and `new_core_digest` bytes(64);
  - `committing`: the `keytable_written` fields plus `header_id_kind` and `header_file_id` with the same platform-dependent encoding.
- **`op: "recover"` or `"convert"`, `phase: "prepared"`:** `old_gen` u64, `new_gen` u64 (= `old_gen` + 1), `target_mode` text, `old_core_digest` bytes(64), `old_keytable_digest` bytes(64) (the old core's `keytable_digest`; approved for Milestone 3), `IDX` when the target is bound, and `mac` bytes(64) keyed with `journal_key(old_bundle)`.
- **Same ops, `phase: "target_created"` (approved for Milestone 3):** every field of the prepared record plus `target_kt_id_kind` and `target_kt_file_id`, the identity of the empty, exclusively created `keytable.<new_gen>.pv.tmp`. It is durable before any key-table byte is written, and later phases retain it. Single `mac` under `journal_key(old_bundle)`.
- **Same ops, `phase: "committing"`:** every field of the `target_created` record, plus:
  - `new_core_digest` bytes(64);
  - `header_id_kind` and `header_file_id`, the identity of the empty `vault.hdr.tmp` created before this record is durable (approved for Milestone 3);
  - `old_slots_authenticated` (bool);
  - `mac_old` and `mac_new` bytes(64), and no `mac` field.
  - **No old-index fields (decided N4, 2026-10-05).** The earlier
    `old_tpm_index`, `old_name_postwrite`, `old_policy_nonce` and scope-4
    `old_tpm_id_*` fields are removed. When the old slots authenticated and
    were bound, the old index is tracked only by the scope-5 `tpm_cleanup`
    entry pre-staged in the new core (6.5 m). Every restart path that may act
    on the old index authenticates that entry without the old TPM:
    - the new-side restart, and later `fsck` or rotations, have the new bundle
      (`core_mac`, `K_mac_new`);
    - on the old side the old index is still live and needs no cleanup;
    - an indeterminate header authorizes no deletion under any design.

    Scope value 4 is reserved and never used in v1.
- **Same ops, `phase: "tracking_created"` (proposed by the readiness audit;
  approved for Milestone 3):** the prepared record's immutable fields
  (including the new-index context, the original scope-3 token and any
  `target_kt_*` identity), **and, when it replaces a `committing` record,
  that record's `header_id_kind` / `header_file_id`** (the committing header
  temp, retained until its identity-checked removal is durable),
  `tracking_gen` u64 (= `old_gen` + 2),
  `cleanup_tpm_id_template` u8 = 1, `cleanup_tpm_id_nonce` bytes(24) and
  `cleanup_tpm_id_ct` bytes(48) (the scope-5 rewrap under old `K_mac`), and
  `track_kt_id_kind` / `track_kt_file_id`, the identity of the empty
  `keytable.<tracking_gen>.pv.tmp`. It is durable before any tracking
  key-table byte is written. Single `mac` under `journal_key(old_bundle)`.
- **Same ops, `phase: "rollback_tracking"` (approved for Milestone 3):** every
  `tracking_created` field plus `tracking_core_digest` bytes(64) and
  `track_hdr_id_kind` / `track_hdr_file_id`, the identity of the empty
  `vault.hdr.tmp` for the tracking header. It is written only after the
  tracking key table is final and durable and the complete tracking core is
  built, and before header bytes are written. Single `mac` under
  `journal_key(old_bundle)`. It has no `new_core_digest`: the abandoned target
  core is not a possible live side in this phase. It retains any `header_*`
  identity from `tracking_created` byte-for-byte; by then that file is gone
  (see the next paragraph), and a restart treats its absence as resolved.

**Resolving an existing `vault.hdr.tmp` before the tracking header temp
(approved for Milestone 3).** The tracking header temp reuses the
name `vault.hdr.tmp`, which a `committing` record may already own through
`header_file_id`. Before creating the tracking header temp, under the
exclusive lock, pvault:
1. **Reopens** `vault.hdr.tmp` relative to the held vault-directory handle,
   without following symlinks. If it is absent, go to step 4.
2. **Unlinks it only if** it is a regular file whose identity equals the
   `header_id_kind` / `header_file_id` retained in the authenticated
   `tracking_created` record (8.1 identity rules, same volume).
3. **Flushes the directory** (Linux `fsync(dirfd)`; macOS `fsync` and
   `F_FULLFSYNC` on `dirfd`; Windows relies on WO-3, 8.5). The retained
   identity stays in the journal until this flush has succeeded. A failed
   flush stops the operation; the journal stays at `tracking_created`, and
   the restart repeats steps 1 to 3.
4. Only then **creates** the new, empty tracking header temp exclusively,
   captures its identity, and makes `rollback_tracking` durable before any
   header byte.

**A mismatch blocks name reuse.** In these cases pvault never deletes or
overwrites the file, and the tracking commit stays blocked with the journal
retained:
- the identity differs or cannot be verified;
- the entry is not a regular file;
- the record carries no `header_*` identity, because the rollback started
  from `prepared` or `target_created` and the file is therefore unowned.

The entry is reported and can be removed only by exact owner confirmation
with a snapshot recheck (8.3 confirmation rules, with a live-vault phrase).
The vault stays readable meanwhile. The same rule governs the creation of the
`committing` header temp: an unowned `vault.hdr.tmp` already present blocks
the commit.
- **Revoke and Erase records:** designed at the Milestone 8 review.

**Expected-core binding (approved for Milestone 3).** Every expected-core field is exactly the 4.2 value `SHA-512("pvault/v1/core" || canonical_cbor(CoreFields))`, encoded as a CBOR byte string of length 64 and covered by the journal MAC. A restart classifies a header as old, new or rollback-tracking only when (1) its `core_mac` verifies with that side's bundle, (2) its recomputed `core_digest` equals the corresponding journal field in constant time, and (3) the applicable journal MAC verifies. Generation alone never selects a side. A dual-MAC record's MAC input omits both `mac_old` and `mac_new`; a single-MAC record omits `mac`.

**Artifact identity encoding (approved for Milestone 3; revised by the readiness audit).** Unix file identity (`id_kind` `"unix"`) is `u64_be(st_ino) || i64_be(birth_sec) || u32_be(birth_nsec)` (20 bytes), from `statx(STATX_INO | STATX_BTIME)` on Linux and `st_birthtimespec` on macOS. When it is verified, the candidate must also have the same `st_dev` as the **held** target-directory handle at that moment. Windows file identity (`"windows"`) is `u64_be(FILE_ID_INFO.VolumeSerialNumber) || FILE_ID_128.Identifier || u64_be(FILE_BASIC_INFO.CreationTime)` (32 bytes). The kind and bytes are captured from an already-open, securely created regular file and journal-authenticated before pvault writes its contents. A filename never proves ownership.

**Rule for every journaled artifact (approved for Milestone 3):** create the file empty with exclusive, no-follow creation; capture its identity from the open handle; make the identity durable in the journal; only then write bytes. Restart deletes an artifact automatically only when the selected authenticated journal records its identity and a no-follow reopen yields a regular file with that identity. A same-directory rename keeps the identity. An owned artifact that no header references yet may also be **resumed in place**: reopened without following symlinks, its identity verified, then truncated and rewritten. Its identity, and therefore the journal record, is unchanged. An artifact created in the window before its identity is journaled is unowned: it is reported, and deleted only by exact owner confirmation with a snapshot recheck. A file system that cannot provide the identity primitives (including birth time) fails the 8.5 preflight.

**Identity support and refusal rules, per platform (approved for Milestone 3).** Support is decided at run time from what the system actually returns, never from a kernel or OS version table:

| Platform (8.5 allowlist) | Query on the open handle | Supported only if | Same-volume check at verification |
| --- | --- | --- | --- |
| Linux: ext4, XFS, Btrfs | `statx(fd, "", AT_EMPTY_PATH, STATX_INO \| STATX_BTIME)` | the call succeeds and the returned `stx_mask` contains **both** `STATX_INO` and `STATX_BTIME`. `ENOSYS` (no `statx`) or a missing bit means unsupported. Whether a volume records birth time depends on its format (for example ext4 inode size), which is why the mask decides | `stx_dev_major`/`stx_dev_minor` equal those of the held target-directory handle |
| macOS: APFS, HFS+ | `fstat`: `st_ino`, `st_birthtimespec` | the call succeeds and `st_birthtimespec` is non-zero; a zero birth time means the volume records none | `st_dev` equals the held directory's |
| Windows: NTFS, ReFS (local only, 8.5) | `GetFileInformationByHandleEx` with `FileIdInfo` and `FileBasicInfo` | both calls succeed | `VolumeSerialNumber` equals the held directory's |

**Refusal rules:**
1. **Preflight:** the same queries run on the held vault-directory and `objects/` handles before the first side effect. Unsupported means the file system fails 8.5; the operation is refused and nothing is written.
2. **At creation:** if the query fails for a newly created artifact, or omits a required field, the operation stops before writing any byte or advancing the journal. The empty file stays unowned: it is reported and removable only by owner confirmation. There is no retry with weaker fields and no fallback to the name.
3. **At restart:** a failed query, a different volume or a different identity means no automatic deletion. Owner confirmation applies where 8.3 offers it; otherwise the operation stays blocked.

**What a match does and does not establish (document).** The identity is a strong discriminator tied to file-system metadata. It is **not a universally unique identifier**. A false match is possible in these cases:
- an inode or file ID is reused and the new file has an equal birth time (the HFS+ creation date has one-second resolution, and clock changes can repeat a time);
- creation times can be **set** by any process with write access: macOS `setattrlist`, Windows `SetFileTime`;
- ReFS file-ID reuse is not documented.

Its purpose is to prevent deletion by name or pattern and to catch accidental replacement. It is not a defense against a local adversary with write access to the vault directory, which 8.4 already puts out of scope (non-cooperating writers). Further limits:
- After the directory is moved to another system or volume, or restored from a backup, identities cannot be verified. The outcome is confirmation or block, never deletion.
- Comparing the device or volume against the live directory handle, rather than a recorded value, avoids false mismatches when device numbers change across reboots or remounts (btrfs subvolumes, removable media).

**Encrypted TPM-identity token (approved for Milestone 3; TPM measurement in Milestone 5).**
`tpm_id_template = 1` is the fixed TCG EK Credential Profile 2.5 R2 H-2 ECC
NIST P-256 storage-EK template: `type=ECC`, `nameAlg=SHA256`, attributes
`fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|adminWithPolicy|
restricted|decrypt`, Policy-B-SHA256
`ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0`,
AES-128-CFB symmetric definition, null ECC scheme, NIST P-256 curve, null KDF
and empty input `unique`.
`ek_digest` is `SHA-256` of the MU-marshalled returned `TPMT_PUBLIC`, including
the populated unique point and excluding the outer `TPM2B_PUBLIC.size`.
Unknown template values fail parsing. For each scope below, derive 32 bytes as
`HKDF-SHA-512(ikm=base_key, salt=empty, info=label, L=32)` and encrypt the
32-byte digest with XChaCha20-Poly1305, a fresh 24-byte nonce and this exact
AAD; ciphertext including tag is 48 bytes:

```text
ASCII("pvault/v1/tpm-id-token\0")
|| u8(scope) || vault_id[16] || u8(tpm_id_template) || u32_be(tpm_index)
|| u8(name_prewrite_present)
|| (name_prewrite[34] if present)
|| name_postwrite[34] || policy_nonce[32]
```

`name_prewrite_present` is exactly 0 or 1. The scopes are:

| Scope | HKDF label | Base key |
| ---: | --- | --- |
| 1 | `pvault/v1/tpm-id/slots` | current `K_mac` |
| 2 | `pvault/v1/tpm-id/init` | `init_journal_key` |
| 3 | `pvault/v1/tpm-id/new-index/old-side` | `journal_key(old_bundle)` |
| 4 | reserved; never used in v1 (decision N4) | none |
| 5 | `pvault/v1/tpm-id/cleanup` | current `K_mac` |

Decrypt only after the containing slots/core/journal MAC verifies. Scope, AAD
or AEAD failure is corruption and never authorizes deletion. Rewrap every
surviving cleanup entry with a fresh nonce on each bundle rotation and zeroize
the plaintext digest immediately. `tpm_cleanup` entries are sorted bytewise by
`(tpm_index, name_postwrite, policy_nonce, tpm_id_template, tpm_id_nonce,
tpm_id_ct)`; exact duplicates are rejected, and semantic duplicates may be
coalesced only after authenticated decryption proves all AAD context and the
digest equal.

The cap is exactly 32 entries. Before an operation that might strand a new or
old index, resolve locally inspectable records, coalesce only proven semantic
duplicates, and reserve one free entry before writing a journal, defining an
index or creating a target key table. If 32 distinct unresolved entries
remain, refuse with “TPM cleanup capacity is full; resolve a recorded index on
its original TPM.” Never evict, overwrite or create an untracked index. A full
vault remains readable and operations that cannot add a record may proceed.

**Parsing limits (all journals).** Maximum size 16 KiB; the 4.4 profile only; reject unknown fields, duplicate keys and wrong field lengths; any Argon2 parameters inside a journal must pass the 4.3 caps before use. The journal parser is a fuzz target (`journal_parse`). A journal that fails parsing is reported and never acted on.

**Transition records.** Any record written just before a commit point that changes the bundle (recovery, `convert`) carries **two** MACs, `mac_old` and `mac_new`, over identical content, so it can be verified whichever bundle the owner unlocks with after a crash. The authenticated expected-core digest, not the generation by itself, decides which side of the commit the vault is on.

**Write-ahead rule.** Any TPM index an operation will create is recorded in an authenticated journal record (handle, policy nonce, and both precomputed expected Names, pre-write and post-write) *before* it is defined. A later record for the same operation (e.g. "committing") replaces the earlier one and must carry the same index fields. A record naming an index that may exist is **never** replaced by a record naming a different index until that index is resolved. Resolved means confirmed absent, confirmed not ours, or deleted under 9.2b. The resolution procedure is **PENDING (SI-35)**.

**Core-binding crash order (approved for Milestone 3).** `prepared` with the immutable `old_core_digest` and `old_keytable_digest` is durable before any target side effect. The target key-table identity (`target_created`) is durable before any key-table byte. After every target dependency is durable, `committing` with the exact `new_core_digest`, the header-temp identity and both MACs is durable before any header byte and before header replacement. For remote pre-commit rollback, `tracking_created` (with the tracking key-table temp identity) is durable before any tracking key-table byte. The tracking key table is then made final and durable, the complete tracking core is built, and `rollback_tracking` (with `tracking_core_digest` and the tracking header-temp identity) is durable before any tracking header byte. A directory-flush failure after header replacement keeps the journal and every old/new dependency as 8.5 requires.

Rollback tracking changes the core while retaining the old authenticated slots. It therefore recomputes **both** `core_mac` and `slots_mac` under `K_mac_old`; the latter is over `tracking_core_digest || canonical_cbor(OldSlotFields)` exactly as 4.2 requires. This rewrite is allowed only after the old `slots_mac` verifies. If it does not verify and the target index cannot be resolved on the present TPM, pvault keeps the journal and blocks rather than authenticating provisional slots.

### 8.2 Rules for `fsck`
1. Without a full unlock, `fsck` only **reports** what it finds. It never deletes TPM indices, and never deletes anything referenced by an unauthenticated journal.
2. With a full unlock (or recovery material), `fsck` verifies the journal MAC with the matching bundle. An invalid journal is reported and left untouched.
3. **A recorded handle never authorizes deletion by itself.** Before undefining any index, `fsck` performs the ownership verification in 9.2b against the journal's authenticated Name and policy nonce.
4. Files not referenced by the current core may be deleted only after an unlock **and** with authenticated ownership. The exact rules are **PENDING (SI-40)**. A file name or pattern alone never authorizes deletion, and files whose ownership cannot be authenticated are only reported.
5. Because of the write-ahead rule, every TPM index created by `pvault` is journaled. An index found in the owner range that no authenticated journal or verified slots mention is **not ours by definition** and is never touched (reported only).

**Transition restart table (approved for Milestone 3).**
“Matches” below means journal MAC, applicable core MAC, constant-time expected
core-digest comparison and the required slots MAC have all verified.

| Journal and observed header | Required action |
| --- | --- |
| `prepared` or `target_created`; header matches `old_core_digest` | Resolve the target index locally if possible, then remove only the target artifacts whose identity the journal records (none in `prepared`). An unowned `vault.hdr.tmp` or journal temp is reported and blocks only the operations that need its name. If the index may exist only on a remote TPM and the old slots authenticate, create durable `tracking_created` and continue the tracking commit. If old slots do not authenticate, retain the journal and block. |
| `committing`; header matches `old_core_digest` | Verify `mac_old`, then use the same rollback rule as `prepared`; the new side did not commit. The committing header temp is owned through `header_file_id`. A local rollback removes it with the other identity-owned target artifacts; a remote rollback retains its identity into `tracking_created` and resolves it before the tracking header temp is created. |
| `tracking_created`; header matches `old_core_digest` | Verify the old core and slots plus the journal. **Resume in place:** reopen the tracking key-table file through its recorded identity (temp or already renamed), truncate it, rewrite it under the old bundle with `context = tracking_gen`, flush, rename it if it is still a temp (no-replace), and flush the directory. It is referenced by no header yet, so the rewrite is safe. Then resolve any committing header temp (8.1), create the tracking header temp and write `rollback_tracking`. A missing or mismatched tracking key-table file blocks (owner confirmation). |
| `rollback_tracking`; header matches `old_core_digest` | Verify the old core and slots plus the journal. Reopen the tracking header temp through `track_hdr_*`, truncate it and rewrite the tracking header, then flush, replace and post-flush. The bytes are reconstructible. Rebuild the tracking core from the authenticated old core, `tracking_gen`, the SHA-512 of `keytable.<tracking_gen>.pv` and the journaled cleanup entry, and require it to hash to `tracking_core_digest`; otherwise the state is indeterminate and blocks. The slots are the old slots, and the MACs are HMACs. Keep the journal across a post-replacement flush failure. A missing tracking header temp is indeterminate: retain the journal, delete nothing and report "The vault state could not be determined safely. No cleanup was performed. Run fsck." Do not infer a cause for the absence and do not create a replacement with an unjournaled identity. A present file with a mismatched identity is unowned residue and blocks for owner confirmation; it is not deleted. |
| `rollback_tracking`; header matches `tracking_core_digest` | The authenticated cleanup entry is authoritative. Repeat the post-replacement flush. Remove only identity-owned target and tracking temps, and the old key table only on a match with `old_keytable_digest` (it is also AEAD-provable under the old bundle). Flush, then durably remove the journal. The remote TPM is not needed. |
| `committing`; header matches `new_core_digest` | Verify `mac_new`, repeat the post-replacement flush, preserve/resolve the pre-staged old-index cleanup entry, delete `keytable.<old_gen>.pv` only on a match with `old_keytable_digest`, then durably remove the journal. |
| Missing, invalid or unexpected core in any phase | Indeterminate. Delete no file or TPM index; retain/report the journal. |

**Transition journal-temp promotion (approved for Milestone 3).**
A journal rewrite writes `vault.journal.tmp`, flushes it, replaces
`vault.journal` and flushes the directory. A crash can leave a canonical
record C and a temp T. These rules are separate from the init rules of 8.3,
and they run under the exclusive lock **before** the header is classified:

*Permitted transitions (T's phase given C's phase):*

| C (canonical) | T may be | Condition on the header |
| --- | --- | --- |
| `prepared` | `target_created`; `tracking_created` | Old (`old_core_digest`) |
| `target_created` | `committing`; `tracking_created` | `committing`: old, or new (`new_core_digest` of T; the Windows WO-1 case). `tracking_created`: old |
| `committing` | `tracking_created` | Old only; a committed transition is never rolled back |
| `tracking_created` | `rollback_tracking` | Old |
| `rollback_tracking` | none | n/a |

Anything else is not a permitted transition: skipped phases (for example
`prepared` → `committing` or `target_created` → `rollback_tracking`), backward
moves, and the same phase with different content. A T byte-identical to C is
an authenticated duplicate and is unlinked after the checks below.

*Authentication:*
- `prepared`, `target_created`, `tracking_created` and `rollback_tracking`
  carry one `mac` under `journal_key(old_bundle)`, so they need the old
  material.
- `committing` carries `mac_old` and `mac_new`. With old material, verify
  `mac_old`; with new material, verify `mac_new`.
- C must authenticate, with one exception. If T is `committing`,
  authenticates through `mac_new`, and its `new_core_digest` equals the
  authenticated header's core digest, C needs only to parse with immutable
  fields equal to T's. T contains every field of C, and only the new material
  is available after the commit.

*Field preservation (byte-for-byte, T versus C):*
- the immutable fields: `vault_id`, `op`, `old_gen`, `new_gen`,
  `target_mode`, `old_core_digest`, `old_keytable_digest`;
- every `IDX` field, including the scope-3 token;
- every artifact identity C carries (`target_kt_*`, `header_*`, `track_kt_*`),
  plus `tracking_gen` and the scope-5 `cleanup_tpm_id_*` once present.

T may only *add* the fields its phase introduces.

*Promotion:* if T is complete, parses within 16 KiB under 4.4,
authenticates, is a permitted transition and preserves the fields above,
pvault replaces C with T (preferring the successor) and flushes the directory.
Only then is the header classified with the promoted record.

*Invalid temps:* a T that is incomplete, unparseable or over its cap, fails
authentication, diverges in a preserved field, drops an identity, or makes a
non-permitted transition is **unowned residue**:
- it is never promoted and never deleted automatically;
- C alone drives the restart;
- because the next rewrite needs the name, any further journal rewrite (and
  so the operation) is blocked until the owner removes the temp by exact
  confirmation with a snapshot recheck;
- the vault stays readable.

**Crash points from `committing` through `tracking_created` to
`rollback_tracking` (approved for Milestone 3).** All of these happen on the old
side (the header still matches `old_core_digest`), with old material:

| Crash point | State left | Restart |
| --- | --- | --- |
| While writing the `tracking_created` temp | C = `committing`; T partial or complete | Complete and valid T: promote, then continue as `tracking_created`. Partial or invalid T: residue; C drives a fresh rollback attempt, which blocks on the residue name until confirmation |
| After `tracking_created`; empty `keytable.<tracking_gen>.pv.tmp` created but **before** the journal recorded it | C = `committing` (or a `tracking_created` T without that identity); unowned empty tmp | The tmp is unowned (create-before-identity window): reported, owner confirmation, the tracking path blocked until then |
| While writing tracking key-table bytes, or before its rename or directory flush | C = `tracking_created` | Resume in place through `track_kt_*` (8.2 row) |
| After the tracking key table is final, before the committing header temp is resolved | C = `tracking_created`, which retains `header_*` | Resolve the header temp (8.1 steps 1 to 3), then continue |
| After the header temp is unlinked, before the directory flush succeeds | C = `tracking_created` | Repeat steps 1 to 3; an absent file is resolved once the flush succeeds |
| After the empty tracking header temp is created, before `rollback_tracking` is durable | C = `tracking_created`; the name `vault.hdr.tmp` holds a file whose identity matches neither `header_*` nor a recorded `track_hdr_*` | Mismatch: name reuse is blocked and the file is unowned; owner confirmation, then continue |
| While writing the `rollback_tracking` temp | C = `tracking_created`; T partial or complete | Complete and valid T: promote. Otherwise: residue, with the same block rule |
| After `rollback_tracking`, before header replacement | C = `rollback_tracking`; header old | Rewrite the tracking header only through the recorded `track_hdr_*` identity. If the temp is absent, or if `keytable.<tracking_gen>.pv` no longer hashes to the digest inside the tracking core, the state is indeterminate: keep the journal, delete nothing and run `fsck`. The absent case is not attributed to any single cause and never authorizes creating a new temp. A present identity mismatch is unowned residue: keep it and the journal, and require owner confirmation. |
| After header replacement, before or during the post-replacement flush | Header = tracking core | Repeat the flush, then clean up: identity-owned temps and target artifacts, the old key table by `old_keytable_digest`, and finally the journal |

### 8.3 Operation ordering

| Operation | Order |
| --- | --- |
| `init` | The four-phase safe-init protocol below (approved for Milestone 3; `init` is built in Milestone 4): durable `prepared` journal → optional bound index → identity-journaled key-table temp → durable completed key table and `keytable_written` → cards/type-back/optional duress → identity-journaled header temp and `committing` → header commit → durable journal removal. |
| `add` | object tmp → flush → rename → new keytable file → header commit (generation+1) → delete old keytable file. A reordering for authenticated leftover handling is **PENDING (SI-40)** |
| `rm` | new keytable file without the entry → header commit → delete old keytable file → delete object. A reordering is **PENDING (SI-40)** |
| Recovery | Section 6, including 6.8 (directly to portable) |
| `convert` | Section 6.9 |
| `duress set` / `duress disable` | Section 6.10 |
| Revoke / Erase | Section 9 (journaled where multi-step) |

**Safe-init key and immutable record (approved for Milestone 3).** `init_journal_key = HKDF-SHA-512(master_pw, salt = empty,
info = "pvault/v1/init-journal", L = 32)`, where `master_pw` is the result of
the same single Argon2id invocation used by the future vault. Every phase
retains the common fields in 8.1 byte-for-byte and is re-MACed. Argon2 caps are
checked before deriving this key. Bound init also retains the complete
journaled index and encrypted TPM-identity token fields.

**Init bootstrap and preflight order (approved for Milestone 3).**
`init` must identify the file system and take the lock before it writes any
vault artifact, but the target directory T and the lock files may not exist
yet. Only the **bootstrap creations** below may precede the completed
preflight. They hold no secret and no vault data, and they are never deleted
by pvault (zero-length lock files and an empty T count as empty on a re-run).

1. **Open the parent P** of T as a directory handle. P's final component may
   not be a symlink or reparse point.
2. **If T does not exist:** identify P's file system with the 8.5 procedure,
   including, on Windows, the local-volume criterion. If P is unsupported,
   unknown or remote, refuse; nothing is created. Otherwise create T relative
   to P with mode `0700` / an owner-only ACL (**bootstrap creation 1**).
3. **Open T** relative to P without following symlinks, as a directory.
   Identify T's file system from its own handle (T can be a mount point).
   - If T was just created, it must be on the same mount and volume as P.
   - If T existed, it must be empty, apart from zero-length regular files
     named `vault.gate` or `vault.lock`.
   - Unsupported, unknown, remote or ambiguous: refuse.
4. **Create or open the lock files** `vault.gate` and `vault.lock` in T:
   - exclusive create, or open an existing zero-length regular file;
   - no-follow, mode `0600` (**bootstrap creation 2**).

   Take G, then L exclusive (SI-14). If locking is unsupported or fails,
   refuse. The lock files stay, as 4 requires.
5. **Under the lock,** re-check that T is empty except for the two lock files,
   which closes the race with a concurrent `init`.
6. **Complete the 8.5 preflight** on T's handle: directory flushes,
   file-identity primitives including birth time, Windows write-through and
   local-volume checks. Any unsupported result refuses; T and the lock files
   remain.
7. **Only now** may `init` write a vault artifact. The first is the
   `prepared` journal, before any TPM index, key table or header.

`init` does **not** create `objects/`. The first `add` (Milestone 4) creates
it relative to the locked T handle, opens it without following symlinks,
and must pass the same-mount check (8.5) before writing any object byte. If
the check fails, the empty directory remains and is reported; directories are
never deleted. Every write other than bootstrap creations 1 and 2 requires
the completed preflight and the exclusive lock.

**Safe-init artifact order and ownership (approved for Milestone 3).** Every create is relative to the already-open target-directory
handle, uses exclusive/no-follow creation, and must produce a regular file.
The monotonic protocol is:

1. Write and directory-flush `prepared` before defining a TPM index or creating
   an artifact.
2. Securely create an empty `keytable.1.pv.tmp`, capture its platform identity
   from that open handle, then durably write `keytable_created` before writing
   key-table bytes. Continue through the same handle; flush, rename to
   `keytable.1.pv`, and flush the directory. Compute `keytable_digest`, build
   the exact future core, and durably write `keytable_written` with its
   `new_core_digest`. Consequently, the authenticated identity—not a digest or
   filename—owns a completed key table left by a crash before the digest-phase
   update.
3. After cards, type-back and optional duress are final, securely create an
   empty `vault.hdr.tmp`, capture its identity, and durably write `committing`
   before writing header bytes. Write through the same handle; the header core
   must hash to `new_core_digest`. Flush and rename it, then execute the 8.5
   post-replacement directory/full-flush boundary.
4. Remove the canonical journal only after the committed header's core,
   `core_mac`, `slots_mac`, applicable journal MAC and `new_core_digest` all
   verify and the post-replacement flush succeeds. `header_file_id` owns only
   `vault.hdr.tmp` residue. A mismatch on the committed header is reported but
   does not block (readiness audit; the header bytes are already
   authenticated by digest and MACs).

The small create-before-identity-journal window is explicit: a temp created in
that window is not automatically owned. An unexpected final key table while
the canonical phase is `prepared` is likewise not owned. Both follow the
owner-confirmation rule below or leave init blocked.

**Interrupted journal rewrite (approved for Milestone 3).** A
`vault.journal.tmp` is not owned by its filename. After authenticating the
canonical journal, it may be promoted only if it independently parses and
authenticates under the same init key, all immutable fields match, and its
phase equals the canonical phase or its single permitted successor in the
sequence above. Prefer the valid successor; finish the rename and directory
flush. An incomplete, invalid, divergent or skipped-phase temp is merely an
unauthenticated residue.

**Owner-confirmed init residue (approved for Milestone 3).**
Only after the canonical init journal authenticates may pvault offer the exact
otherwise-unauthenticated regular-file candidates at `keytable.1.pv.tmp`,
`keytable.1.pv`, `vault.hdr.tmp`, and `vault.journal.tmp`. The name limits the
review set; it never proves ownership. Display each relative name, platform
file identity and byte length, then require the typed confirmation `DELETE
INIT LEFTOVERS <first-8-hex-of-setup_id>`. Immediately before unlink, reopen
relative to the target handle without following symlinks and require the same
regular-file type, identity and length as displayed. Decline, non-interactive
operation, missing/wrong setup passphrase, an identity or length change, or a
move between systems that makes the recorded identity unverifiable leaves the
canonical journal in place and init blocked. Symlinks, directories, special
files and entries at any other name are never offered or deleted; report them
for manual owner handling. Permanent lock files remain. External cards remain
governed by `cards.cbor`.

**Safe-init restart table (approved for Milestone 3).** Every
row runs under the exclusive lock. A malformed or unauthenticated journal
authorizes no deletion.

| Observation | Required action |
| --- | --- |
| No header; authenticated portable journal | Promote only a valid successor journal temp. Automatically delete a key-table or header artifact only when the selected journal authenticates its exact file identity. Offer only the four exact unauthenticated candidates under the confirmation rule. Remove the journal only after every artifact is resolved and the directory is flushed; otherwise remain blocked. |
| No header; authenticated bound journal; matching TPM | First resolve the journaled index using the encrypted identity token and both allowed Names, then apply the portable file rules. Remove the journal only after TPM and file cleanup are durably resolved. |
| No header; authenticated bound journal; original TPM unavailable | Preserve the journal and all artifacts. Report the handle and leave init blocked until cleanup can run on the original TPM. Init has no authenticated old core into which remote cleanup can migrate. |
| Header core digest equals `new_core_digest`, and header core, slots and journal all authenticate | The commit won. Preserve its index and files, repeat the post-replacement flush, then durably remove the journal. A `header_file_id` mismatch is reported only. |
| Header is malformed, foreign, mismatched or unauthenticated | Delete nothing; keep init blocked and direct the owner to recovery/fsck. |
| Journal is malformed, over its cap, wrong-passphrase, or has an invalid phase/digest combination | Delete nothing. Report generically; check the Argon2 caps before derivation. |
| Canonical journal is absent but `vault.journal.tmp` or another init-looking artifact exists | There is no authenticated ownership root. Do not promote, offer or delete it. The target is nonempty and init remains blocked until the owner removes or relocates it manually. |

An authenticated `keytable_created` identity is sufficient to own and remove
the same incomplete **or completed** key-table file after a crash; a content
digest is not required. Nothing in this protocol authorizes deletion by a
filename, glob or generation number alone.

### 8.4 Locking and concurrency

- Every vault has a lock file `vault.lock`. Locks use OS advisory locking (`flock` on Linux/macOS, `LockFileEx` on Windows), which the OS releases automatically if the process dies, so there are no stale locks to clean up.
- **Exclusive lock** for every mutation: `init`, `add`, `rm`, recovery, `convert`, `fsck`, Revoke, Erase, duress (taken before the duress check), and any operation that writes the journal, the header, keytable files, objects or TPM indices.
- **Every ordinary unlock takes the exclusive lock** for the Argon2id and duress-check phase, because any ordinary unlock might turn out to be duress. Verification-only authentication (5.5) makes no vault writes, so it needs only a shared lock (K2 preflight, `verify-card`), or runs under the exclusive lock its parent operation already holds (recovery, `init` cleanup). Read-only operations that unlock (`list`, `get`) then downgrade to a **shared lock** for the rest of their work. `status` never unlocks and only ever takes a shared lock. `verify-card` uses verification-only authentication (5.5) under a shared lock. This keeps lock behavior identical for normal and duress unlocks.
- Locks are taken without blocking: if unavailable, report "The vault is in use by another pvault process" and exit, rather than waiting indefinitely.
- **Lock conversion is never assumed to be atomic.** `flock` converts by releasing and then re-acquiring (Linux and macOS `flock(2)`). `LockFileEx` has no conversion. Rust's `File::lock*` leaves re-locking a handle that already holds a lock unspecified. The gate-lock protocol (G + L: exclusive acquire, downgrade, no re-locking of a held handle) is **approved for Milestone 3 (2026-10-05)** (SI-14). The upgrade-for-commit and mounted-session mechanics are **PENDING (SI-14 / SI-45)** until Milestone 11. No implementation may rely on PID or marker files for liveness, or on atomic conversion.
- **Mounted sessions** hold a shared lock for their lifetime. Writes made through the mount are performed by the mounting process, which upgrades to exclusive only for the duration of each commit. The mechanism is **PENDING (SI-14)**.
- **Intended restriction while mounted:** because every unlock needs the exclusive lock, CLI commands that unlock (`list`, `get`, `add`, `rm`, recovery, `convert`, `fsck`, Revoke, Erase) are refused while the vault is mounted, with the message "This vault is mounted. Use the mounted drive, or unmount first." `status` does not unlock: it reads the header and TPM state under a shared lock and works while mounted.
- **Generation check (best-effort detection):** immediately before every header commit, re-read the on-disk header and abort if `core.generation` differs from the value read at the start of the operation. This **detects some** conflicting writes, but it is not a guarantee: a writer that ignores the lock can still modify the header between the check and the rename. **Concurrency safety depends on every writer being a `pvault` process that honors the lock.** Other software writing into a vault folder is out of scope; document this in `docs/FAILURE_MODES.md`.
- Only one journal may exist per vault. Any operation that finds an existing journal must stop and direct the owner to `fsck`, **except the two handlers whose job is to resolve it:** `fsck` (resolves any journal per 6.6 and 8.2) and `init` (resolves an interrupted setup per 8.3; with no header it handles only `op: "init"` journals, and with a header present it only completes the post-commit case). Neither may start a new multi-step operation until the existing journal is resolved.
- If the file system does not support locking, refuse and say why (8.5).

### 8.5 File-system support and durability

- **Supported file systems.** Mutations are permitted only on a file system where pvault can provide all of: working advisory locks (8.4); a rename that atomically replaces a file within one directory; and a durable flush primitive. Mutations are writes to the header, key table, objects or journal, and duress actions that write the header. v1 decides support with an explicit allowlist of file-system types, queried from the open vault-directory handle:
  - Linux: ext4, XFS, Btrfs;
  - macOS: APFS, HFS+;
  - Windows: NTFS, ReFS.

  Detection is **approved for Milestone 3 (2026-10-05)** (SI-12). On Linux,
  obtain the mount ID for the already-open directory from
  `/proc/self/fdinfo/<fd>` or `statx(..., STATX_MNT_ID)`, match field 1 in
  `/proc/self/mountinfo`, split the record on ASCII spaces and scan after the
  six fixed fields for the first token exactly equal to `-`. The filesystem
  type is the token immediately after that separator; optional fields make its
  numeric position variable. Require the six fixed fields, the separator and
  the three documented post-separator fields, and accept only exact `ext4`,
  `xfs` or `btrfs`. The `statfs` magic `0xEF53` alone is insufficient because
  ext2, ext3 and ext4 share it. macOS and Windows use their handle-based volume
  queries and accept only exact APFS/HFS+ and NTFS/ReFS results respectively;
  query, parse or ambiguity failure refuses mutation.

  Readiness-audit additions (approved for Milestone 3):
  - **Windows local-volume acceptance criterion.** An SMB share can report
    the server's `NTFS`, so the file-system name alone is insufficient. For
    each held directory handle (T, and `objects/` when present), mutations
    are allowed only if **all four** queries give the accepting result:

    | # | Query on the handle | Accepting result | Any other result |
    | --- | --- | --- | --- |
    | Q1 | `GetFileInformationByHandleEx(h, FileRemoteProtocolInfo, …)` | The call **fails** with `ERROR_INVALID_PARAMETER` or `ERROR_NOACCESS`. Native Windows CI run 37390554153 observed `ERROR_NOACCESS` (998) for the runner's local NTFS temp directory; Microsoft does not document one unique local-volume error | Success means **remote**: refuse. Any other error code means **unknown**: refuse |
    | Q2 | `GetFinalPathNameByHandleW(h, …, VOLUME_NAME_GUID)` | Succeeds, and the path begins `\\?\Volume{` (a local volume GUID path) | Failure, a truncated buffer, or any other prefix (for example `\\?\UNC\`): refuse |
    | Q3 | `GetDriveTypeW` on the volume root taken from Q2 (`\\?\Volume{…}\`) | `DRIVE_FIXED` or `DRIVE_REMOVABLE` | `DRIVE_REMOTE`, `DRIVE_CDROM`, `DRIVE_RAMDISK`, `DRIVE_UNKNOWN`, `DRIVE_NO_ROOT_DIR`: refuse |
    | Q4 | `GetVolumeInformationByHandleW(h, …)` | Succeeds; the file-system name is exactly `NTFS` or `ReFS`; and for `objects/`, the `VolumeSerialNumber` equals T's | Failure, any other name, or a serial mismatch: refuse |

    - Queries run in order, and the first non-accepting result refuses with
      the 8.5 message. Nothing is retried with a weaker check, and every
      error is "unsupported or ambiguous".
    - **Evidence status:** the documented contracts are that
      `FileRemoteProtocolInfo` describes the remote protocol of a remote
      file, `VOLUME_NAME_GUID` returns a volume GUID path, and
      `GetDriveTypeW` classifies a root. Microsoft does not document one
      unique Q1 error for a local handle. Native Windows CI run 37390554153
      observed `ERROR_NOACCESS` (998) on local NTFS; the older anticipated
      `ERROR_INVALID_PARAMETER` remains accepted. Q2's failure mode on SMB
      is not yet verified.
    - The native Milestone 3 probe has recorded local NTFS. Remaining native
      coverage is a ReFS dev drive, a mounted VHD, a mapped SMB drive, an
      available UNC path and a `subst` drive. Until every query matches an
      accepted result, the criterion fails closed.
    - All four functions, `FileRemoteProtocolInfo` and `VOLUME_NAME_GUID`
      are in the `windows-sys` feature `Win32_Storage_FileSystem`, which is
      already enabled. The `DRIVE_*` constants are in
      `Win32_System_WindowsProgramming`, which is **not** enabled yet. That is
      a feature addition to the existing crate at implementation time, not a
      new dependency, and no dependency is changed now.
  - Every directory pvault writes in (`objects/`) is identified from its own
    held handle and must be the same mount and volume as the vault directory.
  - Linux identification needs `mnt_id` in fdinfo (Linux 3.15 and later) or
    `STATX_MNT_ID` (Linux 5.8 and later); otherwise the result is unknown.
  - **Preflight:** before the first side effect of a mutating operation, the
    required directory flushes (`fsync(dirfd)`; on macOS also
    `F_FULLFSYNC(dirfd)`) and the file-identity primitives (including birth
    time) are exercised on the held handles. Unsupported means the file system
    fails 8.5, and the operation is refused before anything is written.
    **Passing the preflight never weakens the post-replacement handling:** any
    failure after a header replacement call has been issued, whatever its
    error code (including `ENOTSUP` or `EINVAL` despite a passing probe), is
    classified by the failure boundary below ("outcome unknown" or
    "committed-visible, durability unknown"). It is never treated as a
    refusal or as an ordinary pre-commit abort.
- **Everything else is read-only for pvault v1.** This includes FAT32, exFAT, network file systems (NFS, SMB/CIFS) and FUSE file systems.
  - `status`, `list`, `get` and `verify-card` work, provided the lock files can be created and locked. Otherwise they are refused too.
  - `init`, `add`, `rm`, recovery, `convert`, `fsck` repairs, duress setup, owner Revoke and Erase are refused with: "This file system cannot safely store vault changes (<type>). Copy the vault to a supported drive to change it."
  - A matching **portable** duress passphrase fails like a wrong one and modifies nothing; `status` reports portable duress as unavailable on this file system. Bound duress acts on the TPM only and follows 9.3.
- **No crash safety is claimed on unsupported file systems.** A warning alone is not enough. Redundant headers are not added; they would need a separately reviewed protocol.
- **Durability primitives.** The per-platform table is **approved for Milestone 3 (2026-10-05; SI-12)**. The author selected **Windows W1**: keep NTFS/ReFS writable. The handle-relative Windows correction amends W1 only to name the primitive actually used:

  > After the temp-file flush, successful same-volume handle-relative
  > `NtSetInformationFile(FileRenameInformation)` replacement
  > leaves either the authenticated old header or the authenticated new header
  > after process, OS or power failure.

  This is a product assumption, not a Microsoft-documented guarantee and not a
  claim of verified power-loss safety. Microsoft documents that an NTFS
  write-through request flushes metadata changes such as a rename resulting
  from the request, so the verified source handle requests
  `FILE_WRITE_THROUGH`. That statement does not establish ReFS behavior,
  old-or-new crash atomicity, power-loss safety or equivalence to
  `MoveFileExW(MOVEFILE_WRITE_THROUGH)`. **Scope
  decided (N1, 2026-10-05): Windows power loss is documented as able to break
  a vault.**
  Linux and macOS order earlier creations and deletions before the header
  commit by flushing the directory. Windows offers no directory flush without
  administrator rights, so on Windows the protocols *depend* on these
  **unverified ordering assumptions**:

  - **WO-1 (journal first):** a journal written through a
    `FILE_WRITE_THROUGH` handle, flushed with `FlushFileBuffers` and renamed
    into place with handle-relative
    `NtSetInformationFile(FileRenameInformation)` is durable before any later
    artifact of the same operation.
  - **WO-2 (key table before header):** `keytable.<n>.pv`, created and moved
    into place the same way, is durable before the header that references it.
  - **WO-3 (deletions do not overtake the commit):** deleting
    `keytable.<old_gen>.pv`, a temp or the journal after a commit never becomes
    durable ahead of that commit's header replacement.
  - **W1 (header replacement):** the selected assumption quoted above.

  None of these is a Microsoft-documented guarantee, and none is verified by
  pvault's tests. Process-crash tests cannot exercise them, because a killed
  process does not lose the operating system's pending writes.

  **What can go wrong (document in FAILURE_MODES):** after a power loss or OS
  crash during a commit on Windows, if WO-2, WO-3 or W1 does not hold, the
  surviving header can reference a key table that no longer exists or never
  reached the disk. The vault is then **unreadable**: the key table holds the
  per-file keys, so neither the passphrase nor the recovery cards can restore
  its files. The only remedy is a backup of the whole vault folder. If WO-1
  fails, artifacts can survive without their journal. They are unowned, are
  never deleted automatically, and need owner confirmation; this causes no
  data loss. pvault reports these risks and does not claim power-loss safety
  on Windows. Process-kill tests establish only
  process-crash consistency on the tested systems; VM power-cut probes are
  configuration evidence and do not upgrade the claim. The other proposed
  calls and evidence are in SI-12 and `docs/M3_READINESS.md`:
  - macOS `fsync` does not flush the drive cache, but `F_FULLFSYNC` does.
  - Linux `rename` atomicity is defined for concurrent observers, not for crashes.
  - Windows `MOVEFILE_WRITE_THROUGH` is documented for copy-and-delete moves;
    it does not document the handle-relative same-volume rename used here.
- **Write sequences (approved for Milestone 3; SI-12):** Linux writes and `fsync`s the
  temp, performs same-directory `renameat`, then `fsync`s the directory.
  macOS writes and `F_FULLFSYNC`s the temp, performs same-directory `renameat`,
  then performs both `fsync(dirfd)` and `F_FULLFSYNC(dirfd)`. Windows writes a
  temp opened with `FILE_WRITE_THROUGH`, calls `FlushFileBuffers`, then opens
  the source relative to the held directory with `NtCreateFile` (no-follow)
  with `FILE_WRITE_THROUGH` and performs a same-directory, handle-relative
  `NtSetInformationFile(FileRenameInformation)` replacement. It then reopens
  and authenticates the destination. An unsupported required primitive causes the
  standard refusal; it is never replaced silently with a weaker call.
- **Failure boundary (approved for Milestone 3; SI-12):**

  | Observation | Required classification and handling |
  | --- | --- |
  | Failure before the replacement call | Pre-commit abort. Preserve the old authenticated header; clean only authenticated new artifacts, retaining the journal until cleanup is durable. |
  | Replacement reports failure | Reopen and authenticate `vault.hdr`: exact old bytes mean replacement did not occur and the original I/O error is a pre-commit failure; exact new bytes follow the post-replacement rule. Neither, absence or an unreadable header is outcome unknown: retain the journal and header temp, perform no cleanup, and report "The header replacement outcome could not be determined. Run fsck before making further changes." |
  | Replacement succeeds and all required directory/full flushes succeed | Commit durability is confirmed under the platform policy. Complete authenticated/deferred cleanup, then unlink and directory-flush the journal. |
  | Replacement succeeds but a required directory/full flush fails | New header is visible but durability is unknown. Return a distinct “The new header is visible, but commit durability could not be confirmed; run fsck.” error. Keep the `committing` journal and every old/new dependency; do not report or execute an ordinary pre-commit abort. Restart authenticates the exact core, retries the flush, and only then continues cleanup. |
  | Journal unlink succeeds but its directory flush fails | Report durability unknown. Restart may see the stale authenticated journal and resolves it from the exact header digest; never assume it disappeared. |

- **Testing.** The automated crash tests (F25, F26, F44, F45, F54, F67) inject **process** crashes. They do not establish power-loss safety, which depends on the file system and the device honoring the flush primitive. Documentation must say so.

---

## 9. TPM, Revoke, Erase, duress and rollback

### 9.1 TPM index definition (bound)
- Owner-range handle (`0x01800000` to `0x01BFFFFF`), size 97 bytes (x + wrapped S2).
- Attributes: `AUTHREAD`, `AUTHWRITE`, dictionary-attack protection **on** (no `NO_DA`).
- `authValue = tpm_auth`.
- `authPolicy = PolicyOR(PolicyAuthValue_digest, H("pvault/v1/policy-nonce" || tpm_policy_nonce))`. The second branch is unsatisfiable on purpose; its only job is to put a random 256-bit value into the index's public area so its **Name is unique to this vault index**.
- Writing S2 sets `TPMA_NV_WRITTEN`, which changes the Name. Both Names are precomputed from the public area before definition (6.3 d); after defining, confirm the pre-write Name; after writing S2, confirm the post-write Name. **Only the post-write Name is stored in the slots.**
- **Author-selected v1 policy (P1):** the nonce-policy construction above is
  the only v1 policy branch. PCR binding would change the NV policy, expected
  Names, cleanup reconstruction, encrypted identity-token AAD and duress tag;
  it therefore requires a future reviewed format revision and is not a
  runtime-only addition to v1.
- Develop against `swtpm`. A real TPM is used only behind `--tpm device`, and during development only with the owner's explicit authorization.
- **PENDING (SI-18 / SI-22):** the exact public area (nameAlg, the full `TPMA_NV` value pre- and post-write, `dataSize`), the policy-digest construction, the pinned TPM dependencies and the session design. The proposal is salted HMAC sessions with parameter encryption that fail closed rather than weaken. The design and its trust assumptions are in `docs/SPEC_ISSUES.md`.

### 9.2 Reads vs deletions

**9.2a Reads (unlock).** Reads use the slots' TPM fields *provisionally*, before they can be authenticated (the bundle does not exist yet). Confidentiality comes from the TPM's own authorization (`tpm_auth`) and the MACs checked afterwards: a wrong target yields a wrong bundle, which fails `core_mac`.

Before `NV_Read`, the tool runs `NV_ReadPublic` and checks that (1) the Name equals the provisional `tpm_nv_name`, and (2) the public area exactly matches pvault's format: the attributes and size from 9.1, and an `authPolicy` equal to the PolicyOR digest recomputed from the provisional `tpm_policy_nonce`. On any mismatch it skips `NV_Read` and fails generically.

**What this does and does not achieve (document it):** it catches corrupted or mismatched headers, and an unrelated (non-pvault) index cannot pass check (2). It does **not** establish ownership: an attacker who controls the header can supply consistent fields for some other pvault-format index, or for a decoy they created, and so cause failed authorization attempts that count toward the TPM's global dictionary-attack lockout. That is a local denial-of-service risk, not a confidentiality risk. A local attacker with TPM access can cause lockout by other means anyway.

**9.2b Deletions (ownership verification).** Required before ANY undefine:
1. The handle, expected Name and policy nonce come from an **authenticated** source: a verified `slots_mac`, a verified journal record, a verified duress tag, or (approved for Milestone 3) a `tpm_cleanup` entry in a core whose `core_mac` verified. A cleanup entry supplies its postwrite Name and, when present, its prewrite Name. Provisional (unverified) slots never authorize deletion.
2. `NV_ReadPublic(handle)` → compute the Name → it must equal an expected Name exactly, and the public area must have exactly the attributes, size and policy from 9.1 (recomputed from the policy nonce). Verified slots and the duress tag supply one expected Name (post-write). A journal record for an index the operation created supplies exactly two (`*_prewrite`, `*_postwrite`) for that one handle; no other values are accepted.
3. **Same TPM.** The index must be on the same TPM that created it. An index is never deleted merely because its handle, Name and policy nonce match on whatever TPM is present. The mechanism for establishing TPM identity is approved for Milestone 3 (SI-36; the measurement is implemented in Milestone 5): the encrypted identity token of 8.1. decrypt the authenticated token, measure the live H-2 EK digest, and compare them in constant time. Until it is approved, deletion is refused whenever the TPM identity cannot be established, and the index is reported.
4. Only then may the tool undefine it, with owner authorization as described in 9.3.
5. **Residual case (document it):** an attacker who first deletes the real index and then re-creates an identical one at the same handle, using the policy nonce read from the header, would pass this check. Deleting that decoy causes no harm, because the real index is already gone. Name matching rules out unrelated indices; it cannot prove lifetime identity.

### 9.3 TPM owner authorization and bound duress availability

Defining and deleting owner-range indices is authorized by the **owner hierarchy**, not by the index's own authValue. Owner authorization is often empty on Linux. A local process with TPM access can then delete S2: sabotage equivalent to Revoke, recoverable with the card, not a disclosure.

- **pvault v1 never sets or changes owner authorization.** `tpm-harden` is removed.
- **Externally configured owner authorization:** pvault asks for it whenever it must define or delete an index (`init`, recovery, `convert`, `fsck` cleanup, owner Revoke). It is never stored.
- **Bound duress availability:** the duress action is deleting the index, and duress cannot prompt. Bound duress is therefore **available only if** the index can be deleted with no prompt at that moment:
  - owner authorization is empty (`TPMA_PERMANENT.ownerAuthSet` clear);
  - the storage hierarchy is enabled (`TPMA_STARTUP_CLEAR.shEnable` set);
  - the TPM is not in lockout (`TPMA_PERMANENT.inLockout` clear). While in lockout, commands authorized by anything other than platform or lockout authorization fail.

  The exact capability checks and their timing are prepared for review before Milestone 5 (**PENDING SI-42**). If the SI-36 proposal is adopted, a fourth condition applies: the TPM identity must be computable without a prompt (endorsement hierarchy enabled, endorsement authorization empty, and the fixed H-2 ECC P-256 EK creatable). Because the proposed bound slots and `IDX` records **require** the identity token, the same condition also gates *creating* any bound index.
- **Decided N2 (2026-10-05):** bound `init`, bound recovery and `convert` to bound measure the identity before any journal is written, any index is defined or any file is created. If the measurement fails, the operation is refused and portable mode is offered explicitly:
  - `init`: "This computer's TPM identity cannot be established, so a bound vault cannot be created here. You can create a portable vault instead."
  - bound recovery: the same reason, offering `recover --to-portable`.
  - `convert` to bound: the same reason; the vault stays portable.
- Nothing is written, and the vault is unchanged.
- The identity-token mechanism is approved for Milestone 3 (SI-36).
- **When bound duress is unavailable, pvault says so.**
  - `duress set` refuses in bound mode.
  - `status` shows "Duress: unavailable on this TPM".
  - Documentation never promises bound duress unconditionally.
  - If a configured duress passphrase is entered while duress is unavailable, the unlock fails like any wrong passphrase and nothing is deleted.
- **Lockout disables duress (document):** an attacker who drives the TPM into lockout with wrong guesses also disables bound duress until the lockout clears.
- `status` reports whether owner authorization is set, the storage-hierarchy state and the lockout state.
- Duress-only deletion policies are not possible for owner-created indices.

### 9.4 Revoke (owner-triggered)
- **Bound:** full unlock → ownership verification (9.2b) → undefine the index → zeroize. Reliable. Recover with passphrase + card.
- **Portable:** full unlock → replace the **values** of `slot_nonce`, `slot_ct`, `duress_tag` (if present) and `slots_mac` with random bytes of identical lengths, keeping the exact CBOR structure and field set (atomic write) → zeroize. The header stays parseable; there is no explicit "revoked" marker, so a revoked slot is structurally identical to an active one and simply fails to unlock. Best effort on all storage (old slots may survive in flash cells, journals, snapshots, backups, still passphrase-locked). Recover with Card A + Card B; portable recovery reads no slots data and uses only `core_mac` (6.1).

### 9.5 Erase (owner only, typed confirmation `ERASE <folder basename> <vault ID prefix>`)

**Confirmation:** the vault directory's base name, followed by the first 8 hexadecimal digits of `vault_id` as shown by `status`.

**What Erase removes:** only files it can attribute to the vault through authenticated data:
- the objects listed in the authenticated key table (the list is read before the key table is overwritten);
- the current keytable file;
- the header;
- the journal.

It never deletes other files, never recurses into unrelated content, and never removes the containing directory. Lock files and unrelated files remain. The report lists what was removed and what was left.
- **Bound:** full unlock → Revoke → overwrite the slots section and the current keytable file with random bytes → optional flush step (9.9). Then report:
  > "The laptop chip's share is destroyed and this drive's passphrase share is overwritten. The erase is complete only if: (1) you destroy every backup card ever issued for this vault, (2) no one has ever extracted this laptop chip's share, and (3) no copy or backup of this vault exists from before now. Old overwritten data may remain on flash storage."
- **Portable:** full unlock → overwrite slots and the current keytable file → optional flush. Then report:
  > "The key slot is overwritten, but older passphrase-locked copies may survive on this drive or in any copy or backup, and your two cards can still rebuild the key. Software alone cannot complete this erase. To complete it: destroy at least one card from every card set ever issued, destroy this drive or run K2, and destroy any copies or backups of the vault."

### 9.6 Duress
```
bound:    duress_tag = HMAC-SHA-512(duress_key, "pvault/v1/duress-tag" || vault_id || "bound"
                         || u32_be(tpm_nv_index) || tpm_nv_name || tpm_policy_nonce)
portable: duress_tag = HMAC-SHA-512(duress_key, "pvault/v1/duress-tag" || vault_id || "portable")
```
1. After Argon2id and before any share is used, recompute the tag from the typed passphrase and the header's `core.vault_id`, mode and (bound) slots TPM fields. Constant-time compare.
2. On a match, those fields are authenticated by the duress key.
3. Bound: only if bound duress is available (9.3), run ownership verification (9.2b) with those fields, and undefine only if it passes. Portable: overwrite the slots section as in 9.4, only on a file system that passes 8.5.
4. Return `Unlock failed.` in all cases.
- **Presence leak (document):** the optional `duress_tag` is visible in the header, so anyone who can read the vault can tell that duress is configured. v1 keeps the optional tag (SI-26).
- **Same-TPM check on the duress path: approved for Milestone 3 (SI-36).** The bound formula appends the live EK digest: `duress_tag = HMAC-SHA-512(duress_key, "pvault/v1/duress-tag" || vault_id || "bound" || u32_be(tpm_nv_index) || tpm_nv_name || tpm_policy_nonce || ek_digest)`. The portable formula is unchanged. The duress path has no bundle, so the same-TPM requirement of 9.2b needs its own authenticated check. The proposal binds a digest of the TPM's identity into the bound `duress_tag`. A tag match then authenticates the passphrase, the slots' TPM fields and the TPM itself together, and no TPM identifier is stored in plaintext. Until it is approved, bound duress deletion is not implemented, which is consistent with the Milestone 8 gate.
- Duress fires **Revoke only**, never Erase, never the flush step.
- The duress tag is a second Argon2id-gated verifier (5.4).

### 9.7 Rollback detection
`generation` increments on every commit (Section 3). A local record `rollback.cbor`, a deterministic-CBOR (4.4) map from `vault_id` to the highest generation seen, lives in the platform config directory. It is updated with the same locking and atomic-update discipline as `partials.cbor`. Lower generation → warning, not a block. Only ordinary unlocks and commits update it; verification-only paths never do.

**Limits (document):**
- Revoke and duress writes do not change `generation`, so restoring a pre-Revoke header is **not** detected.
- A copy opened on a machine without a record is not checked.
- The record is local and unauthenticated: anyone with write access to the owner's config directory can edit it.

### 9.8 What each operation can honestly claim

| Operation | Bound | Portable |
| --- | --- | --- |
| Revoke | Daily path removed (reliable); recoverable | Slots overwritten (best effort); recoverable |
| Erase | Complete only under the three conditions in 9.5 | Never complete in software |
| K2 | Section 9.10 | Section 9.10 |

No output may call Revoke "erasure", and no file-level operation may be called "reliable".

### 9.9 Flush step (owner Erase only)
Estimate time and confirm → write random data to `pvault-flush.tmp` until ENOSPC → fsync → delete → fsync directory → TRIM only without privilege escalation. Shows progress, can be cancelled, never runs during duress, never on the system drive without `--allow-system-drive`. Always described as best effort. On current platforms TRIM is normally unavailable without privileges, so it is usually skipped, and the report says so.

### 9.10 K2 (whole device)
Runs only on a device the owner names explicitly; refuses the system drive and mounted devices.

| Drive type | Method | Message |
| --- | --- | --- |
| NVMe SSD | `nvme sanitize` Block Erase, check sanitize log | "Erased by the drive's firmware." |
| SATA SSD | ATA Secure Erase / Sanitize via `hdparm` | "Erased by the drive's firmware." |
| HDD | Full random overwrite + sample verification | "Fully overwritten." |
| Pendrive / SD | Full random overwrite + sample verification | "Overwritten. Physically destroy it to be certain no fragments remain." |

Flow:
1. Owner names the device; destruct code + typed confirmation.
2. With the device's filesystem still mounted, enumerate the vaults on it and authenticate each with `authenticate_verify_only()` (5.5): no duress action, no writes. Locks are released afterwards.
3. 60-second countdown with cancel. **Nothing is modified before the countdown completes.** Cancelling leaves every vault and the device untouched.
4. Erase each vault (file-level, exclusive lock per vault) while the filesystem is still mounted.
5. Unmount the device's filesystems. If unmounting fails, stop and report exactly: "The vaults on this device were erased, but the device wipe was not performed because the device could not be unmounted."
6. Run the device-level method above on the now-unmounted device. The "refuses mounted devices" rule applies to this step only.

Mounted vault sessions on the device must be closed before step 1; K2 refuses to start otherwise. `--dry-run` supported. Loopback devices and images only during development.

**Constraints (v7):**
- pvault never escalates privileges itself.
- No privileged helper and no override for vaults that cannot be authenticated in step 2 may be added without an explicit design review.
- **PENDING (SI-44)**, decided at the Milestone 8 review:
  - platform support;
  - the privilege boundary;
  - mock versus loopback versus hardware test coverage;
  - exact partial-failure reporting;
  - behavior for vaults that cannot be authenticated.

---

## 10. Secrets hygiene (mandatory)
1. Secrets in `secrecy::SecretBox` or `Zeroize + ZeroizeOnDrop` types; `Debug` prints `[REDACTED]`; no `Display`/`Serialize`.
   **Single exception: key-table serialization.** The key table must contain file keys. `keytable.rs` implements one crate-private function that encodes the entry list as deterministic CBOR (4.4) **directly into a pre-allocated, `mlock`ed, zeroize-on-drop buffer**, which is then passed straight to the chunk encryptor and zeroized. Decryption does the reverse into the same kind of buffer. File-key types expose their bytes only through a crate-private accessor used by this function. No general `Serialize` impl exists for any secret type, and no other module may call the accessor. The decoder's scratch buffers, allocations and failure paths are approved for Milestone 3 (SI-07, D3): two-pass decode, exact-capacity arenas, no growable buffer for secrets.
2. **Memory locking: best effort, and visible.**
   - Lock the pages that hold key material (bundle, shares, file keys, passphrase buffers) and the key-table buffer.
   - Platform limits mean locking can fail: Linux `RLIMIT_MEMLOCK` (often 8 MiB), the Windows working-set minimum (raised as needed), and macOS limits. On failure, warn once per process; `status` shows the protection state.
   - An optional **strict mode** (`--strict-memory`, also a config setting) refuses to proceed when any required lock fails.
   - **Argon2id working memory** (256 MiB to 4 GiB) is not locked:
     - It is allocated only after the 4.3 checks, used once, zeroized before release. pvault allocates the block buffer itself, fallibly, and wipes it on every exit path: the `argon2` crate's own allocation is freed without being wiped, even with its `zeroize` feature on, and then freed.
     - It holds passphrase-derived blocks from which the Argon2 output can be computed. If the OS swaps it out, those blocks can reach disk, so documentation recommends encrypted swap (FAILURE_MODES).
     - Strict mode does not cover Argon2 memory, and says so.
3. **Disable core dumps at startup**, where the platform allows:
   - **Linux and macOS:** set `RLIMIT_CORE` to 0, both soft and hard.
   - **Linux additionally:** `PR_SET_DUMPABLE = 0`. This also blocks debugger attachment by the same user; document the impact on development.
   - **Windows: best effort only** (`SetErrorMode`, and `WerSetFlags` with no heap). A system `LocalDumps` policy, an attached debugger, or a kernel or full memory dump can still capture memory.

   pvault never modifies persistent registry entries or system policy. Optional detection of a `LocalDumps` policy may warn, but must never imply that dumps are otherwise prevented. `status` reports the protection level.
4. `subtle` for all secret-dependent comparisons.
5. Zeroize on every exit path, including errors and panics (guard types).
   - Passphrase Unicode normalization (7.3) runs in one fixed-capacity, pvault-owned buffer that is wiped on drop. The iterators of `unicode-normalization` are not used for secrets, because runs of four or more combining marks make them spill to heap blocks that are freed unwiped.
6. No secrets in errors, logs, panics, env vars, or desktop-app IPC beyond the single passphrase hand-off.
   - Secrets are never accepted from command-line arguments or environment variables.
   - Non-interactive input requires an explicit flag, `--secrets-stdin`. Secrets are then read from standard input, one per line, in prompt order.
   - Without the flag, a secret prompt on a non-terminal standard input is refused.
7. No plaintext anywhere except the requested destination (7.9).

---

## 11. Failure scenarios (each needs an automated test)

`tests/failure_scenarios.rs`, owned by the non-published workspace member `crates/pvault-tests` (Section 12). TPM tests use `swtpm`; device tests use images.

- **Crash injection** uses named failpoints compiled only under the non-default Cargo feature `fault-injection`. The test harness runs the CLI in a child process that aborts at a chosen failpoint. Release builds must not be able to enable the feature: the release profile or build script rejects it, and CI checks that release artifacts contain no failpoint names (F85).
- **Scope of crash tests:** they demonstrate process-crash safety only (8.5).

**Core and formats**

| # | Scenario | Expected |
| --- | --- | --- |
| F1 | Bound vault copy only | Cannot decrypt |
| F2 | Bound: wrong passphrase, correct TPM | `Unlock failed.`; TPM DA counter increments |
| F3 | Bound: right passphrase, TPM index missing | `Unlock failed.` (no passphrase-only path) |
| F4 | One card only (either mode) | Cannot decrypt |
| F5 | One share fed to combine | ≠ bundle |
| F6 | Shares from two different splits | Do not combine |
| F7 | Flip any byte in core or `core_mac` | Unlock and recovery both fail. The message is `Unlock failed.`, except for one case: a flipped Argon2 parameter that stays within the hard caps but exceeds this machine's policy or resource limit gives the 4.3 / 5.8 specific message. That message depends only on public header values. No message ever depends on a secret |
| F8 | Flip a byte inside a slots **field value**, or in `slots_mac`, so the header still parses | Daily unlock fails; recovery still succeeds (bound: only if `s1_*` untouched). Structural corruption that stops the header parsing may prevent recovery; this is documented (6.1), not tested as success |
| F9 | Chunk byte flipped | Stream fails; `.pvpartial` deleted; destination not created |
| F10 | Chunks reordered, truncated, duplicated, or swapped between streams | Rejected |
| F11 | Trailing bytes; `rec_len` off by one in either direction; `is_last` on a middle chunk; `plain_size` inconsistent with records; `version` changed | Rejected (a changed `version` fails authentication, 7.7) |
| F12 | Keytable file replaced with an older or foreign one | Digest mismatch → rejected |
| F13 | Argon2 params out of caps (e.g. `m` = 1 TiB) | Rejected before allocation |
| F14 | Oversized or non-canonical header | Rejected without large allocation |
| F15 | Portable: copy folder elsewhere, unlock | Works |
| F16 | Portable: wrong passphrase | `Unlock failed.` |
| F17 | A header whose `mode` disagrees with the requested operation, or with a card's `mode` (e.g. portable unlock or portable cards on a bound vault) | Refused |
| F18 | Rollback to an older vault copy | Warning |
| F19 | TPM in lockout | Clear message, no crash |
| F20 | Per-file `rm` | Entry gone; object undecryptable with current state |

**Recovery and crash safety**

| # | Scenario | Expected |
| --- | --- | --- |
| F21 | Bound recovery (passphrase + card) with TPM index missing | Succeeds; new index; bundle rotated |
| F22 | Portable recovery (A + B) after portable Revoke | Succeeds using `core_mac` only; new passphrase works; old passphrase fails |
| F23 | Old card after a completed recovery | Cannot open the new vault |
| F24 | New card verification fails in phase 2 | Nothing old modified; old material still works |
| F25 | Crash injection after every step of recovery (a to q), including every journal phase and the post-header directory flush | Vault opens with an authenticated core matching exactly `old_core_digest`, `new_core_digest` or `tracking_core_digest`; generation alone never selects a side. Rollback tracking recomputes both `core_mac` and `slots_mac` after authenticating old slots. A post-replacement flush failure retains the journal and both dependency sets. **No index created by this operation** is untracked; a remote index stays in an authenticated journal/core record until its original TPM resolves it. If old slots do not authenticate, rollback tracking is refused and the journal blocks. |
| F26 | Crash injection after every step of `init`, `add`, `rm`, `convert`, including file creation before identity journaling, completed key-table rename before `keytable_written`, header replacement and post-replacement flush | Authenticated matching file identities are cleaned safely, including a completed key table still recorded as `keytable_created`. Unowned or changed tmp/final files require the exact confirmation and snapshot recheck or leave init blocked. No file is deleted by name alone; remote bound init stays blocked with its journal/artifacts. A committed header is preserved and its journal resolved only after exact digest/MAC verification and the repeated flush. Transition target, tracking and header temps are removed only through journaled identities; the old key table only on a digest match. |
| F27 | Journal edited to name another TPM index | MAC fails → nothing deleted |
| F28 | Valid journal, but index at handle has a different Name | Nothing deleted |
| F29a | Index re-created with the same handle and attributes but a different policy nonce | Name differs → nothing deleted |
| F29b | Index deleted and re-created with an identical definition (same policy nonce) | Decoy may be deleted; real data unaffected; behavior documented |
| F30 | TPM Name captured before vs after first write | Only the post-write Name is stored and matches |
| F31 | `fsck` without unlock | Reports only; deletes nothing |
| F32 | `convert` without confirmation or card verification | Refused |
| F33 | `get` interrupted mid-file | The partial is recorded; the next `get` or `fsck` lists it and removes it **after owner confirmation**; declining leaves it in place; a path that was replaced (symlink or different inode) is never deleted |
| F44 | Crash immediately after the header commit (m), before any further step | Unlock with NEW material works; `fsck` verifies `mac_new` and finishes n to p |
| F45 | Crash after "committing" record (l), before header commit (m) | Unlock with OLD material works; `fsck` verifies `mac_old` and rolls back |
| F46 | Recovery of a vault with duress: each of the three choices (6.7) | Re-entered and new duress passphrases are **recognized** by the new slots' tag (trigger action stubbed until Milestone 9); "disable" removes the tag and `status` shows "Duress: off"; no stale tag is ever written |
| F47 | Card verification with only part of the Base32 text, one wrong character, or a truncated QR | Rejected; full-share match required |
| F48 | Portable Revoke | Header still parses; slots structure unchanged; unlock fails; A + B recover |
| F49 | K2 cancelled at any second of the countdown | Nothing on the device or in any vault modified |
| F50 | `.pvpartial` pre-exists; destination is a symlink; parent directory is a symlink | Refused; nothing written |
| F51 | `.pvpartial` and final file permissions | Owner-only |
| F52 | Bound unlock where the index at the handle has a different Name, or a non-pvault public area (wrong attributes, size or `authPolicy`) | Generic failure; `NV_Read` never called; DA counter unchanged |
| F53 | An owner-range index present but not in any journal or verified slots | `fsck` reports it and never deletes it |
| F54 | Crash after defining the new TPM index, before writing S2' | Index has its pre-write Name; `fsck` (old unlock) accepts the journaled `new_name_prewrite`, deletes it, rolls back |
| F55 | Recovery where the old `slots_mac` fails (tampered TPM fields) | Recovery succeeds; old index never deleted and is reported; old duress tag treated as unavailable |
| F61 | Card payload: wrong magic, version, length, `check`, foreign `vault_id`, old `set_id`; Base32 with `I`/`L`/`O` substitutions | Invalid ones rejected; old set reported as "an old card"; substitutions decoded correctly |
| F62 | Shamir test vectors (0x11B field) from `docs/FORMAT.md` | Exact match |
| F63 | Duress passphrase on verification paths: Path A (K2 preflight, post-commit `init`, both modes) and bound Path B (recovery, `verify-card`). Plus portable Path B (two cards, no passphrase input) | Duress passphrase: generic failure, nothing modified, TPM index and slots unchanged. Portable Path B: card validation (7.4a) enforced; no duress check or action occurs at any point |
| F64 | Add two different vault paths with identical content; replace a path with `--replace`; add an existing path without `--replace` | Each write has a distinct `file_id` and distinct `fk_aes`/`fk_chacha`; the old object and entry are gone after a replace; adding an existing path without `--replace` is refused |
| F65 | Card combine inputs: duplicate x-coordinates, mismatched `set_id`, mismatched `vault_id`, invalid `mode` or `share_x`, a bound card with x ≠ 3, portable cards that are not one x=1 and one x=2 | Rejected before any combination is attempted |
| F66 | Verification-only paths: recovery and `verify-card` with the TPM index missing; any path run on a vault with an older generation than recorded | Path B succeeds without the TPM; the rollback warning is shown but the local generation record is never updated by a verification-only path |
| F67 | Crash at each step of `.pvpartial` creation (before identity recorded, after recorded, mid-write) | Before recording: at most an empty untracked file, removable only if regular and size 0 after confirmation; after recording: tracked and handled per F33; concurrent `get`s never corrupt `partials.cbor` |
| F68 | Delivery verification of new cards during recovery and during `convert` (bound to portable and back) | Cards match the in-memory expected payload, including the new mode; the same cards fail to authenticate the vault before the commit |
| F69 | Re-run `init` with each canonical init phase plus a complete successor, incomplete, divergent and skipped-phase `vault.journal.tmp`; repeat with a committed header, recovery/convert journal, malformed journal, foreign `vault_id`, wrong `setup_id`, symlink/special residue and moved/unverifiable file identities | Only an independently authenticated same/successor init-journal temp is promoted. A committed init journal is removed only after exact header digest and core/slots/journal MAC verification plus repeated flush (a header-identity mismatch is reported only). Unauthenticated/mismatched cases delete nothing and remain blocked or direct to `fsck`; owner-confirmed cleanup is limited to the four regular-file candidates and requires snapshot identity/length recheck. |
| F70 | `pvault clean-partials` (and the cleanup component called directly) while a large `get` export is in progress; then after that export's process is killed | While running: the active entry is skipped (not listed, offered or deleted). After the kill: its transfer lock is free, so the entry is offered as stale and removed only after confirmation |
| F71 | Init journal with Argon2 parameters outside the caps; oversized (> 16 KiB) or non-canonical journal | Rejected before any derivation or allocation; reported; nothing deleted |
| F72 | A second `get`, and `fsck`, started while a `get` export holds the vault's shared lock | Both refused with "The vault is in use by another pvault process"; the running export and its partial are unaffected |
| F56a | Two concurrent mutating processes; a crashed process holding the lock | Second process refused; lock released automatically after the crash |
| F56b | CLI `list`/`get`/mutation while the vault is mounted; `status` while mounted | Unlocking commands refused with the mounted message; `status` works |
| F57 | Re-entered duress passphrase: correct; wrong; old tag unavailable | Correct one accepted; wrong one rejected; when unavailable, only "generate new" or "disable" offered |
| F58 | Header generation changed by another writer between operation start and the generation check | The temp may already have been written, but `vault.hdr` is not replaced. Retain journal and temps and report "The vault changed during this operation. The header was not committed." (the test does not claim protection for changes after the check) |
| F59 | `init` interrupted after the header write, before the journal is deleted; then `init` re-run (including once with the duress passphrase) | Header detected; Path A verification required; journal deleted; live TPM index preserved and the vault opens. With the duress passphrase: generic failure, nothing modified |
| F60 | `init` interrupted before the header write; then `init` re-run with and without the passphrase | With: journaled index removed after 9.2b, setup restarts. Without: index left untouched and reported |

**Added in v7**

| # | Scenario | Expected |
| --- | --- | --- |
| F73 | Vault paths. **Input** (`add`, `--replace`, conversion): traversal (`..`), absolute paths, empty components, control characters, Windows-reserved names and characters, components or paths over the length limits, NFC and case-fold collisions, file/directory clashes. **Decode** (an authenticated key table): the same violations **except** NFC form and case-fold collisions, plus unsorted or duplicate entries and missing parent `dir` entries | Every input violation is rejected on input. A decoded key table containing any decode-checked violation fails with `KeyTableCorrupt`. NFC and case-fold collisions are **not** checked at decode, so a later Unicode table cannot make an existing vault unreadable. This split is approved for Milestone 3 (SI-07, D7); Milestone 3 tests the decode part and Milestone 4 the input part |
| F74 | Mutating commands on an unsupported file system (FAT/exFAT image, or a mocked file-system type) | Refused with the 8.5 message; nothing written; read-only commands work; a portable duress match modifies nothing |
| F75 | Normalization: mixed whitespace, case, NFKC forms, hyphenated words; a word outside the list | Normalized as 7.3. The unknown word gives the hint, with no Argon2id run and no TPM command that carries authorization or can change the DA state (DA counter unchanged). Unauthenticated public queries (`GetCapability`, `NV_ReadPublic`) may already have run, for example for the lockout message of 5.8 |
| F76 | Argon2 `m` within the hard caps but above 50% of total RAM; above available memory (mocked) | Specific policy or resource message; stored parameters never altered; no allocation |
| F77 | Memory locking fails (child process with `RLIMIT_MEMLOCK` = 0) | Default: one warning and the operation continues; strict mode: refused; `status` reports the state |
| F78 | Card files: destination inside the vault; pre-existing file; symlinked destination; file replaced between creation and cleanup; cleaner run while the writing operation is still active, and again after that process is killed | Refused or never deleted as 7.4b requires; files are owner-only; only recorded files with matching identity are deleted; entries of an active operation are skipped entirely (lifetime lock, **PENDING SI-10**) |
| F79 | Secret input: non-TTY stdin without `--secrets-stdin`; with it; attempts to pass secrets in argv or environment | Refused; accepted; no such argument or variable exists |
| F80 | `recover --to-portable` with no TPM available | Succeeds; new passphrase and cards work; old index untouched and reported (under the proposed SI-35/SI-36 design, tracked in the new core's `tpm_cleanup` when the old slots authenticated) |
| F81 | Bound duress availability: owner authorization set; storage hierarchy disabled; TPM in lockout (swtpm) | `duress set` refused and `status` shows "unavailable"; a configured duress passphrase deletes nothing |
| F82 | `convert` both directions with duress configured | The new tag is valid for the target mode; the old index is retired only under 9.2b; old cards fail after commit |
| F83 | Old index re-created with an identical definition on a different TPM (second swtpm instance) | Never deleted (9.2b same-TPM rule); reported. Depends on the SI-36 mechanism |
| F84 | Erase confirmation with a wrong basename or ID prefix; unrelated files in the vault directory | Refused; Erase removes only authenticated vault files and never the directory |
| F85 | Release build with the `fault-injection` feature requested; inspect release artifacts | Build refused; no failpoint names present |
| F91 (proposed, N2) | Bound `init`, bound recovery and `convert` to bound on a swtpm whose endorsement hierarchy is disabled, whose endorsement authorization is set, or that cannot create the H-2 EK | Refused before any journal, index or file; portable mode or `recover --to-portable` offered; vault directory and TPM unchanged |
| F92 (proposed, N5) | `add` that would make the key table exceed 65,536 entries: a single file at the limit; a nested path whose new parent directories cross it; exactly 65,536 reached | Over-limit attempts are refused before any write; the vault directory is byte-for-byte unchanged, the generation is unchanged, and no temp or journal exists. Reaching exactly 65,536 succeeds. A decoded table with 65,537 entries is `KeyTableCorrupt` |

**Destructive features (built after the review gate)**

| # | Scenario | Expected |
| --- | --- | --- |
| F34 | Bound owner Revoke | Index gone (after 9.2b); passphrase + card recovers |
| F35 | Portable owner Revoke | Slots overwritten; A + B recover |
| F36 | Bound duress | `Unlock failed.`; index gone; passphrase + card recovers |
| F37 | Portable duress | `Unlock failed.`; slots overwritten; A + B recover |
| F38 | Bound duress with header TPM fields altered | Tag mismatch → nothing deleted |
| F39 | Duress never triggers Erase or flush | Verified by instrumentation; timing within measured bound |
| F40 | Bound Erase | Live vault unopenable even with passphrase + card; report text exact |
| F41 | Portable Erase | Report text exact; never claims completion |
| F42 | Flush on a small image | Fills to ENOSPC, deletes fill file |
| F43 | K2 method selection on mocked devices of each type; overwrite and sample verification on loopback images | Correct method chosen; refuses system/mounted devices; dry-run accurate; firmware commands are never executed in tests (coverage split **PENDING SI-44**) |

Plus round-trip known-answer tests for the chunk format with fixed keys/nonces via `#[cfg(test)]` constructors.

---

## 12. Repository layout (Cargo workspace)

```
pvault/
  Cargo.toml, Cargo.lock, README.md, SECURITY.md
  docs/ THREAT_MODEL.md  FORMAT.md  FAILURE_MODES.md  DESIGN.md  MODES.md  ASSUMPTIONS.md
  assets/eff_large_wordlist.txt
  crates/
    pvault-core/src/
      lib.rs  secrets.rs  errors.rs
      crypto/{cascade,kdf,wrap,mac,random}.rs
      shamir.rs  passphrase.rs
      header.rs   (core + slots, two MACs, caps)
      stream.rs   (chunked format 7.7, shared by objects and key table)
      keytable.rs  journal.rs  rollback.rs
      vault.rs    (init, unlock, add, list, get, rm)
      recovery.rs (Section 6)
      convert.rs
      mode_bound.rs  mode_portable.rs
      tpm.rs      (TpmBackend trait: Swtpm, Device, Mock; ownership verification 9.2b)
      card.rs     (7.4a to 7.4c)
      lock.rs     (8.4)   partials.rs (7.9, 7.4b records)   paths.rs (7.8 vault paths)
      platform/   (all FFI: process hardening, file-system operations, memory, locking; 7.6a)
      destructive/ (revoke.rs, erase.rs, duress.rs, flush.rs, k2.rs; empty until Milestone 9)
    pvault-core/benches/   (Criterion benchmarks)
    pvault-cli/
    pvault-tests/ (publish = false; cross-crate scenario tests; its [[test]] entries point
                   at the top-level tests/ files)
    pvault-app/   (Tauri; kept out of default-members until Milestone 14)
  tests/failure_scenarios.rs
  fuzz/          (cargo-fuzz; excluded from the workspace; nightly toolchain)
    fuzz_targets/{header_parse,stream_parse,card_parse,journal_parse,keytable_parse}.rs
  .github/workflows/ci.yml   (Linux, Windows, macOS; swtpm on Linux; fuzz smoke job on Linux)
```

- **Toolchains:** stable for the product, nightly only for `fuzz/`.
- **MSRV:** `rust-version = "1.89"` (SI-05, approved). Native Rust 1.89 build-and-test CI jobs on Linux, Windows and macOS must pass before a milestone is accepted. The release toolchain is pinned exactly by Milestone 13.

---

## 13. Milestones (build everything, release once at the end)

Each milestone ends with `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, and a summary to the human. From Milestone 1 on, the native Rust 1.89 CI jobs (Linux, Windows, macOS) and `cargo-deny` are also on this list. `cargo-deny` findings are reviewed, never silently suppressed. An item marked **PENDING** in this spec must be resolved before the milestone that first needs it starts.

| # | Milestone | Accept when |
| --- | --- | --- |
| 0 | Setup: workspace, CI on 3 OSes, `secrets.rs`, core-dump disabling | CI green; secrets redact `Debug` |
| 0.5 | **Spec consistency pass.** Read the whole spec only to find contradictions, ambiguities and undefined behavior. Write `docs/SPEC_ISSUES.md` (section, problem, proposed resolution). Write no product code | (1) Every listed issue has a recorded status, resolution or proposal, and the milestone it blocks, in `docs/SPEC_ISSUES.md`. (2) The human has resolved every issue that blocks Milestone 1. (3) Every other issue stays **PENDING**, and is resolved before the milestone it blocks starts (see the rule at the top of this section). Milestone 0.5 does **not** require every issue to be resolved |
| 1 | Core crypto: random, kdf (5.1 parameters and known-answer vectors), mac, cascade | Round trips (0 B, 1 B, 64 KiB, 64 KiB+1, 10 MiB); KDF vectors; benches run |
| 2 | Shamir (0x11B field, published test vectors; implementation per SI-08), passphrases (7.3: generation, H_w and word-list check, H_c, collision rule), bounded secret input (7.6a), the custom-passphrase estimator child process (SI-51), wraps. No header or journal schema changes | F5, F6, F62; wordlist = 7,776; normalization tests (F75 normalization part); SI-51 section 9 tests that need no vault |
| 3 | Formats: deterministic CBOR (4.4), header (core/slots, two MACs, caps and limits), chunked stream (version in AAD), key-table file with vault paths (7.8), journal schemas (8.1), locking (8.4 per SI-14), file-system support check (8.5), test-only failpoints | F7, F9 to F14, F56a, F58, F71, F73 (decode part), F74 (detection part), F76, F85 |
| 4 | Cards (7.4a to 7.4c: payload, Base32, SVG QR, PNG input, card files, published vectors). Portable mode: init (with full card verification), add, list, get, rm with crash-safe ordering and secure `.pvpartial`; `docs/CLI.md` approved first | F15, F16, F20, F26 (init/add/rm), F33, F4 (portable), F50, F51, F61 (portable cards), F64, F65 (portable cards), F67, F70, F72, F73, F74, F75, F78, F79 |
| 5 | Bound mode via swtpm: policy-nonce index, precomputed and post-write Name, read rules (9.2a), ownership verification (9.2b), sessions (SI-22), duress setup (6.10) and availability (9.3) | F1 to F3, F17, F19, F30, F52, F59, F60, F61 and F65 (bound cards), F81 |
| 6 | Recovery (both modes, and directly to portable), bundle rotation, write-ahead journal, dual-MAC transition records, full-share card verification, duress choices, `fsck`, `convert` | F8, F18, F21 to F29b, F31, F32, F26 (convert), F44 to F47, F53 to F55, F57, F63 (verify-card and recovery parts), F66, F68, F69, F80, F82, F83 |
| 7 | Hardening: fuzz all targets 10+ min, memory locking with strict mode, timing measurements, draft docs, `cargo audit` | All tests that do not need mounting or gated features are green in CI (F1 to F33, F44 to F47, F50 to F55, F56a, F57 to F62, F63 except K2, F64 to F83, F85). F48 and F49 are gated (Milestones 9 and 10); F84 is gated (Milestone 9); F56b needs mounting (Milestone 11) |
| **8** | **REVIEW GATE** for the `destructive/` features only. Agent stops. Human (and/or a second AI) reviews Sections 4, 6, 8, 9 and the code from Milestones 3 to 7. Agent writes `docs/REVIEW_8.md` listing every existing code path that deletes or overwrites anything (with the check that protects it) and the planned design of each gated feature, then waits for explicit approval | Human approval recorded |
| 9 | Destructive features: owner Revoke, duress trigger, Erase, flush (under `destructive/`) | F34 to F42, F48, F84 |
| 10 | K2 per drive type (images and mocks only; design per SI-44) | F43, F49, F63 (K2 preflight part) |
| 11 | Mount as a drive (fuser / WinFsp / macFUSE or FUSE-T), auto-lock on sleep, lid close, idle. Starts only after the SI-45 design review (writes of unknown size and random writes under the 7.7 AAD, crate choices, CI feasibility) | Mount tests on all 3 OSes; F56b |
| 12 | Metadata hiding: optional fixed-size container mode | Container round trips; sizes hidden |
| 13 | Signed releases: reproducible builds, hybrid ML-DSA + Ed25519 signatures, `pvault self-verify` | Verification tests |
| 14 | Desktop app (Tauri): wizard (location, mode explained, passphrase practice, cards, card test), unlock + mount, drag and drop, settings (Recover, Duress, Convert, Revoke, Erase, K2, Status) | UI tests; keys never cross into the UI layer; strict CSP; no remote content |
| 15 | PQC card export: hybrid ML-KEM-1024 + X25519, combined with HKDF-SHA-512 | Round trip + tamper tests |
| 16 | Formal model (Tamarin or ProVerif) of unlock, recovery, Revoke, Erase, duress, both modes | Model + written results |
| 17 | Investigate bound mode on Windows (TPM via TBS) and macOS (Secure Enclave); report before building | Feasibility report |
| 18 | Release checklist: all tests green on 3 OSes, docs complete, `ASSUMPTIONS.md` matches Section 2, external review invited, signed release published | Human sign-off |

**Status (2026-10-04):** Milestone 0 accepted. Milestone 0.5 closed. **Milestone 1 accepted** (commit `bd04bb4`; CI run 37254330640, every job green, including the native Rust 1.89 jobs on Linux, Windows and macOS, and `cargo-deny`). **Milestone 2 accepted** (commit `a099bb6`; CI run 37261091478, every job green). Its recorded limitations are in `docs/SPEC_ISSUES.md` 10.4 to 10.8: the estimator's accepted platform limits (Windows Job Object limits deferred), Windows console input that only compiles (interactive validation outstanding), and the normalization-version policy that blocks the Milestone 3 schema review. **Milestone 3 implemented locally (2026-10-05)** under the v7.5 approvals: local checks pass on macOS (stable and Rust 1.89), with cross-target lint for Linux and Windows. The native CI jobs (Linux, Windows including the locality probe, macOS, Rust 1.89, `cargo-deny`, fuzz smoke, release checks, Unicode regeneration) are outstanding until an authorized push. Findings: `docs/SPEC_ISSUES.md` 10.11.

---

## 14. Documentation to produce
- **README.md:** what it is and is not; both modes in plain language; the conditional guarantees table; credits; and: *"In bound mode, no single stolen item exposes your data, but forgetting your passphrase is unrecoverable. Portable mode trades theft resistance for working anywhere, and its two cards can recover a forgotten passphrase. Here is exactly when each can fail."*
- **docs/ASSUMPTIONS.md:** A1 to A6, verbatim from Section 2.
- **docs/MODES.md**, **docs/FORMAT.md** (byte-level), **docs/DESIGN.md**, **docs/THREAT_MODEL.md**.
- **docs/FAILURE_MODES.md:** passphrase observed; malware while open; tampering before unlock; memory attacks; TPM weaknesses and empty owner auth; non-`pvault` software writing into a vault folder (locking is cooperative); coercion; data leaking outside the vault; flash, journal, snapshot and backup remnants; portable clones; old card sets; extracted TPM shares; the duress tag as a verifier; duress hides only in the moment (later forensic inspection can show a missing TPM index or changed slots); implementation bugs; losing access; assumption failures.
- **SECURITY.md:** reporting process; not independently audited.
- **docs/CLI.md** (before Milestone 4): commands, arguments, confirmations, exit codes, and `--secrets-stdin`.
- **docs/SPEC_ISSUES.md:** the decision record for spec changes.
- **docs/FORMAT.md:** byte-level formats and the published known-answer vectors, with their provenance (`tools/vectors/`).
- **THIRD_PARTY_NOTICES.md:** third-party material in the repository (vendored test vectors and, from Milestone 2, the wordlist).
- **Third-party notices:** wordlist credit from Milestone 2. The dependency-notice tooling is **PENDING (SI-04)**.
- **Additions to docs/FAILURE_MODES.md (v7):**
  - Windows core-dump limits, and the Linux debugger impact (10.3);
  - Argon2 memory and swap (10.2);
  - read-only file systems, and the limits of crash safety (8.5);
  - Windows power loss or OS crash during a commit can leave a vault unreadable; the ordering assumptions WO-1 to WO-3 and W1 are unverified (8.5, decision N1);
  - rollback-detection limits (9.7);
  - visibility of the duress tag (9.6);
  - bound duress unavailability and lockout (9.3);
  - remote old TPM indices (6.8);
  - object keys not rotated by recovery (6.11);
  - card-file and terminal remnants (7.4b);
  - header corruption limits and backup guidance (6.1);
  - metadata in `partials.cbor` and `cards.cbor` (7.9).

---

## 15. Things the agent must NOT do
- Claim "unbreakable", "military-grade", "512-bit", or unconditional 50-year/quantum guarantees.
- Use ECB, unauthenticated encryption for file data, MD5, SHA-1, or non-OS RNGs for secrets.
- Reuse a nonce with the same key.
- Store the passphrase, any Argon2 output, or any card share on disk (beyond one-time card files deleted after verification).
- Give a bound vault a passphrase-only unlock path.
- Print different messages for different unlock failures.
- Allocate Argon2 memory before validating caps.
- Delete or undefine anything based on an unauthenticated source, or without ownership verification (9.2b).
- Retire old recovery material before new material is verified (Section 6).
- Skip `core_mac` verification in any path, including recovery.
- Call Revoke "erasure"; call any file-level operation "reliable"; let duress trigger Erase or flush.
- Write any `destructive/` feature (owner Revoke, duress, Erase, flush, K2) before the Milestone 8 approval.
- Use provisional (unverified) header data to authorize any deletion.
- Define a TPM index before its journal record exists.
- Carry a stale duress tag into new slots, or accept a re-entered duress passphrase without checking it against the old authenticated tag.
- Journal or delete an old TPM index whose slots were not authenticated by the old `slots_mac`.
- Mutate a vault without holding its exclusive lock, or commit without the generation check; or describe the generation check as protection against non-cooperating writers.
- Delete a TPM index during `init` recovery when a header exists.
- Accept a card as verified on a checksum alone, or combine shares without the field and set checks in 7.4a.
- Run the duress check in verification-only authentication (5.5), let any verification-only path write to the vault or create/delete TPM indices, or let it update the local rollback record.
- Reuse or derive a `file_id`, `fk_aes` or `fk_chacha`.
- Modify anything during the K2 countdown.
- Run any destructive operation on real hardware during development, or access a real TPM without the owner's explicit authorization.
- Add network code (except the Milestone 14 optional signed update check, off by default).
- Accept secrets from command-line arguments or environment variables.
- Substitute a check-then-act fallback for a required no-follow or no-overwrite primitive; refuse instead (7.6a).
- Delete any file because of its name or a pattern alone, rather than authenticated ownership.
- Claim crash safety on file systems that fail 8.5, or claim that process-crash tests prove power-loss safety.
- Lower or substitute stored Argon2 parameters to make an unlock fit.
- Set or change TPM owner authorization; promise bound duress when 9.3 says it is unavailable.
- Delete a TPM index without establishing that it is on the same TPM that created it (9.2b).
- Let the `fault-injection` feature, or any failpoint, reach a release artifact.
- Add a privileged helper, a privilege escalation, or a K2 override for vaults that cannot be authenticated, without an explicit design review.
- Implement anything marked **PENDING** before it is resolved.

---

## 16. Open decisions for the human (agent: ask before the milestone each item names)
1. Project name: **decided, keep `pvault`** (v7).
2. Passphrase options: **decided; final design approved** (v7.4). Main passphrase: generated (10–16 words, default 12) or custom (user-written), in both modes. Duress: generated only, fixed at 12 words for now. The final design is in SI-51; its metadata, header and journal schemas are approved for Milestone 3 (2026-10-05).
3. Wizard default mode? *Recommendation awaiting confirmation:* bound as the default on Linux, and portable on platforms without bound support. **Needed before Milestone 14** (the desktop wizard is its only user); it does not block Milestone 3.
4. PCR (boot-tampering) policy in bound mode: **decided P1 for v1**. v1 uses
   nonce-policy only. PCR binding requires a future reviewed format revision;
   it is not added to the v1 format or Milestone 5 implementation.
5. License: **decided, `GPL-3.0-only`** (v7.3). Copyright 2026 Yash Sandeep Tamhane. The official GPL v3 text is in `LICENSE`, and the notice in `COPYRIGHT`. Third-party licenses and notices are kept (`THIRD_PARTY_NOTICES.md`). Notices tooling for release artifacts is still proposed separately (SI-04).
6. Every item marked **PENDING (SI-nn)** in this spec. See `docs/SPEC_ISSUES.md` for the evidence, designs and the milestone each one blocks.
