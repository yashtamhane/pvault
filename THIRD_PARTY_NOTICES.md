# Third-party notices

pvault's own code and documentation are Copyright 2026 Yash Sandeep Tamhane,
licensed under `GPL-3.0-only` (see `LICENSE` and `COPYRIGHT`). Third-party
material keeps its own license, as listed below; the project license does not
replace it.

This file lists third-party material kept in this repository. Rust dependency
licenses are checked by `cargo-deny` (`deny.toml`). Generating notices for
release artifacts is planned for Milestone 13.

## EFF's Long Wordlist

- **File:** `assets/eff_large_wordlist.txt` (also embedded, unchanged, in the
  pvault binary).
- **Title:** "EFF's Long Wordlist" (`eff_large_wordlist.txt`).
- **Author:** Electronic Frontier Foundation (Joseph Bonneau, 2016).
- **Source:** <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>,
  announced at
  <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>.
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0),
  <https://creativecommons.org/licenses/by/4.0/>.
- **Changes:** none. The file is byte-identical to EFF's (SHA-256
  `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, checked
  by a test), dice numbers included. It is distributed as separately licensed
  data and is not relicensed under the GPL.
- **Basis:** the file carries no license notice of its own. EFF's copyright
  policy (<https://www.eff.org/copyright>, as read on 2026-10-04) states that
  original material on the EFF website "may be freely distributed at will under
  the Creative Commons Attribution 4.0 International License (CC-BY), unless
  otherwise noted", and nothing else is noted for this file.
- **Remaining uncertainty:** no verified statement from the FSF or Creative
  Commons on combining CC BY 4.0 material with a GPLv3 program was found (the
  terms themselves do not conflict; see SI-04 in `docs/SPEC_ISSUES.md`). EFF's
  2016 site license, possibly CC BY 3.0 US, could not be verified.

## Project Wycheproof test vectors

- **Files:**
  - `crates/pvault-core/testdata/wycheproof_hkdf_sha512.txt`
  - `crates/pvault-core/testdata/wycheproof_hmac_sha512.txt`
  - `crates/pvault-core/testdata/wycheproof_aes256_gcm_siv.txt`
  - `crates/pvault-core/testdata/wycheproof_xchacha20_poly1305.txt`
- **Source:** Project Wycheproof, <https://github.com/C2SP/wycheproof>, commit
  `3fa63dd0344abb611f1fb1d77e119938603ea230`, files under `testvectors_v1/`.
- **License:** Apache License 2.0. A copy is in
  [`third_party/wycheproof/LICENSE`](third_party/wycheproof/LICENSE). The
  upstream repository has no NOTICE file.
- **Changes:** converted from JSON to `key = value` records, keeping only the
  test groups that match pvault's use. Each file's header states the changes,
  the source file and its SHA-256. The conversion is done by
  `tools/vectors/gen_vectors.py`.

## IETF RFC test vectors

- **Files:**
  - `crates/pvault-core/testdata/rfc4231_hmac_sha512.txt`: values from RFC 4231
    ("Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384,
    and HMAC-SHA-512"), Section 4.
  - `crates/pvault-core/testdata/rfc9106_argon2id.txt`: values from RFC 9106
    ("Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
    Applications"), Section 5.3.
  - `crates/pvault-core/testdata/xchacha20_draft.txt`: values from the
    Internet-Draft draft-irtf-cfrg-xchacha-03 ("XChaCha: eXtended-nonce ChaCha
    and AEAD_XChaCha20_Poly1305", S. Arciszewski, January 2020), Appendix
    A.3.2.1. Copyright (c) 2020 IETF Trust and the persons identified as the
    document authors. The draft has expired; it is used as the published
    definition of XChaCha20 that the `chacha20` crate and libsodium follow.
- **Copyright:** the IETF Trust and the persons identified as the documents'
  authors. Use is subject to the IETF Trust Legal Provisions,
  <https://trustee.ietf.org/license-info>.
- **Changes:** only the listed values were extracted, reformatted as hex
  `key = value` records, by `tools/vectors/gen_vectors.py`.
- **Open question:** the Legal Provisions grant a BSD-style license for "Code
  Components". Whether short test-vector excerpts are covered, or need a
  different basis, has not been confirmed and is flagged for review (SI-04).
