# Third-party notices

pvault's own code and documentation are by Yash Sandeep Tamhane. This file
lists third-party material kept in this repository. Rust dependency licenses
are checked by `cargo-deny` (`deny.toml`). Generating notices for release
artifacts is planned for Milestone 13.

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
- **Copyright:** the IETF Trust and the persons identified as the documents'
  authors. Use is subject to the IETF Trust Legal Provisions,
  <https://trustee.ietf.org/license-info>.
- **Open question:** the Legal Provisions grant a BSD-style license for "Code
  Components". Whether short test-vector excerpts are covered, or need a
  different basis, has not been confirmed and is flagged for review (SI-04).
