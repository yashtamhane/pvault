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

## Unicode Character Database 17.0.0

- **Files:**
  - `crates/pvault-core/src/ucd17/tables.rs`: tables generated from
    `UnicodeData.txt`, `DerivedNormalizationProps.txt`,
    `CompositionExclusions.txt`, `CaseFolding.txt` and `PropList.txt`
    (assigned code points, canonical combining classes, decompositions,
    compositions, case folding and `White_Space`). Compiled into the pvault
    library and binary.
  - `crates/pvault-core/testdata/unicode/NormalizationTest-17.0.0.txt`:
    `NormalizationTest.txt`, unchanged, used only by tests.
- **Source:** <https://www.unicode.org/Public/17.0.0/ucd/UCD.zip>. Every input
  file's SHA-256 is pinned in `tools/unicode/gen_ucd17.py` and listed in
  `tools/unicode/MANIFEST.txt`.
- **Copyright:** Copyright © 1991-2026 Unicode, Inc.
- **License:** Unicode License V3. A copy is in
  [`third_party/unicode/LICENSE`](third_party/unicode/LICENSE); it must
  accompany every copy of the data files and of the generated tables, including
  release artifacts (release notices are planned for Milestone 13).
- **Changes:** `tables.rs` is a derived, reformatted subset produced by
  `tools/unicode/gen_ucd17.py`; it states its origin and license in its first
  lines. `NormalizationTest.txt` is byte-identical to the archive's copy.

## libfuzzer-sys 0.4.13 (fuzz tooling only)

- **Use:** direct dependency of the excluded `fuzz/` crate only. It is not in
  the product workspace or product `Cargo.lock`, and is not linked into a
  pvault release artifact.
- **Source and provenance:** crates.io package `libfuzzer-sys` 0.4.13,
  checksum `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2`;
  upstream <https://github.com/rust-fuzz/libfuzzer>, git revision
  `719e4efb9b8857ebaa782ae59376c8cbb78fed0f` recorded by the package.
- **Declared license:** `(MIT OR Apache-2.0) AND NCSA`. The package includes
  `LICENSE-MIT` and `LICENSE-APACHE`; its README says every file in
  `libfuzzer/` is NCSA and all other files are MIT or Apache-2.0.
- **Bundled-source audit:** all 55 C/C++/header/definition files in the
  packaged `libfuzzer/` tree that carry SPDX identifiers say
  `Apache-2.0 WITH LLVM-exception`, rather than NCSA. This discrepancy is
  recorded rather than silently choosing one description; both the manifest
  license and the per-file notices must be preserved by anyone redistributing
  the fuzz runtime. The LLVM license is at
  <https://llvm.org/LICENSE.txt>.
- **Dependency and policy scope:** the direct runtime brings `arbitrary`; its
  build script brings `cc` (and `cc`'s build graph). `fuzz/Cargo.lock` pins the
  complete graph. `fuzz/deny.toml` grants NCSA and
  `Apache-2.0 WITH LLVM-exception` only to `libfuzzer-sys@0.4.13`; the product
  allowlist is unchanged. Advisories, bans, sources and licenses are checked
  against the fuzz lockfile separately.

## rqrr 0.11.0 and quirc-derived code

- **Use:** QR-code recognition in release binaries.
- **Source:** crates.io package `rqrr` 0.11.0,
  <https://crates.io/crates/rqrr/0.11.0>.
- **rqrr license:** MIT or Apache-2.0; pvault uses the MIT option. Copyright
  2019 Moritz Wanzenböck. The MIT permission and warranty notice in the
  package's `LICENSE-MIT` must remain with copies or substantial portions.
- **quirc-derived code:** Copyright (C) 2010-2012 Daniel Beer
  <dlbeer@gmail.com>, under the ISC license. Permission to use, copy, modify
  and/or distribute it for any purpose, with or without fee, is granted if
  that copyright and permission notice appear in all copies. The software is
  provided "AS IS", without warranty; the author is not liable for damages
  arising from its use or performance. The exact notice is distributed in
  the crate as `LICENSE-ISC`.

## foldhash 0.2.0

- **Use:** transitive hasher dependency of QR decoding in release binaries.
- **Source:** crates.io package `foldhash` 0.2.0,
  <https://crates.io/crates/foldhash/0.2.0>.
- **License:** Zlib. Copyright (c) 2024 Orson Peters. The software is provided
  as-is without warranty. It may be used, altered and redistributed for any
  purpose if its origin is not misrepresented, altered versions are marked,
  and the package's license notice is not removed from source distributions.

## option-ext 0.2.0

- **Use:** transitive dependency of the settings-directory lookup in release
  binaries.
- **Source availability:** crates.io package `option-ext` 0.2.0,
  <https://crates.io/crates/option-ext/0.2.0>, including its covered source.
- **License:** Mozilla Public License 2.0, without an Exhibit B notice. The
  package includes the complete text in `LICENSE.txt`; recipients can also
  obtain it at <https://mozilla.org/MPL/2.0/>. MPL 2.0 source-availability
  obligations apply to the covered files.

## MIT-only release dependencies

- `lru` 0.18.5: Copyright (c) 2016 Jerome Froelich.
- `simd-adler32` 0.3.10: Copyright (c) 2021 Marvin Countryman.
- **Source:** <https://crates.io/crates/lru/0.18.5> and
  <https://crates.io/crates/simd-adler32/0.3.10>.
- **License:** MIT. Permission is granted, free of charge, to use, copy,
  modify, merge, publish, distribute, sublicense and/or sell copies, provided
  the applicable copyright and permission notice is included in all copies
  or substantial portions. The software is provided "AS IS", without
  warranty or liability. Each crate includes the exact notice in its license
  file.
