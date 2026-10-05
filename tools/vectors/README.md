# Reference test-vector generator

`gen_vectors.py` writes the known-answer files in
`crates/pvault-core/testdata/`. It never runs pvault code. Every expected
value comes from a published source or from an independent implementation:

| Output | Source |
| --- | --- |
| `wycheproof_*.txt` | Project Wycheproof, commit `3fa63dd0344abb611f1fb1d77e119938603ea230` (Apache-2.0), converted. Each input file's SHA-256 is pinned in the script. |
| `rfc4231_hmac_sha512.txt` | Parsed from the RFC 4231 text (SHA-256 pinned). Each tag is re-verified with Python's `hmac`. |
| `rfc9106_argon2id.txt` | Parsed from the RFC 9106 text (SHA-256 pinned), Section 5.3 body. |
| `pvault_kdf.txt` | Spec 5.1, computed with `argon2-cffi` (the Argon2 reference implementation) and `cryptography` HKDF (OpenSSL). |
| `pvault_stream.txt` | Spec 7.7, computed with `cryptography` AES-GCM-SIV (OpenSSL) and `PyNaCl` XChaCha20-Poly1305 (libsodium). |
| `pvault_gf256.txt` | GF(2^8) with 0x11B: SHA-256 of the full multiplication table and the inverse table, from Python log/antilog tables (generator 0x03). |
| `pvault_shamir.txt` | Spec 7.4: secret, coefficients and shares at x = 1, 2, 3, from the same Python field code. Every pair is re-interpolated at x = 0 before writing. |
| `xchacha20_draft.txt` | Parsed from draft-irtf-cfrg-xchacha-03, Appendix A.3.2.1 (SHA-256 pinned), and re-verified with a Python HChaCha20 plus `cryptography` ChaCha20 (OpenSSL). |
| `pvault_wrap.txt` | Spec 7.5: the same Python HChaCha20 (checked against the draft's Section 2.2.1 vector) plus OpenSSL ChaCha20, cross-checked against `PyNaCl` XChaCha20-Poly1305 (libsodium) at block counter 1. |
| `pvault_passphrase.txt` | Spec 7.3 / SI-51 / D2: rejection sampling over the EFF list read from `assets/` (SHA-256 pinned); `H_w_v1` (unassigned refusal, NFKC, `str.casefold` full case folding, an explicit `White_Space` table) and H_c (unassigned refusal, NFC) with Python's `unicodedata` (Unicode 16.0). Inputs avoid characters whose properties changed in Unicode 17.0, which the Rust side uses. |
| `pvault_header.txt` | Spec 4.1, 4.2, 4.4: an independent Python deterministic-CBOR encoder (RFC 8949 §4.2.1, written from the spec, not from pvault's code); SHA-512 and HMAC-SHA-512 with `hashlib` and `hmac`. |
| `pvault_journal.txt` | Spec 8.1: every transition phase, a portable `convert` and two `init` records, with the same encoder and `hmac`. |
| `pvault_tokens.txt` | Spec 8.1 TPM-identity tokens, scopes 1, 2, 3 and 5: HKDF-SHA-512 (`cryptography`/OpenSSL) and XChaCha20-Poly1305 (`PyNaCl`/libsodium) over the exact AAD. |

## Environment used for the checked-in candidate files

- Python 3.14.7 on macOS (arm64), in an isolated virtual environment used for
  development only.
- Packages, pinned in `requirements.txt`: cryptography 50.0.2 (OpenSSL 4.0.3),
  PyNaCl 1.6.2, argon2-cffi 25.1.0, argon2-cffi-bindings 26.1.0.

## Inputs

- `--wycheproof DIR`: `hkdf_sha512_test.json`, `hmac_sha512_test.json`,
  `aes_gcm_siv_test.json` and `xchacha20_poly1305_test.json` from
  `https://raw.githubusercontent.com/C2SP/wycheproof/<commit>/testvectors_v1/`.
- `--rfc DIR`: `rfc4231.txt` and `rfc9106.txt` from
  `https://www.rfc-editor.org/rfc/`, and `draft-irtf-cfrg-xchacha-03.txt` from
  `https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt`.
- The EFF wordlist is read from `assets/eff_large_wordlist.txt` in this
  repository.

## Running

```sh
python3 -m venv /tmp/pvault-vectors
/tmp/pvault-vectors/bin/pip install -r tools/vectors/requirements.txt
/tmp/pvault-vectors/bin/python tools/vectors/gen_vectors.py \
    --wycheproof DIR --rfc DIR --out crates/pvault-core/testdata
```

The generated repository files in `crates/pvault-core/testdata/` are checked-in
files. The Milestone 1 files were committed in `bd04bb4` and the Milestone 2
files in `a099bb6`. The Milestone 3 changes (`pvault_passphrase.txt` for
`H_w_v1`, and the three format files) are uncommitted candidates. Rerunning
the script must reproduce every file exactly, apart from the provenance
header if package versions change. Verified on 2026-10-04: the eight
Milestone 1 files were reproduced byte-identically by the extended script.
Verified on 2026-10-05: with the Milestone 3 additions, every file other than
`pvault_passphrase.txt` (changed for `H_w_v1`) and the three new format files
is reproduced byte-identically, and a second run reproduces all of them.
