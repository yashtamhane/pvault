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
  `https://www.rfc-editor.org/rfc/`.

## Running

```sh
python3 -m venv /tmp/pvault-vectors
/tmp/pvault-vectors/bin/pip install -r tools/vectors/requirements.txt
/tmp/pvault-vectors/bin/python tools/vectors/gen_vectors.py \
    --wycheproof DIR --rfc DIR --out crates/pvault-core/testdata
```

The generated repository files in `crates/pvault-core/testdata/` are checked-in
candidates. Nothing has been committed to Git yet. Rerunning the script must
reproduce them exactly, apart from the provenance header if package versions
change (verified byte-identical on 2026-10-04).
