# pvault formats (Milestones 1 and 2)

Byte-level formats, written as the milestones that define them are built.
Milestone 1 covers the key derivations of spec Section 5.1 and the chunked
stream of Section 7.7. Milestone 2 adds Shamir sharing (7.4), wraps (7.5) and
passphrase generation and handling (7.3, SI-51). All known-answer values below come from
`crates/pvault-core/testdata/`, which `tools/vectors/gen_vectors.py` produces
with independent implementations and published sources. pvault never
generates its own expected results.

## Key derivation (spec 5.1)

```text
master_pw = Argon2id(version 0x13 (19), password = handled passphrase bytes (H_w or H_c),
                     salt = core.salt (32 bytes), m = argon2_m KiB, t, p,
                     no secret, no associated data)      -> 32 bytes
subkey    = HKDF-SHA-512(ikm, salt = none (64 zero bytes), info, L = 32)
```

| Key | IKM | `info` (ASCII) |
| --- | --- | --- |
| `k_s1wrap` | `master_pw` | `pvault/v1/s1-wrap` |
| `k_s2wrap` | `master_pw` | `pvault/v1/s2-wrap` |
| `tpm_auth` | `master_pw` | `pvault/v1/tpm-auth` |
| `k_slot` | `master_pw` | `pvault/v1/portable-slot` |
| `duress_key` | `master_pw` | `pvault/v1/duress` |
| `journal_key` | `K_mac` | `pvault/v1/journal` |

The Argon2 hard caps (spec 4.3) are checked before any memory is allocated:
262,144 ≤ m ≤ 4,194,304 KiB, 3 ≤ t ≤ 16, 1 ≤ p ≤ 8. pvault allocates the
Argon2 block memory itself, and wipes it before releasing it.

**Measured performance.** Argon2id is single-threaded: the `p` lanes are
computed one after another, because parallel lanes would need `rayon`, which
is not approved. Criterion benchmark `argon2id`, measured 2026-10-04 on an
Apple M4 (10 cores, 16 GiB RAM), macOS, Rust 1.99, release profile. Times
include pvault's block allocation and its wipe.

| Parameters | Median time |
| --- | --- |
| m = 256 MiB, t = 3, p = 4 (minimum memory) | 0.36 s |
| m = 1 GiB, t = 4, p = 4 (defaults for new vaults) | 1.95 s |

Slower machines take proportionally longer per unlock. No other platforms
have been measured yet.

### Known-answer vectors

Passphrases are given as UTF-8 hex, already normalized (spec 7.3). They are
arbitrary test strings and are not checked against the word list.

**KDF vector 1** (m = 262144 KiB, t = 3, p = 4)

```text
passphrase_utf8 = 616261637573206162646f6d656e206162646f6d696e616c2061626964652061626964696e67206162696c6974792061626c617a652061626c652061626e6f726d616c206162726173696f6e2061627261736976652061627265617374
salt            = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
master_pw       = ca447f3c2718da56fe0470cd02a469b5d3e9088bf48f0303e5605fe3a43266c3
s1_wrap         = 91b015d7a02030ed3db90469d1e3354012db8540a639fbb4836cdec63fa92b74
s2_wrap         = f78629d5fbfe62bfddc47674f9cc1a3fe929e05d94b5897aac51841c0aaa7ae9
tpm_auth        = 0a1a177bdd92920b4fcc016bae52341ec6db86e0faaf64ef6d07761369d4c466
portable_slot   = 4327f87ef0ce2e6a2480f972026971871afa39b735fe2457ad7d818da94cb8b2
duress          = 4a80d96aed5aced665a307fbe136ad3804d72b1561857ae6b11f9ceaf3b8e8f6
k_mac           = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
journal_key     = 114e9d9c00d67593990054633470b7f1a502d1b8e87b613917820c810b1184c8
```

**KDF vector 2** (m = 262144 KiB, t = 4, p = 1)

```text
passphrase_utf8 = 7a6f6f6d207a6f6e65207a6f6e696e67207a6f6f6b6565706572207a6f6f6c6f67697374207a6f6f6c6f677920796f2d796f20742d7368697274
salt            = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
master_pw       = e9c9d28b4d7e64f76470d48ea725a5b4d5b7d03ccc64cf755e9bf59118cee265
s1_wrap         = 5822581e2a654617e71af9d881da4e8aac09b20078df2f543432956258b50f03
s2_wrap         = 526cd2cdcb2511edd6c6b36b8edc88b5815d1480ba65b60e11046b6dea105695
tpm_auth        = e3b658639f5cbf800555c1c6b2f6ffb971ea2a0fe4618a608ae4fdf7a4626c34
portable_slot   = 3826f5d28ec6a93b5b513919a159de0bac7c0283788f0fb47e5b2f495844953f
duress          = 3506f004b7f9a294005f46656a6737a298fa4befe5c6a462b1fa2c95e57cc471
k_mac           = 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
journal_key     = 0d70d067572b9009ea835ee97d507280076f484c79962879cd470898dbfd825d
```

Published Argon2id check: RFC 9106 Section 5.3 (32 KiB, with a secret and
associated data) is verified against the `argon2` crate directly, because
pvault itself never uses those inputs.

## Chunked stream (spec 7.7)

```text
header  = magic(4: "PVOB" | "PVKT") || u16_be(version = 1) || stream_id(16)
          || u64_be(context) || u64_be(plain_size)                     38 bytes
records = chunk_count = max(1, ceil(plain_size / 65536)) times:
          u32_be(rec_len) || n2(24) || c2(rec_len - 24)
aad_i   = "pvault/v1/" || magic || u16_be(version) || stream_id || u64_be(context)
          || u64_be(plain_size) || u64_be(chunk_count) || u64_be(i) || u8(is_last)   65 bytes
c1_i    = AES-256-GCM-SIV(key_aes, n1_i).encrypt(chunk_i, aad_i)       (ciphertext || 16-byte tag)
c2_i    = XChaCha20-Poly1305(key_chacha, n2_i).encrypt(n1_i || c1_i, aad_i)
rec_len = 24 + 12 + len(chunk_i) + 16 + 16                             (exact)
```

- Every chunk except the last holds exactly 65,536 plaintext bytes. An empty
  stream is one chunk of 0 bytes.
- Bytes after the last record are rejected.
- Decryption checks the outer tag, then the inner tag, before any plaintext
  of that chunk is released.

### Known-answer vectors

Common to all cases: `key_aes = 202122…3f`, `key_chacha = 404142…5f`.
`stream_id` is `a0a1…af` for objects and `c0c1…cf` for the key table. The
plaintext byte at index j is `(31·j + 7) mod 256`. Nonces for chunk i are
`n1_i[j] = (0x10 + i + j) mod 256` (12 bytes) and
`n2_i[j] = (0x80 + 3·i + j) mod 256` (24 bytes). The full parameters, and the
complete streams of the small cases, are in `testdata/pvault_stream.txt`.

| Case | Kind | `context` | `plain_size` | Stream length | SHA-256 of the stream |
| --- | --- | --- | --- | --- | --- |
| object-empty | object | 0 | 0 | 110 | `f554214bd3d5109ec0cb3192ea0d9a64bc853092e623f46f97e468cc43bb48c6` |
| object-1 | object | 0 | 1 | 111 | `1eaba215b7c48d7c6ca4bbc8b4221cc92121742fa8f3106a1856be1df82c4428` |
| object-64k | object | 0 | 65536 | 65646 | `729e3fd4f3dd7b0000f8abb043c4f80ec634adbbed80a75f0229e81cbcedd806` |
| object-64k-plus-1 | object | 0 | 65537 | 65719 | `f48065260c46fbe3d221250229a2c11f822ae7aa60bab93b8096771374c06015` |
| keytable-100 | keytable | 7 | 100 | 210 | `49438f6337705ef3bccfc1640cae83655bb1f40cce389f146e24ad6d02656676` |

## Shamir sharing (spec 7.4)

```text
field   = GF(2^8), reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B); addition is XOR
split   = for each byte i of the 96-byte secret s, with a fresh random byte a_i:
            y_i(x) = s_i XOR (a_i · x)              for x = 1, 2, 3 (bound) or 1, 2 (portable)
combine = Lagrange interpolation at x = 0 from two shares with distinct, non-zero x:
            s_i = y_i(x1) · x2 / (x1 XOR x2)  XOR  y_i(x2) · x1 / (x1 XOR x2)
```

- `a_i` is uniform over all 256 values, including 0, drawn from `getrandom`.
- Arithmetic is from `vsss-rs` 6.0.1 through its public polynomial API.
  pvault owns and wipes every buffer that holds the secret, a coefficient or a
  share.

**Known-answer vector `counting`** (three more in `testdata/pvault_shamir.txt`:
all-zero coefficients, all `ff`, and hash-derived bytes). The expected values
were computed with GF(2^8) log/antilog tables (generator 0x03), and every pair
was re-interpolated at x = 0.

```text
secret       = 000102…5f   (byte i = i)
coefficients = 606162…bf   (byte i = 0x60 + i)
share_x1     = 6060606060606060606060606060606060606060606060606060606060606060a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0
share_x2     = c0c3c6c5cccfcac9d8dbdeddd4d7d2d1f0f3f6f5fcfffaf9e8ebeeede4e7e2e13b383d3e37343132232025262f2c292a0b080d0e07040102131015161f1c191a1b181d1e17141112030005060f0c090a2b282d2e27242122333035363f3c393a
share_x3     = a0a2a4a6a8aaacaeb0b2b4b6b8babcbe80828486888a8c8e90929496989a9c9ebbb9bfbdb3b1b7b5aba9afada3a1a7a59b999f9d939197958b898f8d83818785bbb9bfbdb3b1b7b5aba9afada3a1a7a59b999f9d939197958b898f8d83818785
```

**Field check.** All 65,536 products `a · b` (a-major order) hash to SHA-256
`14a1e7e77ca8a30b5bb53e6310748ce0498eb9e04ab78a44dbefb6ebfac8a84b`; the 255
inverses are listed in `testdata/pvault_gf256.txt`. The tests compare
`vsss-rs` against both, and against a third, shift-and-add multiply.

## Wraps (spec 7.5)

```text
ct = plaintext XOR XChaCha20_keystream(key (32), nonce (24))     keystream from block counter 0
```

XChaCha20 is as defined in draft-irtf-cfrg-xchacha-03: HChaCha20 over the key
and the first 16 nonce bytes gives a subkey, then ChaCha20 (RFC 8439) runs with
the nonce `00000000 || nonce[16..24]`. There is no tag; the header MACs prove
correctness (spec 5.4).

**Known-answer vector `bundle-counting`** (two more in `testdata/pvault_wrap.txt`).
The expected values come from a Python HChaCha20, checked against the draft's
Section 2.2.1 vector, with OpenSSL ChaCha20. They are cross-checked against
libsodium's XChaCha20-Poly1305 body, which uses block counter 1.

```text
key        = 606162…7f   (byte i = 0x60 + i)
nonce      = b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7
plaintext  = 000102…5f   (byte i = i; 96 bytes)
ciphertext = 7f87bec85b8bd08c73b92fb7cc68132850cae98be9c285cc3bbb768dc2c5b3b62cfb04fad949e49c7afaa8cba25e7c9c99cc047709f6fdf4d156227daed00ea7b38058ee0a57fe060d4adc2198819ebda75f0be54298be0951f08b27dcf40c4e
```

The published draft vector (Appendix A.3.2.1, block counter 0) is also tested.

## Passphrases (spec 7.3, SI-51)

**Generation.** Words come from `assets/eff_large_wordlist.txt` (7,776 words,
SHA-256 `addd3553…903e`), indexed in file order from 0. Each word takes two
bytes from `getrandom`, read as a big-endian `u16`. Values of 62,208
(= 8 × 7,776) or more are rejected and redrawn; otherwise the index is
`value mod 7776`, which is uniform. Words are lowercase and joined by single
spaces (U+0020). Main passphrases have 10–16 words (default 12); duress
passphrases have 12.

| Words | Calculated classical entropy, `n × log2(7776)` | Policy rating |
| --- | --- | --- |
| 10 | 129.2 bits | Medium |
| 11 | 142.2 bits | Medium |
| 12 | 155.1 bits | Strong |
| 16 | 206.8 bits | Strong |

**Sampling vector** (12 words): the byte stream starts
`ffff f300 0000 f2ff 1e60 1e5f …`. The first two values (65,535 and 62,208) are
rejected; 0, 62,207, 7,776 and 7,775 give indices 0, 7,775, 0 and 7,775. The
result is `abacus zoom abacus zoom clothing karaoke density untreated doily
serve ether ouch`, using 30 bytes. Two more vectors (10 and 16 words) are in
`testdata/pvault_passphrase.txt`.

**Handling.** Input is at most 1,024 raw bytes of valid UTF-8.

| | H_w (generated words: main and duress) | H_c (custom main) |
| --- | --- | --- |
| Steps | NFKC; trim; each run of `White_Space` → one U+0020; per-character full lowercase | NFC only |
| Output limit | 1,024 bytes | 1 to 256 bytes |
| Refused | empty result | empty result; C0 and C1 controls and DEL; U+2028, U+2029; bidirectional controls U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069; U+FEFF; noncharacters |
| Warned (kept) | — | leading or trailing whitespace; U+200C, U+200D, U+2060, U+00AD |
| Then | word-list check (first unknown word reported) | estimator, at creation only |

Examples from `testdata/pvault_passphrase.txt` (19 handling vectors, computed
with Python's `unicodedata`, Unicode 16.0):

| Input | Handling | Result |
| --- | --- | --- |
| `␠␠Abacus⇥⇥ZONE␠U+3000␠ｙｏ-ｙｏ␠↵` | H_w | `abacus zone yo-yo` |
| `ﬁve Ⅳ` | H_w | `five iv` |
| `cafe` + U+0301 | H_c | `café` (NFC changed the input, so the notice is shown) |
| `ﬁ Ａ Ⅳ` | H_c | unchanged (NFC keeps compatibility characters) |
| `abc` + U+202E + `def` | H_c | refused: bidirectional control |

Normalization runs the UAX #15 algorithm over the per-character primitives of
`unicode-normalization` 0.1.25 (Unicode 17.0) in one fixed, wiped buffer. Its
results are tested to be identical to that crate's own NFC and NFKC
iterators.

**Collision rule.** A duress passphrase collides with the main passphrase when
`H_w(main input)` equals the duress words. It is checked at duress setup and
whenever either credential changes.

## Custom-passphrase estimator protocol (SI-51)

The parent re-executes the pvault binary with the single argument
`__pvault-estimate-child`, a cleared environment (Windows keeps `SystemRoot`),
piped stdin and stdout, and stderr discarded. The child hardens itself (core
dumps off; `RLIMIT_CPU` 5 s; Linux `RLIMIT_AS` 512 MiB) before reading.

```text
request = u16_be(len) || H_c bytes (1..256) || u8(context_len) || context (0..255, UTF-8)
reply   = u8(version = 1) || u16_be(round(log10(guesses) × 100))
          || u8(warning: 0 = none, else zxcvbn Warning discriminant + 1)
          || u8(count) || count × u8(zxcvbn Suggestion discriminant)          ≤ 64 bytes
```

- The codes are `zxcvbn` 3.1.1's enum declaration order (14 warnings, 13
  suggestions); a test pins the order.
- Any failure (spawn, a 5 s wall-clock timeout, a non-zero exit, a malformed
  reply) refuses the new custom passphrase.
- Bands (provisional policy, always shown as "Estimated"): weak below 14.00
  (refused), medium 14.00 to 17.99 (needs `ACCEPT MEDIUM PASSPHRASE`), strong
  18.00 and above.

## Published vectors used by the tests

| File | Source | Records |
| --- | --- | --- |
| `wycheproof_hmac_sha512.txt` | Wycheproof `hmac_sha512_test.json`, 512-bit tags only | 87 |
| `wycheproof_hkdf_sha512.txt` | Wycheproof `hkdf_sha512_test.json` | 83 |
| `wycheproof_aes256_gcm_siv.txt` | Wycheproof `aes_gcm_siv_test.json`, 256-bit keys | 103 |
| `wycheproof_xchacha20_poly1305.txt` | Wycheproof `xchacha20_poly1305_test.json`, 192-bit nonces | 306 |
| `rfc4231_hmac_sha512.txt` | RFC 4231 Section 4, Test Cases 1–4, 6, 7 | 6 |
| `rfc9106_argon2id.txt` | RFC 9106 Section 5.3 | 1 |
| `xchacha20_draft.txt` | draft-irtf-cfrg-xchacha-03 Appendix A.3.2.1 (XChaCha20, counter 0) | 1 |

The Wycheproof vectors are at commit `3fa63dd0344abb611f1fb1d77e119938603ea230`.
Licensing and changes are listed in `THIRD_PARTY_NOTICES.md`.
