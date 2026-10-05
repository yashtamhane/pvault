//! Known-answer tests for the Milestone 3 formats against independent
//! vectors from `tools/vectors/gen_vectors.py` (a Python deterministic-CBOR
//! encoder, `hashlib`/`hmac`, OpenSSL HKDF and libsodium XChaCha20-Poly1305).

use crate::header::{Header, core_digest_of};
use crate::journal::{Record, TransitionPhase};
use crate::secrets::SecretBytes;
use crate::testvec::{field, hex_field, records};
use crate::tpmid::{self, IndexContext, Scope};

fn key(v: &[u8]) -> SecretBytes<32> {
    SecretBytes::take_from(&mut v.to_vec()).unwrap()
}

/// Parse, re-encode, digest and both MACs; then a rebuild from the parsed
/// fields reproduces the header byte for byte.
#[test]
fn header_vectors() {
    let all = records(include_str!("../testdata/pvault_header.txt"));
    assert_eq!(all.len(), 3);
    for v in all {
        let name = field(&v, "name");
        let bytes = hex_field(&v, "header");
        let k = key(&hex_field(&v, "k_mac"));
        let h = Header::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(h.core_bytes(), hex_field(&v, "core"), "{name}");
        assert_eq!(h.slots_bytes(), hex_field(&v, "slots"), "{name}");
        assert_eq!(h.core().encode().unwrap(), hex_field(&v, "core"), "{name}");
        assert_eq!(
            h.slots().encode().unwrap(),
            hex_field(&v, "slots"),
            "{name}"
        );
        assert_eq!(
            h.core_digest().to_vec(),
            hex_field(&v, "core_digest"),
            "{name}"
        );
        assert_eq!(core_digest_of(h.core_bytes()), h.core().digest().unwrap());
        assert!(h.verify_core(&k) && h.verify_slots(&k), "{name}");
        assert_eq!(
            Header::build(h.core(), h.slots(), &k).unwrap(),
            bytes,
            "{name}"
        );
        assert!(!h.verify_core(&key(&[0; 32])));
    }
}

/// Parse, authenticate with the recorded keys, and re-seal to the same bytes.
#[test]
fn journal_vectors() {
    let all = records(include_str!("../testdata/pvault_journal.txt"));
    assert_eq!(all.len(), 8);
    for v in all {
        let name = field(&v, "name");
        let bytes = hex_field(&v, "record");
        let old = key(&hex_field(&v, "key_old"));
        let new = v.get("key_new").map(|_| key(&hex_field(&v, "key_new")));
        let rec = Record::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(rec.verify_old(&old), "{name}");
        if let Some(n) = &new {
            assert!(rec.verify_new(n), "{name}");
            assert!(
                matches!(&rec, Record::Transition(t) if t.phase == TransitionPhase::Committing)
            );
        }
        let mut again = rec.clone();
        again.seal(&old, new.as_ref()).unwrap();
        assert_eq!(again.encode(), bytes, "{name}");
    }
}

/// Every token scope seals to the vector ciphertext with the fixed nonce,
/// and opens to the EK digest; another scope fails.
#[test]
fn token_vectors() {
    let all = records(include_str!("../testdata/pvault_tokens.txt"));
    assert_eq!(all.len(), 4);
    for v in all {
        let name = field(&v, "name");
        let scope = match field(&v, "scope") {
            "1" => Scope::Slots,
            "2" => Scope::Init,
            "3" => Scope::NewIndexOldSide,
            "5" => Scope::Cleanup,
            s => panic!("scope {s}"),
        };
        let ctx = IndexContext {
            tpm_index: field(&v, "tpm_index").parse().unwrap(),
            name_prewrite: v
                .get("name_prewrite")
                .map(|_| hex_field(&v, "name_prewrite").try_into().unwrap()),
            name_postwrite: hex_field(&v, "name_postwrite").try_into().unwrap(),
            policy_nonce: hex_field(&v, "policy_nonce").try_into().unwrap(),
        };
        let base = key(&hex_field(&v, "base_key"));
        let vault_id: [u8; 16] = hex_field(&v, "vault_id").try_into().unwrap();
        let digest = key(&hex_field(&v, "ek_digest"));
        let nonce = hex_field(&v, "nonce").try_into().unwrap();
        let token = tpmid::seal_with_nonce(scope, &base, &vault_id, &ctx, &digest, nonce).unwrap();
        assert_eq!(token.ct.to_vec(), hex_field(&v, "ct"), "{name}");
        let opened = tpmid::open(scope, &base, &vault_id, &ctx, &token).unwrap();
        assert_eq!(opened.expose_secret(), digest.expose_secret());
        let other = if scope == Scope::Cleanup {
            Scope::Slots
        } else {
            Scope::Cleanup
        };
        assert!(
            tpmid::open(other, &base, &vault_id, &ctx, &token).is_err(),
            "{name}"
        );
    }
}
