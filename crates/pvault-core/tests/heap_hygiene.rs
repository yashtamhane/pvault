//! Heap hygiene for secret-handling code (SI-08, SI-51). Runs in its own test
//! process with a counting global allocator.
//!
//! While a check is armed on the current thread, the allocator counts every
//! allocation and inspects every freed block. A freed block that still holds a
//! non-zero byte is an unwiped copy.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use pvault_core::crypto::{random, wrap};
use pvault_core::passphrase::{self, WordCount};
use pvault_core::shamir;

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static UNWIPED_FREES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

fn armed() -> bool {
    ARMED.try_with(Cell::get).unwrap_or(false)
}

// SAFETY: every call is forwarded unchanged to `System`; the extra work only
// reads memory that the caller still owns.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if armed() {
            ALLOCATIONS.fetch_add(1, SeqCst);
        }
        // SAFETY: forwarded with the caller's valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if armed() {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes that the
            // caller is about to free.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            if block.iter().any(|&b| b != 0) {
                UNWIPED_FREES.fetch_add(1, SeqCst);
            }
        }
        // SAFETY: forwarded with the pointer and layout the caller allocated.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Runs `f` armed and returns (allocations, unwiped frees) made inside it.
fn measure<T>(f: impl FnOnce() -> T) -> (usize, usize) {
    ALLOCATIONS.store(0, SeqCst);
    UNWIPED_FREES.store(0, SeqCst);
    ARMED.with(|a| a.set(true));
    let out = f();
    drop(out);
    ARMED.with(|a| a.set(false));
    (ALLOCATIONS.load(SeqCst), UNWIPED_FREES.load(SeqCst))
}

// One test function, so no other test thread runs while a check is armed.
#[test]
fn secret_code_paths_allocate_only_their_outputs_and_free_only_wiped_blocks() {
    // Warm-up: builds the word list index once.
    assert!(passphrase::is_listed("abacus"));
    let secret = random::secret::<{ shamir::SECRET_LEN }>().unwrap();
    let key = random::secret::<32>().unwrap();

    // Shamir: vsss-rs works only in pvault-owned fixed storage. Each
    // `SecretBytes` is one boxed allocation (so moving it never copies the
    // secret). The 9 allocations are exactly pvault's own buffers: per split,
    // one coefficient buffer plus one per share (4 + 3), plus one output per
    // combine (2). Any allocation inside vsss-rs would raise the count.
    let (allocs, unwiped) = measure(|| {
        let shares = shamir::split_2_of_3(&secret).unwrap();
        let back = shamir::combine(&shares[0], &shares[2]).unwrap();
        let portable = shamir::split_2_of_2(&secret).unwrap();
        let again = shamir::combine(&portable[1], &portable[0]).unwrap();
        (shares, back, portable, again)
    });
    assert_eq!((allocs, unwiped), (9, 0), "shamir");

    // Shamir error path: a share paired with itself is refused before any
    // buffer is allocated.
    let shares = shamir::split_2_of_3(&secret).unwrap();
    let (allocs, unwiped) = measure(|| assert!(shamir::combine(&shares[1], &shares[1]).is_err()));
    assert_eq!((allocs, unwiped), (0, 0), "shamir error path");

    // Wraps: the ciphertext is a plain array; the unwrapped secret is one box.
    let (allocs, unwiped) = measure(|| {
        let (nonce, ct) = wrap::wrap(&key, &secret).unwrap();
        wrap::unwrap(&key, &nonce, &ct)
    });
    assert_eq!((allocs, unwiped), (1, 0), "wrap");

    // Generation: exactly one exactly-sized output buffer.
    let (allocs, unwiped) = measure(|| passphrase::generate(WordCount::new(16).unwrap()).unwrap());
    assert_eq!((allocs, unwiped), (1, 0), "generate");

    // Handling: one normalization buffer and one exactly sized output, both
    // wiped. Long runs of combining marks are included because the iterators
    // of unicode-normalization spill such runs to unwiped heap blocks.
    let marks = "\u{301}\u{316}".repeat(60);
    let inputs = [
        "  Abacus   ZONE yo-yo\tT-SHIRT ".to_string(),
        "Caf\u{e9} au lait, s'il vous pla\u{ee}t".to_string(),
        format!("a{marks}b \u{fdfa} \u{ac00}\u{11a8}"),
        "\u{fdfa}".repeat(passphrase::MAX_RAW_BYTES / 3),
    ];
    // The last input expands past the words limit and is refused after
    // normalization, with only the working buffer allocated.
    for (input, expected) in inputs.iter().zip([2, 2, 2, 1]) {
        let raw = input.as_bytes().to_vec();
        let (allocs, unwiped) = measure(|| {
            assert_eq!(passphrase::handle_words(&raw).is_ok(), expected == 2);
        });
        assert_eq!(
            (allocs, unwiped),
            (expected, 0),
            "handle_words {}",
            raw.len()
        );
    }

    // Custom handling. Accepted: working buffer and output. Refused
    // character: the same, both wiped. Too long: only the working buffer.
    // (Warnings, when present, are a list of positions, not passphrase text.)
    let custom = [
        (inputs[1].clone(), true, 2),
        (format!("a{marks}b"), true, 2),
        ("tab\there".to_string(), false, 2),
        (inputs[3].clone(), false, 1),
    ];
    for (input, accepted, expected) in &custom {
        let raw = input.as_bytes().to_vec();
        let (allocs, unwiped) =
            measure(|| assert_eq!(passphrase::handle_custom(&raw).is_ok(), *accepted));
        assert_eq!(
            (allocs, unwiped),
            (*expected, 0),
            "handle_custom {}",
            raw.len()
        );
    }

    // The collision rule: one handled copy plus its working buffer.
    let typed = inputs[0].as_bytes().to_vec();
    let duress = passphrase::generate(WordCount::DURESS).unwrap();
    let (allocs, unwiped) = measure(|| passphrase::duress_collides(&typed, &duress));
    assert_eq!((allocs, unwiped), (2, 0), "duress_collides");
}
