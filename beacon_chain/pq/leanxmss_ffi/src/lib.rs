//! C ABI over leanXMSS (leanVM `lean_xmss` crate) for nimbus-eth2.
//!
//! All functions are panic-safe: a panic inside the scheme is reported as a
//! failure instead of unwinding into the caller.

use lean_xmss::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey, LeanXmssSignature, MESSAGE_LEN, PUB_KEY_SIZE,
    SECRET_KEY_LEN, SIG_SIZE,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const _: () = assert!(PUB_KEY_SIZE == 32);
const _: () = assert!(SIG_SIZE == 2404);
const _: () = assert!(SECRET_KEY_LEN == 32);
const _: () = assert!(MESSAGE_LEN == 32);

/// Opaque expanded secret key: the top tree plus a cache of bottom trees.
pub struct LeanXmssKey {
    key: LeanXmssExpandedSecretKey,
    public_key: [u8; 32],
}

/// Generates the expanded secret key of `seed`, writing its public key to
/// `pubkey_out`. Returns null on failure. Free with `leanxmss_key_free`.
///
/// # Safety
/// `seed` must point to 32 readable bytes and `pubkey_out` to 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_key_gen(
    seed: *const u8,
    pubkey_out: *mut u8,
) -> *mut LeanXmssKey {
    if seed.is_null() || pubkey_out.is_null() {
        return std::ptr::null_mut();
    }
    let seed: [u8; 32] = unsafe { *(seed as *const [u8; 32]) };
    match catch_unwind(|| lean_xmss::key_gen(&seed)) {
        Ok((key, public_key)) => {
            let public_key = public_key.to_bytes();
            unsafe { std::ptr::copy_nonoverlapping(public_key.as_ptr(), pubkey_out, 32) };
            Box::into_raw(Box::new(LeanXmssKey { key, public_key }))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Generates `count` keys in parallel on up to `threads` threads (0: one per
/// core). `seeds` holds `count` 32-byte seeds back to back, `pubkeys_out`
/// receives `count` 32-byte public keys and `keys_out` `count` key pointers.
/// Returns the number of keys generated; a failed key is left null.
///
/// # Safety
/// Buffers must be valid for the sizes given above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_key_gen_many(
    seeds: *const u8,
    count: usize,
    threads: usize,
    pubkeys_out: *mut u8,
    keys_out: *mut *mut LeanXmssKey,
) -> usize {
    if count == 0 {
        return 0;
    }
    if seeds.is_null() || pubkeys_out.is_null() || keys_out.is_null() {
        return 0;
    }
    let seeds: Vec<[u8; 32]> = (0..count)
        .map(|i| unsafe { *(seeds.add(32 * i) as *const [u8; 32]) })
        .collect();
    let threads = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads
    }
    .min(count);

    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<std::sync::Mutex<Option<(LeanXmssExpandedSecretKey, [u8; 32])>>> =
        (0..count).map(|_| std::sync::Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= count {
                        break;
                    }
                    let seed = seeds[i];
                    if let Ok((key, pk)) = catch_unwind(|| lean_xmss::key_gen(&seed)) {
                        *results[i].lock().unwrap() = Some((key, pk.to_bytes()));
                    }
                }
            });
        }
    });

    let mut generated = 0;
    for (i, slot) in results.into_iter().enumerate() {
        let ptr = match slot.into_inner().unwrap() {
            Some((key, public_key)) => {
                unsafe {
                    std::ptr::copy_nonoverlapping(public_key.as_ptr(), pubkeys_out.add(32 * i), 32)
                };
                generated += 1;
                Box::into_raw(Box::new(LeanXmssKey { key, public_key }))
            }
            None => std::ptr::null_mut(),
        };
        unsafe { *keys_out.add(i) = ptr };
    }
    generated
}

/// Frees a key from `leanxmss_key_gen`. Null is ignored.
///
/// # Safety
/// `key` must come from this library and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_key_free(key: *mut LeanXmssKey) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Writes the public key of `key` to `pubkey_out` (32 bytes).
///
/// # Safety
/// `key` must be a live key; `pubkey_out` must have 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_key_public_key(key: *const LeanXmssKey, pubkey_out: *mut u8) {
    if key.is_null() || pubkey_out.is_null() {
        return;
    }
    let key = unsafe { &*key };
    unsafe { std::ptr::copy_nonoverlapping(key.public_key.as_ptr(), pubkey_out, 32) };
}

/// Builds and caches the bottom tree that holds `leaf_index`, so a later
/// `leanxmss_sign` at that leaf is fast. Returns 1 on success.
///
/// # Safety
/// `key` must be a live key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_prepare(key: *const LeanXmssKey, leaf_index: u32) -> i32 {
    if key.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    match catch_unwind(AssertUnwindSafe(|| key.key.prepare(leaf_index))) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Builds the bottom trees of `count` keys in parallel on up to `threads`
/// threads (0: one per core): the tree of `leaf_indices[i]` for `keys[i]`.
/// Returns the number of trees built.
///
/// # Safety
/// `keys` must hold `count` live keys and `leaf_indices` `count` indices.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_prepare_many(
    keys: *const *const LeanXmssKey,
    leaf_indices: *const u32,
    count: usize,
    threads: usize,
) -> usize {
    if count == 0 || keys.is_null() || leaf_indices.is_null() {
        return 0;
    }
    let jobs: Vec<(&LeanXmssKey, u32)> = (0..count)
        .filter_map(|i| {
            let key = unsafe { *keys.add(i) };
            if key.is_null() {
                None
            } else {
                Some((unsafe { &*key }, unsafe { *leaf_indices.add(i) }))
            }
        })
        .collect();
    let threads = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads
    }
    .min(jobs.len().max(1));

    let next = std::sync::atomic::AtomicUsize::new(0);
    let built = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= jobs.len() {
                        break;
                    }
                    let (key, leaf_index) = jobs[i];
                    if catch_unwind(AssertUnwindSafe(|| key.key.prepare(leaf_index))).is_ok() {
                        built.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    });
    built.load(std::sync::atomic::Ordering::Relaxed)
}

/// Signs the 32-byte `message` at `leaf_index`, writing 2404 bytes to
/// `signature_out`. Returns 1 on success.
///
/// # Safety
/// `key` must be a live key, `message` 32 readable bytes and `signature_out`
/// 2404 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_sign(
    key: *const LeanXmssKey,
    message: *const u8,
    leaf_index: u32,
    signature_out: *mut u8,
) -> i32 {
    if key.is_null() || message.is_null() || signature_out.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    let message: [u8; 32] = unsafe { *(message as *const [u8; 32]) };
    match catch_unwind(AssertUnwindSafe(|| {
        lean_xmss::sign(&key.key, &message, leaf_index).to_bytes()
    })) {
        Ok(signature) => {
            unsafe { std::ptr::copy_nonoverlapping(signature.as_ptr(), signature_out, SIG_SIZE) };
            1
        }
        Err(_) => 0,
    }
}

/// Whether the 2404-byte `signature` is valid for `message` under `pubkey`
/// at the leaf index it embeds. Returns 1 if valid, 0 otherwise.
///
/// # Safety
/// `pubkey` and `message` must be 32 readable bytes, `signature` 2404.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_verify(
    pubkey: *const u8,
    message: *const u8,
    signature: *const u8,
) -> i32 {
    if pubkey.is_null() || message.is_null() || signature.is_null() {
        return 0;
    }
    let pubkey: &[u8; 32] = unsafe { &*(pubkey as *const [u8; 32]) };
    let message: &[u8; 32] = unsafe { &*(message as *const [u8; 32]) };
    let signature: &[u8; SIG_SIZE] = unsafe { &*(signature as *const [u8; SIG_SIZE]) };
    match catch_unwind(|| {
        lean_xmss::verify(
            &LeanXmssPublicKey::from_bytes(pubkey),
            message,
            &LeanXmssSignature::from_bytes(signature),
        )
    }) {
        Ok(true) => 1,
        _ => 0,
    }
}
