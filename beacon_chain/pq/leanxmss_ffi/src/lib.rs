// beacon_chain
// Copyright (c) 2026 Status Research & Development GmbH
// Licensed and distributed under either of
//   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
//   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
// at your option. This file may not be copied, modified, or distributed except according to those terms.

//! C ABI over leanXMSS (leanVM `lean_xmss` crate) for nimbus-eth2.
//!
//! All functions are panic-safe: a panic inside the scheme is reported as a
//! failure instead of unwinding into the caller.

use lean_xmss::internals::{PUBLIC_PARAM_LEN, public_param, scheme_seed};
use lean_xmss::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey, LeanXmssSignature, MESSAGE_LEN, PUB_KEY_SIZE,
    SECRET_KEY_LEN, SIG_SIZE,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

const _: () = assert!(PUB_KEY_SIZE == 32);
const _: () = assert!(SIG_SIZE == 2404);
const _: () = assert!(SECRET_KEY_LEN == 32);
const _: () = assert!(MESSAGE_LEN == 32);
const _: () = assert!(PUBLIC_PARAM_LEN == 16);

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

/// Writes the 16-byte public parameter of the key of `seed`, the second half
/// of its public key, to `param_out`. Unlike key generation this is a single
/// hash. Returns 1 on success.
///
/// # Safety
/// `seed` must point to 32 readable bytes and `param_out` to 16 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_public_param(seed: *const u8, param_out: *mut u8) -> i32 {
    if seed.is_null() || param_out.is_null() {
        return 0;
    }
    let seed: [u8; 32] = unsafe { *(seed as *const [u8; 32]) };
    match catch_unwind(|| public_param(&scheme_seed(&seed))) {
        Ok(param) => {
            unsafe { std::ptr::copy_nonoverlapping(param.as_ptr(), param_out, PUBLIC_PARAM_LEN) };
            1
        }
        Err(_) => 0,
    }
}

/// Loads the key of `seed` from `cache`, the `cache_len` bytes of
/// `leanxmss_key_cache` for the key with public key `pubkey`, instead of
/// hashing its trees. The cache holds no secret and is checked against
/// `pubkey`: null is returned if it is not that of the key. Free with
/// `leanxmss_key_free`.
///
/// # Safety
/// `seed` and `pubkey` must point to 32 readable bytes and `cache` to
/// `cache_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_key_from_cache(
    seed: *const u8,
    pubkey: *const u8,
    cache: *const u8,
    cache_len: usize,
) -> *mut LeanXmssKey {
    if seed.is_null() || pubkey.is_null() || cache.is_null() {
        return std::ptr::null_mut();
    }
    let seed: [u8; 32] = unsafe { *(seed as *const [u8; 32]) };
    let public_key: [u8; 32] = unsafe { *(pubkey as *const [u8; 32]) };
    let cache = unsafe { std::slice::from_raw_parts(cache, cache_len) };
    match catch_unwind(|| {
        LeanXmssExpandedSecretKey::from_cache_bytes(
            &seed,
            &LeanXmssPublicKey::from_bytes(&public_key),
            cache,
        )
    }) {
        Ok(Some(key)) => Box::into_raw(Box::new(LeanXmssKey { key, public_key })),
        _ => std::ptr::null_mut(),
    }
}

/// Copies the tree cache of `key`, its top tree and the bottom trees it used
/// last, to the `capacity` bytes at `cache_out` if it fits. Returns the size
/// of the cache, 0 on failure.
///
/// # Safety
/// `key` must be a live key and `cache_out` have `capacity` writable bytes;
/// `cache_out` may be null when `capacity` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_key_cache(
    key: *const LeanXmssKey,
    cache_out: *mut u8,
    capacity: usize,
) -> usize {
    if key.is_null() {
        return 0;
    }
    let key = unsafe { &*key };
    match catch_unwind(AssertUnwindSafe(|| key.key.cache_to_bytes())) {
        Ok(cache) => {
            if cache.len() <= capacity && !cache_out.is_null() {
                unsafe { std::ptr::copy_nonoverlapping(cache.as_ptr(), cache_out, cache.len()) };
            }
            cache.len()
        }
        Err(_) => 0,
    }
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

/// Leaves under one stored node of a VRF tree: `2^10`.
const VRF_SUBTREE_LEAVES: u64 = 1 << 10;

/// The root of the subtree of `VRF_SUBTREE_LEAVES` leaves that starts at leaf
/// `first` of the VRF tree of `seed`: leaf `i` is
/// `keccak256(seed | i as 8 little-endian bytes)`, a node
/// `keccak256(left | right)`.
fn vrf_subtree_root(seed: &[u8; 32], first: u64) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = (first..first + VRF_SUBTREE_LEAVES)
        .map(|i| {
            let mut leaf = [0u8; 40];
            leaf[..32].copy_from_slice(seed);
            leaf[32..].copy_from_slice(&i.to_le_bytes());
            keccak256::hash(&leaf)
        })
        .collect();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[left, right]| keccak256::hash_pair(left, right))
            .collect();
    }
    level[0]
}

/// Hashes the first `subtrees * 2^10` leaves of the VRF trees of `count` seeds
/// on up to `threads` threads (0: one per core). `seeds` holds `count`
/// 32-byte seeds back to back; `roots_out` receives, per seed, the `subtrees`
/// 32-byte roots of its subtrees of `2^10` leaves, left to right. Returns the
/// number of trees hashed.
///
/// # Safety
/// `seeds` must point to `32 * count` readable bytes and `roots_out` to
/// `32 * subtrees * count` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanxmss_vrf_subtree_roots_many(
    seeds: *const u8,
    count: usize,
    subtrees: usize,
    threads: usize,
    roots_out: *mut u8,
) -> usize {
    if count == 0 || subtrees == 0 || seeds.is_null() || roots_out.is_null() {
        return 0;
    }
    let seeds: Vec<[u8; 32]> = (0..count)
        .map(|i| unsafe { *(seeds.add(32 * i) as *const [u8; 32]) })
        .collect();
    let out = unsafe { std::slice::from_raw_parts_mut(roots_out, 32 * subtrees * count) };
    let threads = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads
    }
    .min(count);

    // One tree per job: each thread takes the next tree and its part of `out`
    let jobs = std::sync::Mutex::new(seeds.iter().zip(out.chunks_mut(32 * subtrees)));
    let hashed = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let Some((seed, roots)) = jobs.lock().unwrap().next() else {
                        break;
                    };
                    let done = catch_unwind(AssertUnwindSafe(|| {
                        for (k, root) in roots.chunks_mut(32).enumerate() {
                            root.copy_from_slice(&vrf_subtree_root(
                                seed,
                                k as u64 * VRF_SUBTREE_LEAVES,
                            ));
                        }
                    }));
                    if done.is_ok() {
                        hashed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    });
    hashed.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION_LEAF: u32 = 0;
    const SLOT_DUTY_LEAF: u32 = 24576 << 16;

    fn key_gen(seed: &[u8; 32]) -> (*mut LeanXmssKey, [u8; 32]) {
        let mut pubkey = [0u8; 32];
        let key = unsafe { leanxmss_key_gen(seed.as_ptr(), pubkey.as_mut_ptr()) };
        assert!(!key.is_null());
        (key, pubkey)
    }

    fn cache(key: *const LeanXmssKey) -> Vec<u8> {
        let len = unsafe { leanxmss_key_cache(key, std::ptr::null_mut(), 0) };
        let mut out = vec![0u8; len];
        assert_eq!(unsafe { leanxmss_key_cache(key, out.as_mut_ptr(), len) }, len);
        out
    }

    fn sign(key: *const LeanXmssKey, message: &[u8; 32], leaf_index: u32) -> Vec<u8> {
        let mut signature = vec![0u8; SIG_SIZE];
        assert_eq!(
            unsafe { leanxmss_sign(key, message.as_ptr(), leaf_index, signature.as_mut_ptr()) },
            1
        );
        signature
    }

    #[test]
    fn sign_and_verify() {
        let (key, pubkey) = key_gen(&[1; 32]);
        let message = [2u8; 32];
        let signature = sign(key, &message, 5);
        assert_eq!(
            unsafe { leanxmss_verify(pubkey.as_ptr(), message.as_ptr(), signature.as_ptr()) },
            1
        );
        assert_eq!(
            unsafe { leanxmss_verify(pubkey.as_ptr(), [3u8; 32].as_ptr(), signature.as_ptr()) },
            0
        );
        unsafe { leanxmss_key_free(key) };
    }

    #[test]
    fn public_param_is_the_end_of_the_public_key() {
        let seed = [4u8; 32];
        let (key, pubkey) = key_gen(&seed);
        let mut param = [0u8; PUBLIC_PARAM_LEN];
        assert_eq!(unsafe { leanxmss_public_param(seed.as_ptr(), param.as_mut_ptr()) }, 1);
        assert_eq!(param, pubkey[PUB_KEY_SIZE - PUBLIC_PARAM_LEN..]);
        unsafe { leanxmss_key_free(key) };
    }

    #[test]
    fn key_loads_from_its_cache_only() {
        let seed = [5u8; 32];
        let (key, pubkey) = key_gen(&seed);
        assert_eq!(cache(key).len(), 4096);
        assert_eq!(unsafe { leanxmss_prepare(key, ATTESTATION_LEAF) }, 1);
        assert_eq!(unsafe { leanxmss_prepare(key, SLOT_DUTY_LEAF) }, 1);
        let bytes = cache(key);
        // The record size of the files of `--xmss-cache-url`
        assert_eq!(bytes.len(), 14696);

        let load = |seed: &[u8; 32], pubkey: &[u8; 32], bytes: &[u8]| unsafe {
            leanxmss_key_from_cache(seed.as_ptr(), pubkey.as_ptr(), bytes.as_ptr(), bytes.len())
        };
        let loaded = load(&seed, &pubkey, &bytes);
        assert!(!loaded.is_null());
        let mut loaded_pubkey = [0u8; 32];
        unsafe { leanxmss_key_public_key(loaded, loaded_pubkey.as_mut_ptr()) };
        assert_eq!(loaded_pubkey, pubkey);
        let message = [6u8; 32];
        for leaf_index in [ATTESTATION_LEAF + 3, SLOT_DUTY_LEAF + 9] {
            assert_eq!(sign(loaded, &message, leaf_index), sign(key, &message, leaf_index));
        }
        assert_eq!(cache(loaded), bytes);

        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(load(&seed, &pubkey, &tampered).is_null());
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(load(&seed, &pubkey, &tampered).is_null());
        assert!(load(&seed, &pubkey, &bytes[..bytes.len() - 1]).is_null());
        assert!(load(&[7; 32], &pubkey, &bytes).is_null());
        let mut other = pubkey;
        other[0] ^= 1;
        assert!(load(&seed, &other, &bytes).is_null());

        unsafe { leanxmss_key_free(loaded) };
        unsafe { leanxmss_key_free(key) };
    }

    #[test]
    fn vrf_subtree_roots_do_not_depend_on_threads() {
        let seeds: Vec<u8> = (0..3u8).flat_map(|i| [i + 8; 32]).collect();
        let roots = |threads: usize| {
            let mut out = vec![0u8; 32 * 4 * 3];
            assert_eq!(
                unsafe {
                    leanxmss_vrf_subtree_roots_many(seeds.as_ptr(), 3, 4, threads, out.as_mut_ptr())
                },
                3
            );
            out
        };
        let one = roots(1);
        assert_eq!(roots(3), one);
        assert_eq!(roots(0), one);
        // Per seed, subtree `k` starts at leaf `1024 * k`
        for (i, seed) in seeds.chunks(32).enumerate() {
            let seed: [u8; 32] = seed.try_into().unwrap();
            for k in 0..4 {
                let at = 32 * (4 * i + k);
                assert_eq!(one[at..at + 32], vrf_subtree_root(&seed, 1024 * k as u64));
            }
        }
        assert_eq!(
            unsafe { leanxmss_vrf_subtree_roots_many(seeds.as_ptr(), 0, 4, 1, std::ptr::null_mut()) },
            0
        );
    }
}
