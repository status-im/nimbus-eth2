// beacon_chain
// Copyright (c) 2026 Status Research & Development GmbH
// Licensed and distributed under either of
//   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
//   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
// at your option. This file may not be copied, modified, or distributed except according to those terms.

//! C ABI over leanVM for nimbus-eth2: leanXMSS signatures (`lean_xmss`), the
//! VRF tree, and the prover and verifier of signature aggregates (`lean_vm`),
//! which run in this process.
//!
//! All functions are panic-safe: a panic inside leanVM is reported as a
//! failure instead of unwinding into the caller.

#[cfg(unix)]
#[global_allocator]
static ALLOCATOR: allocator::Jemalloc = allocator::Jemalloc;

use lean_vm::{AggregateClaims, AggregateProof, OutputClaims};
use lean_xmss::internals::{PUBLIC_PARAM_LEN, public_param, scheme_seed};
use lean_xmss::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey, LeanXmssSignature, MESSAGE_LEN, PUB_KEY_SIZE,
    SECRET_KEY_LEN, SIG_SIZE,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

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

const VRF_SECRET_DOMAIN: &[u8; 10] = b"VRF_SECRET";
const VRF_LEAF_DOMAIN: &[u8; 8] = b"VRF_LEAF";

/// The secret of slot `index` of the VRF tree of `seed`:
/// `keccak256("VRF_SECRET" | seed | index as 8 little-endian bytes)`.
fn vrf_secret(seed: &[u8; 32], index: u64) -> [u8; 32] {
    let mut data = [0u8; 10 + 32 + 8];
    data[..10].copy_from_slice(VRF_SECRET_DOMAIN);
    data[10..42].copy_from_slice(seed);
    data[42..].copy_from_slice(&index.to_le_bytes());
    keccak256::hash(&data)
}

/// Leaf `index` of a VRF tree, which commits to the `secret` of that slot:
/// `keccak256("VRF_LEAF" | secret | index as 8 little-endian bytes)`.
fn vrf_leaf(secret: &[u8; 32], index: u64) -> [u8; 32] {
    let mut data = [0u8; 8 + 32 + 8];
    data[..8].copy_from_slice(VRF_LEAF_DOMAIN);
    data[8..40].copy_from_slice(secret);
    data[40..].copy_from_slice(&index.to_le_bytes());
    keccak256::hash(&data)
}

/// The root of the subtree of `VRF_SUBTREE_LEAVES` leaves that starts at leaf
/// `first` of the VRF tree of `seed`: a node is `keccak256(left | right)`.
fn vrf_subtree_root(seed: &[u8; 32], first: u64) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = (first..first + VRF_SUBTREE_LEAVES)
        .map(|i| vrf_leaf(&vrf_secret(seed, i), i))
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

// ----------------------------------------------------------------------------
// Aggregates

/// The thread count the prover pool started with, and whether it started.
static PROVER: OnceLock<(usize, bool)> = OnceLock::new();

/// Starts the prover pool with `threads` threads (0: one per physical core)
/// and builds the aggregation program, once per process: later calls say
/// whether it runs with that many threads.
fn prover_setup(threads: usize) -> bool {
    let (running, started) =
        *PROVER.get_or_init(|| (threads, catch_unwind(|| lean_vm::setup(threads)).is_ok()));
    started && running == threads
}

/// The prover as it runs, started with one thread per physical core if
/// `leanvm_setup` was not called.
fn prover_ready() -> bool {
    PROVER.get_or_init(|| (0, catch_unwind(|| lean_vm::setup(0)).is_ok())).1
}

/// Starts the prover and verifier of aggregates with `threads` threads (0:
/// one per physical core). Returns 1 when they run with that many threads, 0
/// when they could not be started or run with another number.
#[unsafe(no_mangle)]
pub extern "C" fn leanvm_setup(threads: usize) -> i32 {
    i32::from(prover_setup(threads))
}

/// The version of the proof system: proofs of another version do not verify.
#[unsafe(no_mangle)]
pub extern "C" fn leanvm_protocol_version() -> u32 {
    lean_vm::PROTOCOL_VERSION
}

/// The most children that one `leanvm_aggregate` call takes.
#[unsafe(no_mangle)]
pub extern "C" fn leanvm_max_children() -> usize {
    lean_vm::MAX_RECURSIONS
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len)?;
        self.0 = tail;
        Some(head)
    }

    fn count(&mut self) -> Option<usize> {
        let bytes: [u8; 8] = self.take(8)?.try_into().ok()?;
        usize::try_from(u64::from_le_bytes(bytes)).ok()
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.count()?;
        self.take(len)
    }
}

type RawXmss = (LeanXmssPublicKey, lean_xmss::Message, LeanXmssSignature);

fn read_aggregate_request(
    request: &[u8],
) -> Option<(Vec<(AggregateClaims, AggregateProof)>, Vec<RawXmss>)> {
    let mut reader = Reader(request);
    let mut children = Vec::new();
    for _ in 0..reader.count()? {
        let claims = AggregateClaims::from_bytes(reader.bytes()?)?;
        let proof = AggregateProof::from_bytes(reader.bytes()?)?;
        children.push((claims, proof));
    }
    let mut raw = Vec::new();
    for _ in 0..reader.count()? {
        let public_key: &[u8; PUB_KEY_SIZE] = reader.take(PUB_KEY_SIZE)?.try_into().ok()?;
        let message: lean_xmss::Message = reader.take(MESSAGE_LEN)?.try_into().ok()?;
        let signature: &[u8; SIG_SIZE] = reader.take(SIG_SIZE)?.try_into().ok()?;
        raw.push((
            LeanXmssPublicKey::from_bytes(public_key),
            message,
            LeanXmssSignature::from_bytes(signature),
        ));
    }
    reader.0.is_empty().then_some((children, raw))
}

fn aggregate(request: &[u8], expected_claims: &[u8], log_inv_rate: usize) -> Result<Vec<u8>, String> {
    if !(lean_vm::MIN_LOG_INV_RATE..=lean_vm::MAX_LOG_INV_RATE).contains(&log_inv_rate) {
        return Err("proof rate out of range".into());
    }
    if !prover_ready() {
        return Err("the prover could not be started".into());
    }
    let (children, raw) =
        read_aggregate_request(request).ok_or("malformed request, claims or child proof")?;
    let (claims, proof) =
        lean_vm::aggregate(&children, raw, vec![], None, OutputClaims::All, log_inv_rate)
            .map_err(|error| error.to_string())?;
    if claims.to_bytes() != expected_claims {
        return Err(format!(
            "proved {} claims, which are not the claims asked for",
            claims.num_signature_claims()
        ));
    }
    Ok(proof.to_bytes())
}

/// Proves signatures and child aggregates together as one aggregate. The
/// call takes seconds, during which the prover works on its own threads; a
/// second call waits for the first.
///
/// `request` is, with every count and length as 8 little-endian bytes: the
/// number of children and, per child, the length and bytes of its claims and
/// the length and bytes of its proof; then the number of signatures and, per
/// signature, the public key (32 bytes), the message (32) and the signature
/// (2404). Claims are in the encoding of `leanvm_verify`. The proof has to
/// prove exactly `expected_claims`.
///
/// Returns 1 with the proof in `out`, or 0 with the reason as text. Free
/// `out` with `leanvm_free`.
///
/// # Safety
/// `request` and `expected_claims` must be readable for their lengths, and
/// `out` and `out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanvm_aggregate(
    request: *const u8,
    request_len: usize,
    expected_claims: *const u8,
    expected_claims_len: usize,
    log_inv_rate: u8,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if request.is_null() || expected_claims.is_null() || out.is_null() || out_len.is_null() {
        return 0;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let expected_claims =
        unsafe { std::slice::from_raw_parts(expected_claims, expected_claims_len) };
    let result = catch_unwind(|| aggregate(request, expected_claims, usize::from(log_inv_rate)))
        .unwrap_or_else(|_| Err("the prover panicked".into()));
    let (status, bytes) = match result {
        Ok(proof) => (1, proof),
        Err(reason) => (0, reason.into_bytes()),
    };
    let bytes = bytes.into_boxed_slice();
    unsafe {
        *out_len = bytes.len();
        *out = Box::into_raw(bytes) as *mut u8;
    }
    status
}

/// Frees a buffer from `leanvm_aggregate`. Null is ignored.
///
/// # Safety
/// `data` and `len` must come from `leanvm_aggregate` and not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanvm_free(data: *mut u8, len: usize) {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, len)) });
    }
}

/// Whether `proof` proves exactly `claims`: the number of leanXMSS claims as
/// 8 little-endian bytes, each claim as a public key (32 bytes) and a message
/// (32), strictly sorted, then 9 zero bytes (no leanSPHINCS claims, no data
/// commitment). Returns 1 if it does, 0 if not, -1 when that cannot be told.
///
/// # Safety
/// `claims` and `proof` must be readable for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanvm_verify(
    claims: *const u8,
    claims_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    if claims.is_null() || proof.is_null() {
        return 0;
    }
    let claims = unsafe { std::slice::from_raw_parts(claims, claims_len) };
    let proof = unsafe { std::slice::from_raw_parts(proof, proof_len) };
    match catch_unwind(|| {
        if !prover_ready() {
            return -1;
        }
        let Some(claims) = AggregateClaims::from_bytes(claims) else {
            return 0;
        };
        i32::from(AggregateProof::from_bytes(proof).is_some_and(|proof| proof.verify(&claims)))
    }) {
        Ok(verdict) => verdict,
        Err(_) => -1,
    }
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

    #[test]
    fn vrf_leaves_commit_to_secrets() {
        let seed = [9u8; 32];
        let secret = vrf_secret(&seed, 5);
        let mut data = b"VRF_SECRET".to_vec();
        data.extend_from_slice(&seed);
        data.extend_from_slice(&5u64.to_le_bytes());
        assert_eq!(secret, keccak256::hash(&data));
        let mut data = b"VRF_LEAF".to_vec();
        data.extend_from_slice(&secret);
        data.extend_from_slice(&5u64.to_le_bytes());
        assert_eq!(vrf_leaf(&secret, 5), keccak256::hash(&data));
        // The same tree as leanVM's
        let key = lean_vm::lean_vrf::VrfKey::new(seed, 0..1024).unwrap();
        let proof = key.proof(5).unwrap();
        assert_eq!(proof[0], secret);
        assert_eq!(proof[1], vrf_leaf(&vrf_secret(&seed, 4), 4));
        let mut node = vrf_subtree_root(&seed, 0);
        let mut other = vrf_leaf(&secret, 5);
        for (height, sibling) in proof[1..].iter().enumerate() {
            other = if (5 >> height) & 1 == 1 {
                keccak256::hash_pair(sibling, &other)
            } else {
                keccak256::hash_pair(&other, sibling)
            };
            if height == 9 {
                assert_eq!(other, node);
            }
            if height >= 10 {
                node = keccak256::hash_pair(&node, sibling);
            }
        }
        assert_eq!(node, key.root());
        assert_eq!(other, key.root());
    }

    fn claims(claims: &[([u8; 32], [u8; 32])]) -> Vec<u8> {
        let mut sorted = claims.to_vec();
        sorted.sort_unstable();
        let mut out = (sorted.len() as u64).to_le_bytes().to_vec();
        for (pubkey, message) in sorted {
            out.extend_from_slice(&pubkey);
            out.extend_from_slice(&message);
        }
        out.extend_from_slice(&[0u8; 9]);
        out
    }

    fn run_aggregate(request: &[u8], expected: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = std::ptr::null_mut();
        let mut out_len = 0usize;
        let status = unsafe {
            leanvm_aggregate(
                request.as_ptr(),
                request.len(),
                expected.as_ptr(),
                expected.len(),
                2,
                &mut out,
                &mut out_len,
            )
        };
        let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
        unsafe { leanvm_free(out, out_len) };
        if status == 1 { Ok(bytes) } else { Err(String::from_utf8(bytes).unwrap()) }
    }

    fn verify(claims: &[u8], proof: &[u8]) -> i32 {
        unsafe { leanvm_verify(claims.as_ptr(), claims.len(), proof.as_ptr(), proof.len()) }
    }

    #[test]
    fn aggregates_are_proven_merged_and_verified() {
        assert_eq!(leanvm_setup(0), 1);
        assert_eq!(leanvm_setup(0), 1);
        assert_eq!(leanvm_setup(1), 0);
        assert_eq!(leanvm_max_children(), 16);

        let (key, pubkey) = key_gen(&[10; 32]);
        let mut children = Vec::new();
        for message in [[1u8; 32], [2u8; 32]] {
            let signature = sign(key, &message, ATTESTATION_LEAF + 1);
            let mut request = 0u64.to_le_bytes().to_vec();
            request.extend_from_slice(&1u64.to_le_bytes());
            request.extend_from_slice(&pubkey);
            request.extend_from_slice(&message);
            request.extend_from_slice(&signature);
            let expected = claims(&[(pubkey, message)]);
            let proof = run_aggregate(&request, &expected).unwrap();
            assert_eq!(verify(&expected, &proof), 1);
            assert_eq!(verify(&claims(&[(pubkey, [3; 32])]), &proof), 0);
            // Other claims than those the signatures give
            assert!(run_aggregate(&request, &claims(&[(pubkey, [3; 32])])).is_err());
            children.push((expected, proof));
        }

        let mut request = 2u64.to_le_bytes().to_vec();
        for (claims, proof) in &children {
            request.extend_from_slice(&(claims.len() as u64).to_le_bytes());
            request.extend_from_slice(claims);
            request.extend_from_slice(&(proof.len() as u64).to_le_bytes());
            request.extend_from_slice(proof);
        }
        request.extend_from_slice(&0u64.to_le_bytes());
        let both = claims(&[(pubkey, [1; 32]), (pubkey, [2; 32])]);
        let merged = run_aggregate(&request, &both).unwrap();
        assert_eq!(verify(&both, &merged), 1);
        assert_eq!(verify(&children[0].0, &merged), 0);
        assert_eq!(verify(&both, &[0xff; 64]), 0);
        assert_eq!(verify(&both[..both.len() - 1], &merged), 0);

        assert!(run_aggregate(&request[..request.len() - 1], &both).is_err());
        assert!(run_aggregate(&[], &both).is_err());
        unsafe { leanxmss_key_free(key) };
    }
}
