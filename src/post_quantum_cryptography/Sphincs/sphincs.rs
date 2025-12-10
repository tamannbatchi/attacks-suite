// Pedagogical SPHINCS-like K: single Merkle layer, FORS + WOTS over the FORS root.
// Signature: R || FORS_sig || WOTS_sig || Merkle_auth.

use super::fors::{fors_sign, fors_verify};
use super::hash::{h_n, prf, shake256};
use super::merkle::{merkle_gen_auth, merkle_verify};
use super::params::{MERKLE_HEIGHT, N, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIG_BYTES, WOTS_LEN};
use super::wots::{wots_pk, wots_pk_hash, wots_sign, wots_verify};
use rand::{rngs::OsRng, RngCore};

pub struct PublicKey {
    pub bytes: Vec<u8>,
} // pk_seed || pk_root
pub struct SecretKey {
    pub bytes: Vec<u8>,
} // sk_seed || sk_prf || pk_seed || pk_root
pub struct Signature {
    pub bytes: Vec<u8>,
} // R || FORS || WOTS || auth path

fn random_n() -> [u8; N] {
    let mut x = [0u8; N];
    OsRng.fill_bytes(&mut x);
    x
}

pub fn keygen() -> (PublicKey, SecretKey) {
    // Seeds
    let sk_seed = random_n();
    let sk_prf = random_n();
    let pk_seed = random_n();

    // Build WOTS leaves (one WOTS pk per leaf index in top tree)
    let num_leaves = 1usize << MERKLE_HEIGHT;
    let mut leaves = Vec::with_capacity(num_leaves);
    for idx in 0..num_leaves {
        let addr = [(idx & 0xFF) as u8];
        let wpk = wots_pk(&sk_seed, &pk_seed, &addr);
        let leaf_hash = wots_pk_hash(&wpk);
        leaves.push(leaf_hash);
    }

    // Compute auth path for leaf 0 and tree root
    let (auth_path0, pk_root) = merkle_gen_auth(&leaves, 0);

    // Pack keys
    let mut pk_bytes = Vec::with_capacity(PUBLIC_KEY_BYTES);
    pk_bytes.extend_from_slice(&pk_seed);
    pk_bytes.extend_from_slice(&pk_root);

    let mut sk_bytes = Vec::with_capacity(SECRET_KEY_BYTES);
    sk_bytes.extend_from_slice(&sk_seed);
    sk_bytes.extend_from_slice(&sk_prf);
    sk_bytes.extend_from_slice(&pk_seed);
    sk_bytes.extend_from_slice(&pk_root);

    (PublicKey { bytes: pk_bytes }, SecretKey { bytes: sk_bytes })
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    // Unpack SK
    let sk_seed = &sk.bytes[0..N];
    let sk_prf = &sk.bytes[N..2 * N];
    let pk_seed = &sk.bytes[2 * N..3 * N];
    let pk_root = &sk.bytes[3 * N..4 * N];

    // Randomization R = PRF(sk_prf, msg)
    let r = prf(sk_prf, msg, N);

    // Digest used by FORS
    let md = shake256(N, &[&r, msg, pk_seed, pk_root]);

    // FORS signature + FORS root
    let (fors_sig_parts, fors_root) = fors_sign(sk_seed, pk_seed, &md);

    // WOTS sign the FORS root on leaf index 0 (single leaf for demo)
    let addr0 = [0u8];
    let wots_sig = wots_sign(sk_seed, pk_seed, &addr0, &fors_root);

    // Merkle auth path for leaf 0 (recompute leaves for path)
    let num_leaves = 1usize << MERKLE_HEIGHT;
    let mut leaves = Vec::with_capacity(num_leaves);
    for idx in 0..num_leaves {
        let addr = [(idx & 0xFF) as u8];
        let wpk = wots_pk(sk_seed, pk_seed, &addr);
        let leaf_hash = wots_pk_hash(&wpk);
        leaves.push(leaf_hash);
    }
    let (auth_path, _root_check) = merkle_gen_auth(&leaves, 0);

    // Pack signature: R || FORS || WOTS || auth
    let mut sig = Vec::with_capacity(SIG_BYTES);
    sig.extend_from_slice(&r);
    for s in &fors_sig_parts {
        sig.extend_from_slice(s);
    }
    for s in &wots_sig {
        sig.extend_from_slice(s);
    }
    for a in &auth_path {
        sig.extend_from_slice(a);
    }

    Signature { bytes: sig }
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    // Unpack PK
    let pk_seed = &pk.bytes[0..N];
    let pk_root = &pk.bytes[N..2 * N];

    // Unpack signature
    let r = &sig.bytes[0..N];
    let mut offset = N;

    // FORS part
    let fors_count = super::params::FORS_TREES * super::params::FORS_HEIGHT;
    let mut fors_sig_parts = Vec::with_capacity(fors_count);
    for _ in 0..fors_count {
        let mut nbytes = [0u8; N];
        nbytes.copy_from_slice(&sig.bytes[offset..offset + N]);
        fors_sig_parts.push(nbytes);
        offset += N;
    }

    // WOTS signature
    let mut wots_sig = Vec::with_capacity(WOTS_LEN);
    for _ in 0..WOTS_LEN {
        let mut nbytes = [0u8; N];
        nbytes.copy_from_slice(&sig.bytes[offset..offset + N]);
        wots_sig.push(nbytes);
        offset += N;
    }

    // Merkle auth path
    let mut auth_path = Vec::with_capacity(MERKLE_HEIGHT);
    for _ in 0..MERKLE_HEIGHT {
        let mut nbytes = [0u8; N];
        nbytes.copy_from_slice(&sig.bytes[offset..offset + N]);
        auth_path.push(nbytes);
        offset += N;
    }

    // Recompute md
    let md = shake256(N, &[r, msg, pk_seed, pk_root]);

    // Recompute FORS root
    let fors_root = fors_verify(pk_seed, &md, &fors_sig_parts);

    // Recompute WOTS public key from signature and message digest
    let addr0 = [0u8];
    let wots_pk_rec = wots_verify(pk_seed, &addr0, &fors_root, &wots_sig);
    let leaf_hash = wots_pk_hash(&wots_pk_rec);

    // Verify Merkle path to pk_root
    let root = merkle_verify(&leaf_hash, &auth_path, 0);
    root.as_ref() == pk_root
}
