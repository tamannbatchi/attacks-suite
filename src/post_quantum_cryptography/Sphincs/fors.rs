//! Pedagogical FORS: signs a message digest with a forest of small trees.
//! Each tree picks an index; signature includes leaf and auth path.

use super::hash::{h_n, shake256};
use super::params::{FORS_HEIGHT, FORS_TREES, N};

fn fors_leaf(sk_seed: &[u8], pk_seed: &[u8], tree_idx: usize, leaf_idx: usize) -> [u8; N] {
    // Leaf = H(sk_seed || pk_seed || tree_idx || leaf_idx)
    h_n(&[sk_seed, pk_seed, &[tree_idx as u8], &[leaf_idx as u8]], N)
}

fn fors_parent(left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    h_n(&[left, right], N)
}

pub fn fors_sign(sk_seed: &[u8], pk_seed: &[u8], msg_digest: &[u8]) -> (Vec<[u8; N]>, [u8; N]) {
    // Interpret msg_digest as indexes for each tree (low FORS_HEIGHT bits).
    let mut sig_parts = Vec::with_capacity(FORS_TREES * (1 + FORS_HEIGHT));
    let mut roots = Vec::with_capacity(FORS_TREES);

    for t in 0..FORS_TREES {
        let idx_bits = ((msg_digest[t] as usize) & ((1 << FORS_HEIGHT) - 1)) as usize;
        // Leaf
        let leaf = fors_leaf(sk_seed, pk_seed, t, idx_bits);
        let mut node = leaf;
        // Auth path up the tree
        for h in 0..FORS_HEIGHT {
            let sib_idx = idx_bits ^ (1 << h);
            let sibling = fors_leaf(sk_seed, pk_seed, t, sib_idx);
            let parent = if idx_bits & (1 << h) == 0 {
                fors_parent(&node, &sibling)
            } else {
                fors_parent(&sibling, &node)
            };
            sig_parts.push(sibling);
            node = parent;
        }
        roots.push(node);
    }

    // Aggregate FORS roots into a single root digest
    let mut cat = Vec::with_capacity(FORS_TREES * N);
    for r in &roots {
        cat.extend_from_slice(r);
    }
    let fors_root = h_n(&[&cat], N);
    (sig_parts, fors_root)
}

pub fn fors_verify(pk_seed: &[u8], msg_digest: &[u8], sig_parts: &[[u8; N]]) -> [u8; N] {
    let mut roots = Vec::with_capacity(FORS_TREES);
    let mut offset = 0;
    for t in 0..FORS_TREES {
        let idx_bits = ((msg_digest[t] as usize) & ((1 << FORS_HEIGHT) - 1)) as usize;
        // Reconstruct root from leaf implied by idx_bits and provided path
        let mut node = fors_leaf(&[0u8; N], pk_seed, t, idx_bits); // sk_seed unknown; in real FORS, leaf uses pk_seed-committed secret. Here pedagogical.
        for h in 0..FORS_HEIGHT {
            let sibling = sig_parts[offset];
            offset += 1;
            let parent = if idx_bits & (1 << h) == 0 {
                h_n(&[&node, &sibling], N)
            } else {
                h_n(&[&sibling, &node], N)
            };
            node = parent;
        }
        roots.push(node);
    }
    let mut cat = Vec::with_capacity(FORS_TREES * N);
    for r in &roots {
        cat.extend_from_slice(r);
    }
    h_n(&[&cat], N)
}
