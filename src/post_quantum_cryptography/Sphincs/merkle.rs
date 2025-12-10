//! Merkle auth path over WOTS public keys. Pedagogical build/verify.

use super::hash::h_n;
use super::params::{MERKLE_HEIGHT, N};

fn parent(l: &[u8; N], r: &[u8; N]) -> [u8; N] {
    h_n(&[l, r], N)
}

pub fn merkle_gen_auth(leaves: &[[u8; N]], leaf_idx: usize) -> (Vec<[u8; N]>, [u8; N]) {
    // Build tree and produce auth path from leaf_idx to root.
    let mut level = leaves.to_vec();
    let mut path = Vec::with_capacity(MERKLE_HEIGHT);
    let mut idx = leaf_idx;
    for _h in 0..MERKLE_HEIGHT {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for i in (0..level.len()).step_by(2) {
            let l = level[i];
            let r = if i + 1 < level.len() { level[i + 1] } else { l };
            let p = parent(&l, &r);
            next.push(p);
            if i / 2 == idx / 2 {
                let sibling = if idx % 2 == 0 { r } else { l };
                path.push(sibling);
            }
        }
        level = next;
        idx /= 2;
    }
    let root = level[0];
    (path, root)
}

pub fn merkle_verify(leaf_hash: &[u8; N], auth_path: &[[u8; N]], leaf_idx: usize) -> [u8; N] {
    let mut node = *leaf_hash;
    let mut idx = leaf_idx;
    for s in auth_path {
        node = if idx % 2 == 0 {
            h_n(&[&node, s], N)
        } else {
            h_n(&[s, &node], N)
        };
        idx /= 2;
    }
    node
}
