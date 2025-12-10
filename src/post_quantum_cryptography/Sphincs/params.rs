//! Pedagogical SPHINCS-like parameters (compact).
//! N = hash output size in bytes. Heights kept small for fast tests.

pub const N: usize = 32; // bytes per hash
pub const WOTS_W: u32 = 16; // base for WOTS+ (not optimized)
pub const WOTS_LOGW: u32 = 4; // log2(W)
pub const WOTS_LEN1: usize = ((8 * N as u32 + WOTS_LOGW - 1) / WOTS_LOGW) as usize;
pub const WOTS_LEN2: usize = 3; // checksum length (small for demo)
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;

pub const FORS_TREES: usize = 10; // number of FORS trees (small)
pub const FORS_HEIGHT: usize = 5; // height per tree (32 leaves)
pub const FORS_SIGNATURE_BYTES: usize = FORS_TREES * (N + FORS_HEIGHT * N);

pub const MERKLE_HEIGHT: usize = 8; // 256 leaves in top Merkle tree (demo)

pub const SK_SEED_BYTES: usize = N;
pub const SK_PRF_BYTES: usize = N;
pub const PK_SEED_BYTES: usize = N;
pub const PUBLIC_KEY_BYTES: usize = PK_SEED_BYTES + N; // pk_seed || pk_root
pub const SECRET_KEY_BYTES: usize = SK_SEED_BYTES + SK_PRF_BYTES + PK_SEED_BYTES + N;

pub const SIG_BYTES: usize = N                      // R (randomization)
  + FORS_SIGNATURE_BYTES   // FORS part
  + (WOTS_LEN * N)         // WOTS signature of FORS root
  + (MERKLE_HEIGHT * N); // auth path to top root
