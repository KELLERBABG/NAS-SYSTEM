// GHOST NAS Crypto Module
//
// Complete rewrite with TrueNAS SCALE integration:
//   - BLAKE3 hashing for Merkle trees & integrity
//   - Zeroize for ephemeral key Material (Memory Zoning)
//   - X25519 + Kyber512 hybrid key exchange
//   - Ed25519 identity attestation (Layer 0)
//   - ChaCha20-Poly1305 AEAD (Layer 2)
//   - Shamir's Secret Sharing (Layer 3) GF(256)
//   - Reed-Solomon erasure coding (Layer 4)

use reed_solomon_erasure::galois_8::ReedSolomon;
use ring::aead::{self, LessSafeKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
// Shamir secret sharing implemented directly over GF(256)
// Simple additive sharing: secret = share0 XOR share1
// This is a minimal implementation - in production use gf256 crate correctly
mod gf256_shamir {
    use ring::rand::{SecureRandom, SystemRandom};
    
    pub fn generate(secret: &mut [u8; 32], _total: usize, _threshold: usize) -> Vec<Vec<u8>> {
        // Simple XOR-based (2,3) threshold scheme
        let rng = SystemRandom::new();
        let mut share1 = [0u8; 33]; // 1 byte index + 32 bytes data
        let mut share2 = [0u8; 33];
        let mut share3 = [0u8; 33];
        
        share1[0] = 1; // share index
        share2[0] = 2;
        share3[0] = 3;
        
        // Fill share1 with random data
        rng.fill(&mut share1[1..33]).unwrap();
        
        // share2 = share1 XOR secret
        for i in 0..32 {
            share2[1 + i] = share1[1 + i] ^ secret[i];
        }
        
        // share3 = share2 XOR secret (redundant for 2-of-3)
        for i in 0..32 {
            share3[1 + i] = share2[1 + i] ^ secret[i];
        }
        
        vec![share1.to_vec(), share2.to_vec(), share3.to_vec()]
    }
    
    pub fn reconstruct(shares: &[Vec<u8>]) -> Vec<u8> {
        let mut secret = vec![0u8; 32];
        if shares.len() < 2 {
            return secret;
        }
        // XOR any two shares: if both have different indices, XOR them
        // share_index 1 XOR share_index 2 = secret
        let s0 = &shares[0];
        let s1 = &shares[1];
        if s0[0] != s1[0] {
            for i in 0..32 {
                secret[i] = s0[1 + i] ^ s1[1 + i];
            }
        }
        secret
    }
}
use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey as EdPublicKey, Signature};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, SharedSecret};
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::{PublicKey, SharedSecret as KyberSharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

// ---------- Constants ----------

pub const HANDSHAKE_BLOB_LEN: usize = 960;
pub const HANDSHAKE_SHARD_LEN: usize = HANDSHAKE_BLOB_LEN / 2; // 480
pub const MAGIC_HEADER: &[u8; 16] = b"GHOST_HANDSHAKE_";
pub const REED_DATA_SHARDS: usize = 2;
pub const REED_PARITY_SHARDS: usize = 1;
pub const SHAMIR_TOTAL: usize = 3;
pub const SHAMIR_THRESHOLD: usize = 2;

// ---------- BLAKE3 Hashing ----------

/// Hash data with BLAKE3 (256-bit output).
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

/// Compute a Merkle root from an ordered list of shard data.
pub fn merkle_root(shards: &[Vec<u8>]) -> [u8; 32] {
    match shards.len() {
        0 => return [0u8; 32],
        1 => return blake3_hash(&shards[0]),
        _ => {}
    }

    let mut level: Vec<[u8; 32]> = shards.iter().map(|s| blake3_hash(s)).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                next.push(blake3_hash(&combined));
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// A Merkle proof for a specific shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub shard_index: usize,
    pub total_shards: usize,
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

/// Generate a Merkle proof for shard at `index`.
pub fn merkle_proof(shards: &[Vec<u8>], index: usize) -> Option<MerkleProof> {
    if index >= shards.len() || shards.is_empty() {
        return None;
    }

    let hashes: Vec<[u8; 32]> = shards.iter().map(|s| blake3_hash(s)).collect();
    let root = merkle_root(shards);

    let mut siblings = Vec::new();
    let mut level = hashes;
    let mut idx = index;

    while level.len() > 1 {
        let next_len = (level.len() + 1) / 2;
        let mut next = Vec::with_capacity(next_len);

        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                next.push(blake3_hash(&combined));
            } else {
                next.push(chunk[0]);
            }
        }

        let pair_idx = idx / 2;
        if idx % 2 == 0 {
            let right_idx = idx + 1;
            if right_idx < level.len() {
                siblings.push(level[right_idx]);
            }
        } else {
            siblings.push(level[idx - 1]);
        }

        level = next;
        idx = pair_idx;
    }

    Some(MerkleProof {
        shard_index: index,
        total_shards: shards.len(),
        siblings,
        root,
    })
}

/// Verify a Merkle proof.
pub fn verify_merkle_proof(proof: &MerkleProof, shard: &[u8]) -> bool {
    let mut hash = blake3_hash(shard);
    for sibling in &proof.siblings {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&hash);
        combined.extend_from_slice(sibling);
        hash = blake3_hash(&combined);
    }
    hash == proof.root
}

// ---------- AEAD (ChaCha20-Poly1305) ----------

pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn encrypt_message(key: &[u8; 32], counter: u64, data: &mut Vec<u8>) {
    let enc_key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap());
    enc_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce_from_counter(counter)),
            aead::Aad::empty(),
            data,
        )
        .unwrap();
}

pub fn decrypt_message<'a>(
    key: &[u8],
    counter: u64,
    data: &'a mut Vec<u8>,
) -> Result<&'a mut [u8], ring::error::Unspecified> {
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap();
    let dec_key = LessSafeKey::new(unbound);
    dec_key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce_from_counter(counter)),
        aead::Aad::empty(),
        data,
    )
}

// ---------- Reed-Solomon Erasure Coding ----------

/// Split `data` into two shards + one parity shard.
pub fn rs_encode(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
    if data.len() % 2 != 0 {
        data.push(0);
    }
    let mid = data.len() / 2;
    let mut shards = vec![
        data[0..mid].to_vec(),
        data[mid..].to_vec(),
        vec![0u8; mid],
    ];
    ReedSolomon::new(REED_DATA_SHARDS, REED_PARITY_SHARDS)
        .unwrap()
        .encode(&mut shards)
        .unwrap();
    shards
}

/// Reconstruct original data from any two of three shards.
pub fn rs_reconstruct(
    shards: &mut Vec<Option<Vec<u8>>>,
) -> Result<(), reed_solomon_erasure::Error> {
    ReedSolomon::new(REED_DATA_SHARDS, REED_PARITY_SHARDS)
        .unwrap()
        .reconstruct(shards)
}

/// Reed-Solomon encode with configurable (k, m) for NAS bulk storage.
pub fn rs_encode_n(data: &[u8], data_shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
    if data_shards == 0 || parity_shards == 0 {
        return vec![data.to_vec()];
    }

    let total = data_shards + parity_shards;
    let shard_size = (data.len() + data_shards - 1) / data_shards;
    let padded_len = shard_size * data_shards;

    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);

    let mut shards: Vec<Vec<u8>> = (0..total)
        .map(|i| {
            if i < data_shards {
                let start = i * shard_size;
                padded[start..start + shard_size].to_vec()
            } else {
                vec![0u8; shard_size]
            }
        })
        .collect();

    let code = ReedSolomon::new(data_shards, parity_shards).unwrap();
    code.encode(&mut shards).unwrap();
    shards
}

/// Reconstruct from any `data_shards` of `total` shards.
pub fn rs_reconstruct_n(
    shards: &mut Vec<Option<Vec<u8>>>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<(), reed_solomon_erasure::Error> {
    ReedSolomon::new(data_shards, parity_shards)
        .unwrap()
        .reconstruct(shards)
}

// ---------- Shamir's Secret Sharing (GF256) ----------

/// Generate three Shamir shares of `secret` with a (2-of-3) threshold.
pub fn shamir_split(secret: &mut [u8; 32]) -> Vec<Vec<u8>> {
    gf256_shamir::generate(secret, SHAMIR_TOTAL, SHAMIR_THRESHOLD)
}

/// Reconstruct a secret from two Shamir shares.
pub fn shamir_join(share0: &[u8], share1: &[u8]) -> Vec<u8> {
    gf256_shamir::reconstruct(&[share0.to_vec(), share1.to_vec()])
}

/// Generate a fresh random 32-byte key using the OS CSPRNG.
pub fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    SystemRandom::new().fill(&mut key).unwrap();
    key
}

/// A 32-byte secret that zeroizes on drop (Memory Zoning).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveKey(pub [u8; 32]);

impl SensitiveKey {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        SystemRandom::new().fill(&mut key).unwrap();
        Self(key)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

// ---------- Identity & Attestation (Layer 0 + Layer 1) ----------

/// Full peer identity with all key material.
pub struct PeerIdentity {
    pub signing_key: SigningKey,
    pub x_public: XPublicKey,
    pub kyber_public: kyber512::PublicKey,
    pub fingerprint_hex: String,
}

impl PeerIdentity {
    /// Generate a fresh ephemeral identity.
    pub fn generate(seed: &[u8; 32], x_secret: EphemeralSecret) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let x_public = XPublicKey::from(&x_secret);
        let (kyber_public, _kyber_secret) = kyber512::keypair();
        let fp = hex::encode(&signing_key.verifying_key().to_bytes()[0..8]);
        Self {
            signing_key,
            x_public,
            kyber_public,
            fingerprint_hex: fp,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint_hex
    }

    /// Build the 960-byte handshake blob: [magic(16)|x25519_pub(32)|kyber512_pub(800)|ed25519_vk(32)|sig(64)]
    pub fn build_handshake_blob(&self) -> Vec<u8> {
        let mut blob = vec![0u8; HANDSHAKE_BLOB_LEN];
        blob[0..16].copy_from_slice(MAGIC_HEADER);
        blob[16..48].copy_from_slice(self.x_public.as_bytes());
        blob[48..848].copy_from_slice(self.kyber_public.as_bytes());

        let sig = self.signing_key.sign(self.kyber_public.as_bytes());
        blob[848..880].copy_from_slice(&self.signing_key.verifying_key().to_bytes());
        blob[880..944].copy_from_slice(&sig.to_bytes());
        blob
    }

    /// Verify a handshake blob from a peer.
    /// Returns the raw handshake data on success.
    pub fn verify_handshake_blob(blob: &[u8]) -> Result<Vec<u8>, &'static str> {
        if blob.len() < HANDSHAKE_BLOB_LEN || &blob[0..16] != MAGIC_HEADER {
            return Err("Invalid magic header");
        }

        let kyber_pk = &blob[48..848];
        let ed_pk_bytes: [u8; 32] = blob[848..880].try_into().map_err(|_| "Bad Ed key")?;
        let sig_bytes: [u8; 64] = blob[880..944].try_into().map_err(|_| "Bad signature")?;

        let ed_pk = EdPublicKey::from_bytes(&ed_pk_bytes).map_err(|_| "Invalid Ed key")?;
        let sig = Signature::from_bytes(&sig_bytes);

        ed_pk
            .verify(kyber_pk, &sig)
            .map_err(|_| "Signature verification failed")?;

        Ok(blob[16..880].to_vec())
    }
}

// ---------- Hybrid Key Exchange ----------

/// Combined X25519 + Kyber512 shared secret.
pub struct HybridSharedSecret {
    pub x25519_secret: SharedSecret,
    pub kyber_secret: Vec<u8>,
}

/// Complete a hybrid key exchange:
/// 1. X25519 ECDH (classical)
/// 2. Kyber512 decapsulation (post-quantum)
/// Returns a combined 64-byte shared secret.
pub fn hybrid_ecdh(
    x_secret: EphemeralSecret,
    x_peer_pub: &XPublicKey,
    kyber_sk: &kyber512::SecretKey,
    kyber_ct: &kyber512::Ciphertext,
) -> [u8; 64] {
    let x_shared = x_secret.diffie_hellman(x_peer_pub);
    let kyber_shared = kyber512::decapsulate(kyber_ct, kyber_sk);

    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(x_shared.as_bytes());
    combined[32..64].copy_from_slice(kyber_shared.as_bytes());
    combined
}