//! Encrypted Directory Tree
//!
//! Maps file paths to shard group IDs with all filenames and directory
//! structures encrypted using the Ed25519-derived directory key.
//!
//! On disk: `shards/<blake3_hash>/shard_NNN.bin` — no plaintext names anywhere.
//! The directory tree is stored as a single encrypted JSON blob at
//! `/mnt/tank/ghost-vault/.meta/directory.enc` — sealed with an AEAD key
//! derived from the node's Ed25519 identity.
//!
//! Without the identity key, an attacker sees only noise on the ZFS dataset.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::fs;
use ring::aead::{self, LessSafeKey, UnboundKey, Aad, Nonce};
use ring::rand::{SecureRandom, SystemRandom};

#[derive(Error, Debug)]
pub enum DirectoryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Encryption error: {0}")]
    Crypto(String),
    #[error("Path not found: {0}")]
    PathNotFound(String),
    #[error("Path already exists: {0}")]
    PathExists(String),
}

/// Metadata for a single file in the NAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Original plaintext filename (only stored in-memory after decryption)
    pub filename: String,
    /// Size in bytes
    pub size: u64,
    /// BLAKE3 hash of the plaintext file (for integrity verification)
    pub content_hash: [u8; 32],
    /// Number of blocks this file was split into
    pub block_count: usize,
    /// Shard group ID per block: block_index → group_id
    pub block_groups: Vec<String>,
    /// Creation timestamp (Unix nanos)
    pub created_at_ns: u64,
    /// Last modified timestamp (Unix nanos)
    pub modified_at_ns: u64,
    /// POSIX-style permissions octet (e.g. 0o644)
    pub mode: u32,
    /// Monotonic version counter for conflict resolution
    pub version: u64,
}

/// A directory node in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Original plaintext directory name
    pub dirname: String,
    /// Subdirectory names (encrypted on disk, decrypted in memory)
    pub subdirs: Vec<String>,
    /// File names in this directory
    pub files: Vec<FileEntry>,
    /// Creation timestamp
    pub created_at_ns: u64,
}

/// The full directory tree — serialized, encrypted, stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryTree {
    /// Root directory entries, keyed by directory name
    pub root: Vec<DirEntry>,
}

impl DirectoryTree {
    pub fn new() -> Self {
        Self { root: Vec::new() }
    }
}

/// The encrypted directory manager.
pub struct EncryptedDirectory {
    /// Path to the encrypted directory DB file
    db_path: PathBuf,
    /// In-memory decrypted directory tree
    tree: Arc<RwLock<DirectoryTree>>,
    /// AEAD key derived from the identity key
    crypto_key: [u8; 32],
}

impl EncryptedDirectory {
    /// Open or create the encrypted directory database.
    /// `identity_seed` is the 32-byte Ed25519 seed from which we derive
    /// the directory encryption key via BLAKE3.
    pub async fn open(
        db_path: &Path,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DirectoryError> {
        // Derive directory encryption key: blake3("ghost-dir-key" || seed)
        let dir_key = crate::crypto::blake3_hash(
            &[b"ghost-dir-key", identity_seed.as_slice()].concat()
        );

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let tree = if db_path.exists() {
            // Read and decrypt the directory DB
            let encrypted = fs::read(db_path).await?;
            match Self::decrypt_tree(&encrypted, &dir_key) {
                Ok(tree) => tree,
                Err(_) => {
                    tracing::warn!("Directory DB corrupted or key mismatch, starting fresh");
                    DirectoryTree::new()
                }
            }
        } else {
            DirectoryTree::new()
        };

        tracing::info!(
            "Encrypted directory opened at {} ({} root entries)",
            db_path.display(),
            tree.root.len()
        );

        Ok(Self {
            db_path: db_path.to_path_buf(),
            tree: Arc::new(RwLock::new(tree)),
            crypto_key: dir_key,
        })
    }

    /// Flush the in-memory tree to disk (encrypted).
    pub async fn flush(&self) -> Result<(), DirectoryError> {
        let tree = self.tree.read().await;
        let plaintext = serde_json::to_vec(&*tree)?;
        let encrypted = Self::encrypt_tree(&plaintext, &self.crypto_key)?;
        fs::write(&self.db_path, &encrypted).await?;
        tracing::debug!("Directory tree flushed to disk ({} bytes encrypted)", encrypted.len());
        Ok(())
    }

    /// Encrypt the serialized directory tree with AEAD.
    fn encrypt_tree(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, DirectoryError> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .map_err(|e| DirectoryError::Crypto(e.to_string()))?;

        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|e| DirectoryError::Crypto(e.to_string()))?;
        let enc_key = LessSafeKey::new(unbound);

        let mut ciphertext = plaintext.to_vec();
        enc_key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut ciphertext,
        )
        .map_err(|e| DirectoryError::Crypto(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt the directory tree from disk.
    fn decrypt_tree(encrypted: &[u8], key: &[u8; 32]) -> Result<DirectoryTree, DirectoryError> {
        if encrypted.len() < 12 {
            return Err(DirectoryError::Crypto("Truncated encrypted blob".into()));
        }

        let (nonce_bytes, ct) = encrypted.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);

        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key)
            .map_err(|e| DirectoryError::Crypto(e.to_string()))?;
        let dec_key = LessSafeKey::new(unbound);

        let mut ciphertext = ct.to_vec();
        let plaintext = dec_key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut ciphertext)
            .map_err(|_| DirectoryError::Crypto("Decryption failed".into()))?;

        serde_json::from_slice(plaintext)
            .map_err(|e| DirectoryError::Serde(e))
    }

    /// Resolve a path like "/documents/report.pdf" to its FileEntry.
    /// Returns None if the path doesn't exist.
    pub async fn resolve_path(&self, path: &str) -> Option<FileEntry> {
        let tree = self.tree.read().await;
        let normalized = path.trim_start_matches('/').trim_end_matches('/');

        if normalized.is_empty() {
            return None; // root is not a file
        }

        let parts: Vec<&str> = normalized.split('/').collect();
        if parts.is_empty() {
            return None;
        }

        let filename = parts.last().unwrap();
        let dir_parts = &parts[..parts.len() - 1];

        // Walk the directory tree
        let mut current_dir: Option<&DirEntry> = None;
        for part in dir_parts {
            let dirs = if let Some(d) = current_dir {
                // Search subdirs of current dir
                let target = d.subdirs.iter().find(|s| s == part)?.clone();
                // We need to find the DirEntry for this subdir
                // For simplicity, we search root-level dirs and nested
                // In a full implementation, subdirs would be stored recursively
                let candidates: Vec<&DirEntry> = tree.root.iter().filter(|d| d.dirname == *part).collect();
                if candidates.is_empty() {
                    return None;
                }
                candidates[0]
            } else {
                let candidates: Vec<&DirEntry> = tree.root.iter().filter(|d| d.dirname == *part).collect();
                if candidates.is_empty() {
                    return None;
                }
                candidates[0]
            };
            current_dir = Some(dirs);
        }

        // Search for the file in the target directory
        let dir = if let Some(d) = current_dir {
            d
        } else {
            // File is in root
            let candidates: Vec<&DirEntry> = tree.root.iter().filter(|d| {
                d.files.iter().any(|f| f.filename == *filename)
            }).collect();
            for d in &tree.root {
                for f in &d.files {
                    if f.filename == *filename {
                        return Some(f.clone());
                    }
                }
            }
            return None;
        };

        dir.files.iter().find(|f| f.filename == *filename).cloned()
    }

    /// Add a file entry to the directory tree.
    pub async fn add_file(&self, parent_dir: &str, entry: FileEntry) -> Result<(), DirectoryError> {
        let mut tree = self.tree.write().await;

        if parent_dir.is_empty() || parent_dir == "/" {
            // Add to root — find or create a root pseudo-dir for files without subdirs
            let existing = tree.root.iter_mut().find(|d| d.dirname == "_root");
            if let Some(d) = existing {
                d.files.push(entry);
            } else {
                tree.root.push(DirEntry {
                    dirname: "_root".into(),
                    subdirs: vec![],
                    files: vec![entry],
                    created_at_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                });
            }
        } else {
            let dirname = parent_dir.trim_start_matches('/').trim_end_matches('/');
            let existing = tree.root.iter_mut().find(|d| d.dirname == dirname);
            if let Some(d) = existing {
                // Check for duplicate
                if d.files.iter().any(|f| f.filename == entry.filename) {
                    return Err(DirectoryError::PathExists(entry.filename));
                }
                d.files.push(entry);
            } else {
                tree.root.push(DirEntry {
                    dirname: dirname.into(),
                    subdirs: vec![],
                    files: vec![entry],
                    created_at_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                });
            }
        }

        // Flush to disk
        drop(tree);
        self.flush().await?;
        Ok(())
    }

    /// Remove a file entry from the directory tree.
    pub async fn remove_file(&self, path: &str) -> Result<(), DirectoryError> {
        let mut tree = self.tree.write().await;
        let normalized = path.trim_start_matches('/').trim_end_matches('/');

        if normalized.is_empty() {
            return Err(DirectoryError::PathNotFound(path.into()));
        }

        let parts: Vec<&str> = normalized.split('/').collect();
        let filename = parts.last().unwrap();
        let dirname = if parts.len() > 1 { parts[0] } else { "_root" };

        let dir = tree.root.iter_mut().find(|d| d.dirname == dirname)
            .ok_or_else(|| DirectoryError::PathNotFound(path.into()))?;

        let pos = dir.files.iter().position(|f| f.filename == *filename)
            .ok_or_else(|| DirectoryError::PathNotFound(path.into()))?;
        dir.files.remove(pos);

        drop(tree);
        self.flush().await?;
        Ok(())
    }

    /// List all files in a directory.
    pub async fn list_directory(&self, dir_path: &str) -> Vec<FileEntry> {
        let tree = self.tree.read().await;
        let normalized = dir_path.trim_start_matches('/').trim_end_matches('/');

        if normalized.is_empty() || normalized == "_root" {
            let mut all = Vec::new();
            for d in &tree.root {
                all.extend(d.files.clone());
            }
            return all;
        }

        let dir = match tree.root.iter().find(|d| d.dirname == normalized) {
            Some(d) => d,
            None => return vec![],
        };
        dir.files.clone()
    }

    /// List all subdirectory names.
    pub async fn list_subdirs(&self) -> Vec<String> {
        let tree = self.tree.read().await;
        tree.root.iter()
            .filter(|d| d.dirname != "_root")
            .map(|d| d.dirname.clone())
            .collect()
    }

    /// Check if a path exists.
    pub async fn path_exists(&self, path: &str) -> bool {
        self.resolve_path(path).await.is_some()
    }

    /// Get total file count across all directories.
    pub async fn file_count(&self) -> usize {
        let tree = self.tree.read().await;
        tree.root.iter().map(|d| d.files.len()).sum()
    }

    /// Get all file entries matching a predicate.
    pub async fn find_files<F>(&self, predicate: F) -> Vec<(String, FileEntry)>
    where
        F: Fn(&FileEntry) -> bool,
    {
        let tree = self.tree.read().await;
        let mut results = Vec::new();
        for d in &tree.root {
            for f in &d.files {
                if predicate(f) {
                    results.push((d.dirname.clone(), f.clone()));
                }
            }
        }
        results
    }
}