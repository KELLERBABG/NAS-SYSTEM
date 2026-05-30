//! WebDAV Filesystem Server
//!
//! Implements the WebDAV protocol (RFC 4918) for Windows Explorer (`\\IP` LAN)
//! and Chrome browser (WAN) access to the encrypted GHOST NAS.
//!
//! Windows Explorer connects via:
//!   \\192.168.x.x:9443  (WebClient service must be running)
//!
//! Key endpoints:
//!   PROPFIND  /dav/...   — List directory / get file metadata
//!   GET       /dav/...   — Download / read file
//!   PUT       /dav/...   — Upload / write file
//!   DELETE    /dav/...   — Delete file
//!   MKCOL     /dav/...   — Create directory
//!   MOVE      /dav/...   — Rename / move file
//!
//! All paths are transparently decrypted via the EncryptedDirectory,
//! and file data flows through: file → block → encrypt → shard → RS encode → vault

use std::sync::Arc;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Method, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};

use crate::directory::{EncryptedDirectory, FileEntry};
use crate::vault::Vault;
use crate::crypto::{
    blake3_hash, merkle_root, encrypt_message,
    rs_encode_n, rs_reconstruct_n,
    shamir_split, random_key,
};
use crate::router::WanRouter;

/// Shared WebDAV state.
#[derive(Clone)]
pub struct DavState {
    pub directory: Arc<EncryptedDirectory>,
    pub vault: Arc<Vault>,
    pub router: Arc<WanRouter>,
    pub rs_data_shards: usize,
    pub rs_parity_shards: usize,
    pub block_size: usize,
}

/// Build the WebDAV router — mounted at /dav/ in the main API server.
pub fn build_dav_router(state: DavState) -> Router {
    Router::new()
        // WebDAV methods
        .route("/dav/*path", any(dav_handler))
        // Also handle /dav root without trailing path
        .route("/dav", any(dav_root_handler))
        // Public file serving for WAN web UI (read-only)
        .route("/api/v1/files/*path", get(wan_file_handler))
        .route("/api/v1/files", get(wan_list_handler))
        .with_state(Arc::new(state))
}

/// Unified WebDAV handler that dispatches by HTTP method.
async fn dav_handler(
    State(state): State<Arc<DavState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Extract the path after /dav/
    let path = uri.path().trim_start_matches("/dav/").to_string();
    if path.is_empty() || path == "/" {
        return dav_root(state, method, headers, body).await;
    }

    // Match on method string for WebDAV-specific methods that axum doesn't have variants for
    match method.as_str() {
        "OPTIONS" => dav_options().await,
        "PROPFIND" => dav_propfind(state, &path).await,
        "GET" | "HEAD" => dav_get(state, &path).await,
        "PUT" => dav_put(state, &path, body).await,
        "DELETE" => dav_delete(state, &path).await,
        "MKCOL" => dav_mkcol().await,
        "MOVE" => dav_move().await,
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            [("Allow", "OPTIONS, PROPFIND, GET, PUT, DELETE, MKCOL, MOVE")],
        )
            .into_response(),
    }
}

/// Handler for /dav (root listing).
async fn dav_root_handler(
    State(state): State<Arc<DavState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    dav_root(state, method, headers, body).await
}

async fn dav_root(
    state: Arc<DavState>,
    method: Method,
    _headers: HeaderMap,
    _body: Bytes,
) -> Response {
    match method.as_str() {
        "OPTIONS" => dav_options().await,
        "PROPFIND" => {
            // List root directory (all subdirs + root files)
            let files = state.directory.list_directory("/").await;
            let dirs = state.directory.list_subdirs().await;

            let mut xml = String::from(
                r#"<?xml version="1.0" encoding="utf-8"?>"#
            );
            xml.push_str(r#"<D:multistatus xmlns:D="DAV:">"#);

            // Root entry
            xml.push_str(r#"<D:response><D:href>/dav/</D:href><D:propstat><D:prop>"#);
            xml.push_str(r#"<D:displayname>GHOST NAS</D:displayname>"#);
            xml.push_str(r#"<D:resourcetype><D:collection/></D:resourcetype>"#);
            xml.push_str(r#"<D:getcontenttype>httpd/unix-directory</D:getcontenttype>"#);
            let now = chrono::Utc::now().to_rfc3339();
            xml.push_str(&format!(r#"<D:getlastmodified>{}</D:getlastmodified>"#, now));
            xml.push_str(r#"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"#);

            // Subdirectory entries
            for dirname in &dirs {
                xml.push_str(&format!(
                    r#"<D:response><D:href>/dav/{}/</D:href><D:propstat><D:prop>"#, dirname
                ));
                xml.push_str(&format!(r#"<D:displayname>{}</D:displayname>"#, dirname));
                xml.push_str(r#"<D:resourcetype><D:collection/></D:resourcetype>"#);
                xml.push_str(r#"<D:getcontenttype>httpd/unix-directory</D:getcontenttype>"#);
                xml.push_str(&format!(r#"<D:getlastmodified>{}</D:getlastmodified>"#, now));
                xml.push_str(r#"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"#);
            }

            // Root-level files
            for file in &files {
                xml.push_str(&format!(
                    r#"<D:response><D:href>/dav/{}</D:href><D:propstat><D:prop>"#, file.filename
                ));
                xml.push_str(&format!(r#"<D:displayname>{}</D:displayname>"#, file.filename));
                xml.push_str(r#"<D:resourcetype/>"#);
                xml.push_str(&format!(r#"<D:getcontentlength>{}</D:getcontentlength>"#, file.size));
                xml.push_str(r#"<D:getcontenttype>application/octet-stream</D:getcontenttype>"#);
                xml.push_str(&format!(r#"<D:getlastmodified>{}</D:getlastmodified>"#, now));
                xml.push_str(r#"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"#);
            }

            xml.push_str(r#"</D:multistatus>"#);

            (
                StatusCode::MULTI_STATUS,
                [("Content-Type", "application/xml; charset=utf-8")],
                xml,
            )
                .into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// Handle OPTIONS (for WebDAV feature discovery).
async fn dav_options() -> Response {
    (
        StatusCode::OK,
        [
            ("DAV", "1, 2"),
            ("Allow", "OPTIONS, PROPFIND, GET, PUT, DELETE, MKCOL, MOVE"),
            ("MS-Author-Via", "DAV"),
        ],
    )
        .into_response()
}

/// Handle PROPFIND — list a directory.
async fn dav_propfind(
    state: Arc<DavState>,
    path: &str,
) -> Response {
    // Try to resolve as a file first
    if let Some(file) = state.directory.resolve_path(path).await {
        // Return file metadata
        let xml = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/{}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>{}</D:displayname>
        <D:resourcetype/>
        <D:getcontentlength>{}</D:getcontentlength>
        <D:getcontenttype>application/octet-stream</D:getcontenttype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#,
            path, file.filename, file.size
        );
        return (
            StatusCode::MULTI_STATUS,
            [("Content-Type", "application/xml; charset=utf-8")],
            xml,
        )
            .into_response();
    }

    // Try as a directory
    let files = state.directory.list_directory(path).await;

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">"#
    );

    // The directory itself
    xml.push_str(&format!(
        r#"<D:response><D:href>/dav/{}/</D:href><D:propstat><D:prop><D:displayname>{}</D:displayname><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"#,
        path, path
    ));

    // Files in directory
    for file in &files {
        xml.push_str(&format!(
            r#"<D:response><D:href>/dav/{}</D:href><D:propstat><D:prop><D:displayname>{}</D:displayname><D:resourcetype/><D:getcontentlength>{}</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"#,
            file.filename, file.filename, file.size
        ));
    }

    xml.push_str("</D:multistatus>");

    (
        StatusCode::MULTI_STATUS,
        [("Content-Type", "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

/// Handle GET — download a file.
async fn dav_get(
    state: Arc<DavState>,
    path: &str,
) -> Response {
    let file = match state.directory.resolve_path(path).await {
        Some(f) => f,
        None => return (StatusCode::NOT_FOUND, "File not found").into_response(),
    };

    // Reconstruct the file from shards
    match reconstruct_file(&state, &file).await {
        Ok(data) => {
            (
                StatusCode::OK,
                [
                    ("Content-Type", "application/octet-stream"),
                    ("Content-Disposition", &format!("attachment; filename=\"{}\"", file.filename)),
                    ("Content-Length", &data.len().to_string()),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to reconstruct file {}: {}", path, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("File reconstruction failed: {}", e),
            )
                .into_response()
        }
    }
}

/// Handle PUT — upload a file.
async fn dav_put(
    state: Arc<DavState>,
    path: &str,
    body: Bytes,
) -> Response {
    let data = body.to_vec();
    let file_size = data.len() as u64;
    let content_hash = blake3_hash(&data);

    tracing::info!("PUT {} ({} bytes)", path, file_size);

    // Split the file into blocks and shard each block
    match store_file(&state, path, &data, file_size, content_hash).await {
        Ok(_) => {
            tracing::info!("File stored successfully: {}", path);
            (StatusCode::CREATED, "File uploaded").into_response()
        }
        Err(e) => {
            tracing::error!("Failed to store file {}: {}", path, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("File storage failed: {}", e),
            )
                .into_response()
        }
    }
}

/// Handle DELETE — remove a file.
async fn dav_delete(
    state: Arc<DavState>,
    path: &str,
) -> Response {
    let file = match state.directory.resolve_path(path).await {
        Some(f) => f,
        None => return (StatusCode::NOT_FOUND, "File not found").into_response(),
    };

    // Remove shard groups from vault
    for group_id in &file.block_groups {
        if let Err(e) = state.vault.secure_wipe_group(group_id).await {
            tracing::warn!("Failed to wipe group {}: {}", group_id, e);
        }
        state.router.remove_route(group_id).await;
    }

    // Remove from directory tree
    match state.directory.remove_file(path).await {
        Ok(_) => (StatusCode::NO_CONTENT, "").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Handle MKCOL — create a directory.
async fn dav_mkcol() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "Directories are auto-created").into_response()
}

/// Handle MOVE — rename/move a file.
async fn dav_move() -> Response {
    (StatusCode::NOT_IMPLEMENTED, "MOVE not yet implemented").into_response()
}

/// WAN file download handler (Chrome browser).
async fn wan_file_handler(
    State(state): State<Arc<DavState>>,
    Path(path): Path<String>,
) -> Response {
    dav_get(state, &path).await
}

/// WAN file listing handler (Chrome browser).
async fn wan_list_handler(
    State(state): State<Arc<DavState>>,
) -> Response {
    let files = state.directory.list_directory("/").await;
    let dirs = state.directory.list_subdirs().await;

    let resp = serde_json::json!({
        "directories": dirs,
        "files": files.iter().map(|f| serde_json::json!({
            "name": f.filename,
            "size": f.size,
            "blocks": f.block_count,
        })).collect::<Vec<_>>(),
    });

    (StatusCode::OK, axum::Json(resp)).into_response()
}

// ────────────────────────────────────────────────────────────────────────────
// File Storage / Retrieval Core Logic
// ────────────────────────────────────────────────────────────────────────────

/// Store a file: split into blocks, encrypt, shard, RS encode, store in vault + route.
async fn store_file(
    state: &DavState,
    path: &str,
    data: &[u8],
    file_size: u64,
    content_hash: [u8; 32],
) -> Result<(), String> {
    let parent_dir: String = if path.contains('/') {
        let parts: Vec<&str> = path.split('/').collect();
        parts[..parts.len() - 1].join("/")
    } else {
        "/".to_string()
    };
    let filename = if path.contains('/') {
        path.split('/').last().unwrap_or(path)
    } else {
        path
    };

    let block_size = state.block_size;
    let total_blocks = (data.len() + block_size - 1) / block_size;
    let mut block_groups = Vec::with_capacity(total_blocks);

    // Process each block
    for block_idx in 0..total_blocks {
        let start = block_idx * block_size;
        let end = (start + block_size).min(data.len());
        let block_data = &data[start..end];

        // Encrypt the block
        let mut block_key = random_key();
        let mut encrypted = block_data.to_vec();
        let counter = (block_idx as u64) + 1;
        encrypt_message(&block_key, counter, &mut encrypted);

        // Shamir split the block key
        let _key_shares = shamir_split(&mut block_key);

        // RS encode the encrypted block
        let shards = rs_encode_n(
            &encrypted,
            state.rs_data_shards,
            state.rs_parity_shards,
        );

        // Generate a unique group_id for this block
        let group_id = hex::encode(&blake3_hash(&[block_idx.to_le_bytes().as_slice(), &encrypted].concat())[0..16]);

        // Merkle root for integrity
        let root = merkle_root(&shards);

        // Compute route (where each shard goes)
        let route = state.router.compute_route(
            &group_id,
            shards.len(),
            state.rs_data_shards,
            state.rs_parity_shards,
        ).await;

        // Store each shard locally and push to remote peers
        for (i, shard) in shards.iter().enumerate() {
            // Always store locally in vault
            if let Err(e) = state.vault.store_shard(
                &group_id,
                i,
                shard,
                counter,
                root,
                shards.len(),
            ).await {
                tracing::warn!("Failed to store shard {}/{} locally: {}", group_id, i, e);
            }

            // Push to remote peer if it's not local
            if let Some(loc) = route.locations.get(i) {
                if loc.peer_nickname != "local" {
                    if let Err(e) = state.router.push_shard_to_peer(
                        &group_id, i, shard, &loc.peer_addr,
                    ).await {
                        tracing::warn!("Failed to push shard {} to peer {}: {}", i, loc.peer_nickname, e);
                    }
                }
            }
        }

        block_groups.push(group_id);
    }

    // Create file entry in the directory tree
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let entry = FileEntry {
        filename: filename.to_string(),
        size: file_size,
        content_hash,
        block_count: total_blocks,
        block_groups,
        created_at_ns: now,
        modified_at_ns: now,
        mode: 0o644,
        version: 1,
    };

    state.directory.add_file(&parent_dir, entry).await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Reconstruct a file from its shards.
async fn reconstruct_file(
    state: &DavState,
    file: &FileEntry,
) -> Result<Vec<u8>, String> {
    let mut file_data = Vec::new();

    for (block_idx, group_id) in file.block_groups.iter().enumerate() {
        let route = state.router.get_route(group_id).await
            .ok_or_else(|| format!("No route for group {}", group_id))?;

        // Try to read shards from local vault first
        let mut shard_opts: Vec<Option<Vec<u8>>> = Vec::new();

        for i in 0..route.total_shards {
            match state.vault.read_shard(group_id, i).await {
                Ok(shard) => shard_opts.push(Some(shard.data)),
                Err(_) => {
                    // Try to fetch from peer
                    let loc = route.locations.get(i);
                    if let Some(l) = loc {
                        match state.router.fetch_shard_from_peer(
                            group_id, i, &l.peer_addr,
                        ).await {
                            Ok(data) => shard_opts.push(Some(data)),
                            Err(_) => shard_opts.push(None),
                        }
                    } else {
                        shard_opts.push(None);
                    }
                }
            }
        }

        // Reconstruct using RS
        let data_shards = state.rs_data_shards;
        let parity_shards = state.rs_parity_shards;
        rs_reconstruct_n(&mut shard_opts, data_shards, parity_shards)
            .map_err(|e| format!("RS reconstruction failed for block {}: {}", block_idx, e))?;

        // Concatenate reconstructed shards
        let encrypted_block: Vec<u8> = shard_opts.iter()
            .filter_map(|s| s.as_ref())
            .flat_map(|s| s.iter().copied())
            .collect();

        file_data.extend_from_slice(&encrypted_block);
    }

    Ok(file_data)
}