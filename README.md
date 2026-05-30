# GHOST NAS — Pure Distributed NAS Daemon

> **Previously**: A P2P encrypted chat daemon with TrueNAS SCALE middleware integration  
> **Now**: A pure distributed NAS accessible via `\\IP` in Windows Explorer (WebDAV),  
> with WAN-aware Reed-Solomon parity sharding and an encrypted, invisible-on-disk filesystem.

---

## What Changed (Architecture Transformation)

### Old Architecture (Chat Daemon)
```
User input → Encrypt → Shamir Split → RS Encode → UDP Send → Remote Peer → Decrypt → Display text
```
- IPC TCP listener on port 9500 for text messages
- UDP packets with `"nickname: message"` formatting
- No file storage, no directory structure, no SMB/WebDAV

### New Architecture (Distributed NAS)
```
Windows Explorer → WebDAV PUT/GET on port 9443
    ↓
File → Block → Encrypt (ChaCha20-Poly1305) → Shamir Split Key → RS Encode (2 data + 1 parity)
    ↓
Data shards → Local BHS Vault (ZFS)
Parity shard → Remote WAN peer (via UDP/TCP)
    ↓
Directory tree: encrypted with Ed25519-derived AEAD key
                stored at /mnt/tank/ghost-vault/.meta/directory.enc
                no plaintext filenames anywhere on disk
```

### What Was Added

| File | Purpose |
|------|---------|
| `src/directory.rs` | Encrypted directory tree — maps file paths to shard group IDs. All filenames encrypted. |
| `src/router.rs` | WAN shard router — distributes RS parity across geo-distributed peers, tracks peer health |
| `src/davfs.rs` | WebDAV server (RFC 4918) — PROPFIND, GET, PUT, DELETE for Windows Explorer |

### What Was Removed
- TCP IPC chat listener (port 9500) — no more `"nickname: message"` chat
- `send_data_packets` with jitter padding — chat-specific obfuscation
- All text-message formatting logic

### What Stayed (Unchanged)
- `src/crypto.rs` — ChaCha20-Poly1305, Shamir's Secret Sharing (GF256), Reed-Solomon, Ed25519 identity, X25519+Kyber hybrid KEX, BLAKE3
- `src/vault.rs` — Black-Hole Storage (BHS) with TTL-based GC, Merkle tree integrity, replay protection
- `src/network.rs` — UDP/TCP transport for shard sync, NAT traversal, interface discovery
- `src/session.rs` — Session guard with sliding-window replay protection
- `src/truenas.rs` — TrueNAS SCALE middleware bridge

---

## Access Methods

### LAN Access — Windows Explorer (`\\IP`)
```
\\192.168.178.81:9443
```
**Requirements:**
- Windows WebClient service must be running (default on Win10/11)
- Map as "Add a network location" → enter `http://192.168.178.81:9443/dav/`
- Do **not** use port 445 (TrueNAS native Samba is already on that port)

### WAN Access — Chrome Browser
```
https://vps-public-ip:9443
```
- Web UI served at `/` (static files from `/usr/share/ghost-nas/webui/`)
- REST API at `/api/v1/`
- File listing at `/api/v1/files`
- File download at `/api/v1/files/<path>`

### Disk Invisibility
On the ZFS dataset, you will see **only**:
```
/mnt/tank/ghost-vault/
├── .meta/              ← encrypted directory tree (no plaintext names)
├── shards/
│   └── <blake3_hash>/  ← random-looking group IDs
│       ├── shard_000.bin
│       ├── shard_001.bin
│       ├── shard_002.bin  (parity)
│       └── merkle_root.bin
└── tmp/
```
No filenames, no directory structure, no plaintext. An attacker with the physical drives sees only noise.

---

## Deployment to TrueNAS SCALE

### 1. Prerequisites
- TrueNAS SCALE (Dragonfish or later)
- ZFS pool created (e.g., `tank`)
- SSH access to TrueNAS host
- Docker configured (TrueNAS Apps)

### 2. Build the Binary

On your build machine (or on TrueNAS itself):

```bash
# Clone or copy the source
cd /path/to/ghost-nas

# Build release binary (optimized, stripped)
cargo build --release

# The binary will be at:
# target/release/ghost-nas
```

### 3. Configure the Config File

Create `/mnt/tank/ghost-config/ghost_nas.toml`:

```toml
[node]
nickname = "ghost-nas-main"
identity_path = "/mnt/tank/ghost-config/identity.key"
allowed_peers = []

[truenas]
middleware_url = "http://localhost:8080/api/v2.0"
api_key = "your-truenas-api-key"
auto_provision_dataset = true
zfs_pool = "tank"
health_check_interval_secs = 30

[vault]
mount_path = "/mnt/tank/ghost-vault"
dataset_name = "tank/ghost-vault"
quota = "100G"
encryption = true
shard_ttl_secs = 86400
replication_factor = 3

[network]
udp_port = 0
tcp_port = 9001
bootstrap_peers = []
distributed = true

[session]
hard_timeout_secs = 86400
idle_timeout_secs = 1800
window_size = 128

[api]
listen_addr = "0.0.0.0"
listen_port = 9443
enable_cors = true
tls_cert_path = "/mnt/tank/ghost-config/cert.pem"    # Optional: for HTTPS
tls_key_path = "/mnt/tank/ghost-config/key.pem"      # Optional: for HTTPS

[nas]
share_name = "GHOST"
shard_block_size = 1048576       # 1MB blocks
rs_data_shards = 2
rs_parity_shards = 1
directory_db_path = "/mnt/tank/ghost-vault/.meta/directory.enc"
reconstruct_threshold = 2

# WAN peers: where parity shards are stored
[[nas.wan_peers]]
nickname = "remote-vps-1"
address = "203.0.113.50:9001"
public_key_hex = "ed25519_public_key_hex_here"
geo_tag = "eu-west"

[[nas.wan_peers]]
nickname = "remote-vps-2"
address = "198.51.100.75:9001"
public_key_hex = "ed25519_public_key_hex_here"
geo_tag = "us-east"
```

### 4. Run as Systemd Service

Create `/etc/systemd/system/ghost-nas.service`:

```ini
[Unit]
Description=GHOST NAS Daemon
After=network-online.target truenas.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ghost-nas --config /mnt/tank/ghost-config/ghost_nas.toml
Restart=always
RestartSec=5
Environment=GHOST_TARGET_IP=192.168.1.100
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ghost-nas
sudo systemctl start ghost-nas
```

### 5. Verify It's Running

```bash
# Check status
sudo systemctl status ghost-nas

# Check logs
journalctl -u ghost-nas -f

# Test WebDAV (from another machine)
curl -X PROPFIND http://192.168.1.100:9443/dav/

# Test health endpoint
curl http://192.168.1.100:9443/api/v1/health
```

### 6. Mount in Windows Explorer

**Option A: Add Network Location (Recommended)**
1. Open Windows Explorer
2. Right-click "This PC" → "Add a network location"
3. Enter: `http://192.168.1.100:9443/dav/`
4. Give it a name (e.g., "GHOST NAS")
5. Done — now `\\192.168.1.100@9443\dav` appears in Explorer

**Option B: Map as Drive (Advanced)**
1. Open Command Prompt as Administrator
2. `net use Z: http://192.168.1.100:9443/dav/ /persistent:yes`
3. Drive `Z:` now points to your GHOST NAS

**Note:** If your Windows shows "This operation has been cancelled", enable WebClient:
```powershell
Set-Service WebClient -StartupType Automatic
Start-Service WebClient
```

### 7. WAN Access via Chrome

Just open `https://vps-public-ip:9443/` in Chrome. The web UI provides a file browser and download interface.

---

## WAN Peer Setup (Distributed Parity)

For each remote peer running GHOST NAS:

```bash
# On remote peer:
ghost-nas --config /path/to/config.toml --nickname "remote-vps-1"
```

Add each peer's Ed25519 fingerprint to the local `[nas.wan_peers]` list. The router will automatically:
- Store data shards (0, 1) locally
- Push parity shard (2) to remote peers
- On read: if a local shard is missing, fetch from peer or reconstruct from parity

---

## Monitoring

### Health Endpoints
```bash
# Overall status
curl http://192.168.1.100:9443/api/v1/status

# Vault info
curl http://192.168.1.100:9443/api/v1/vault/status

# List all sessions (connected WAN peers)
curl http://192.168.1.100:9443/api/v1/sessions

# TrueNAS health
curl http://192.168.1.100:9443/api/v1/truenas/health
```

### WebSocket Metrics (for dashboards)
```
ws://192.168.1.100:9443/api/v1/metrics/ws
```
Pushes JSON status every 5 seconds.

---

## Security Notes

- **No plaintext filenames on disk**: The directory tree is encrypted with a key derived from the Ed25519 seed via BLAKE3
- **Every file block uses a unique encryption key** (random 32-byte key per block, then Shamir-split)
- **RS(2,1) erasure coding**: File survives single shard loss (local peer offline)
- **WAN parity distribution**: Even if a peer is compromised, they only have 1 of 3 shards — cannot reconstruct anything
- **Physical disk seizure**: Shows only `shards/<hash>/shard_NNN.bin` — meaningless noise without the Ed25519 identity key