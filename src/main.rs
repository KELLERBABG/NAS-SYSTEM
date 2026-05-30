// ═══════════════════════════════════════════════════════════════════════════
//  GHOST NAS — Pure Distributed NAS Daemon
//  ═══════════════════════════════════════════════════════════════════════════
//
//  Architecture:
//    Layer 0: Ed25519 Identity & Attestation
//    Layer 1: X25519 + Kyber512 Hybrid Key Exchange
//    Layer 2: ChaCha20-Poly1305 AEAD (encryption)
//    Layer 3: Shamir's Secret Sharing GF(256)
//    Layer 4: Reed-Solomon Erasure Coding
//    Layer 5: WAN Shard Router (distributed parity storage)
//    Layer 6: Encrypted Directory Tree (path → shard groups)
//
//  Access:
//    LAN:  \\192.168.x.x:9443  (WebDAV via Windows Explorer)
//    WAN:  https://vps-ip:9443  (Chrome browser Web UI)
//
//  Disk invisibility: ZFS stores only shards/<blake3_hash>/shard_NNN.bin
//  — no filenames, no structure, no plaintext anywhere.

use std::sync::Arc;
use std::path::PathBuf;
use clap::Parser;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

// ──────────────────────────────────────────────────────────────────────────
// Modules
// ──────────────────────────────────────────────────────────────────────────

mod session;
mod crypto;
mod network;
mod config;
mod truenas;
mod vault;
mod api;
mod directory;
mod router;
mod davfs;

use session::{SessionGuard, SessionManager, heartbeat_monitor_loop};
use crypto::{
    decrypt_message,
    shamir_split, shamir_join,
    random_key, PeerIdentity,
};
use network::{
    HANDSHAKE_ID,
    send_handshake_packets,
    ParsedPacket,
    bind_udp, discover_interfaces,
    OFFSET_MSG_ID, OFFSET_ORIG_LEN,
    keepalive_loop, NatState, MAX_PACKET_SIZE,
};
use config::GhostConfig;
use truenas::TrueNASBridge;
use vault::Vault;
use api::{AppState, build_router};
use directory::EncryptedDirectory;
use router::WanRouter;
use davfs::{DavState, build_dav_router};

use rand::Rng;
use x25519_dalek::EphemeralSecret;

// ──────────────────────────────────────────────────────────────────────────
// CLI Arguments
// ──────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ghost-nas", version, about = "GHOST NAS Daemon — Pure Distributed NAS")]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long, default_value = None)]
    config: Option<PathBuf>,

    /// Peer target address (overrides config)
    #[arg(short, long)]
    target: Option<String>,

    /// Nickname for this node
    #[arg(short, long)]
    nickname: Option<String>,

    /// UDP listen port (overrides config)
    #[arg(short = 'u', long)]
    udp_port: Option<u16>,

    /// HTTP API / WebDAV / WebUI port (overrides config)
    #[arg(short = 'p', long)]
    api_port: Option<u16>,

    /// Initialize vault dataset only, then exit
    #[arg(long)]
    init_vault: bool,
}

// ──────────────────────────────────────────────────────────────────────────
// Main Entry Point
// ──────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Tracing / Logging ──
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,ghost_nas=debug")),
        )
        .with_target(true)
        .init();

    // ── CLI & Config ──
    let cli = Cli::parse();
    let config_path = cli.config
        .clone()
        .unwrap_or_else(GhostConfig::default_path);
    let mut cfg = GhostConfig::load_or_create(&config_path)?;

    // Apply CLI overrides
    if let Some(ref nick) = cli.nickname {
        cfg.node.nickname = nick.clone();
    }
    if let Some(port) = cli.udp_port {
        cfg.network.udp_port = port;
    }
    if let Some(port) = cli.api_port {
        cfg.api.listen_port = port;
    }

    tracing::info!("╔══════════════════════════════════════╗");
    tracing::info!("║  GHOST NAS v{}                  ║", env!("CARGO_PKG_VERSION"));
    tracing::info!("╚══════════════════════════════════════╝");
    tracing::info!("Node: {}", cfg.node.nickname);
    tracing::info!("Config: {}", config_path.display());

    // ── TrueNAS Middleware Bridge ──
    let truenas = match TrueNASBridge::new(&cfg) {
        Ok(bridge) => {
            tracing::info!("TrueNAS middleware bridge initialized");
            Arc::new(bridge)
        }
        Err(e) => {
            tracing::warn!("TrueNAS bridge init failed (will retry): {}", e);
            // Create a dummy bridge for offline mode
            let dummy_cfg = GhostConfig::default();
            Arc::new(TrueNASBridge::new(&dummy_cfg)?)
        }
    };

    // ── ZFS Dataset Provisioning ──
    if cfg.truenas.auto_provision_dataset {
        match truenas.provision_vault_dataset().await {
            Ok(_) => tracing::info!("Vault dataset provisioned"),
            Err(e) => tracing::warn!("Vault provisioning skipped: {}", e),
        }
        match truenas.mount_vault().await {
            Ok(_) => tracing::info!("Vault dataset mounted"),
            Err(e) => tracing::warn!("Vault mount skipped: {}", e),
        }
    }

    // If --init-vault, exit here (for use in init scripts)
    if cli.init_vault {
        tracing::info!("Vault initialized. Exiting (--init-vault).");
        return Ok(());
    }

    // ── Vault (Black-Hole Storage) ──
    let vault = Arc::new(
        Vault::open(&cfg.vault.mount_path, cfg.vault.shard_ttl_secs).await?,
    );
    tracing::info!("Vault opened at {}", cfg.vault.mount_path.display());

    // ── Identity Generation ──
    let mut seed = [0u8; 32];
    rand::thread_rng().fill(&mut seed);
    let x_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let identity = PeerIdentity::generate(&seed, x_secret);
    let node_fingerprint = identity.fingerprint().to_string();
    tracing::info!("Identity: {}", node_fingerprint);

    // ── Encrypted Directory Tree ──
    let directory = Arc::new(
        EncryptedDirectory::open(&cfg.nas.directory_db_path, &seed).await?,
    );
    tracing::info!(
        "Encrypted directory tree opened at {}",
        cfg.nas.directory_db_path.display()
    );

    // ── WAN Shard Router ──
    let local_addr = format!("127.0.0.1:{}", cfg.network.tcp_port);
    let router = Arc::new(WanRouter::new(
        cfg.node.nickname.clone(),
        local_addr,
        node_fingerprint.clone(),
        cfg.nas.wan_peers.clone(),
    ));
    tracing::info!(
        "WAN router initialized with {} peers",
        cfg.nas.wan_peers.len()
    );

    // ── Network Setup ──
    let interfaces = discover_interfaces();
    tracing::info!("Network interfaces: {:?}", interfaces.iter().map(|i| &i.name).collect::<Vec<_>>());

    let socket = bind_udp(cfg.network.udp_port)?;
    let local_addr = socket.local_addr().unwrap();
    tracing::info!("UDP bound to: {}", local_addr);
    let socket = Arc::new(socket);

    // ── Shared State ──
    let master_key: Arc<RwLock<Option<[u8; 32]>>> = Arc::new(RwLock::new(None));
    let master_key_rx = Arc::clone(&master_key);
    let global_tx_counter = Arc::new(RwLock::new(0u64));
    let session_manager = Arc::new(SessionManager::new());

    // Target address (from env, CLI, or config peer list)
    let initial_target = if let Some(ref t) = cli.target {
        t.clone()
    } else if let Some(ref t) = std::env::var("GHOST_TARGET_IP").ok() {
        format!("{}:{}", t, cfg.network.tcp_port)
    } else if !cfg.network.bootstrap_peers.is_empty() {
        cfg.network.bootstrap_peers[0].clone()
    } else {
        "127.0.0.1:9000".to_string()
    };
    let target_addr = Arc::new(RwLock::new(initial_target));

    // NAT state
    let nat_state = Arc::new(RwLock::new(NatState::new()));
    let peers = Arc::new(RwLock::new(Vec::<String>::new()));

    // ── Background Tasks ──

    // 1) TrueNAS health check loop
    let truenas_health = Arc::clone(&truenas);
    tokio::spawn(async move {
        TrueNASBridge::health_loop(truenas_health).await;
    });

    // 2) Vault GC loop
    let vault_gc = Arc::clone(&vault);
    let gc_interval = Duration::from_secs(cfg.vault.shard_ttl_secs.min(3600));
    tokio::spawn(async move {
        loop {
            sleep(gc_interval).await;
            if let Err(e) = vault_gc.garbage_collect().await {
                tracing::warn!("Vault GC error: {}", e);
            }
        }
    });

    // 3) Heartbeat monitor (session expiry / reactive wipe)
    let sm_hb = Arc::clone(&session_manager);
    tokio::spawn(async move {
        heartbeat_monitor_loop(sm_hb, Duration::from_secs(30)).await;
    });

    // 4) NAT keepalive loop
    let socket_ka = Arc::clone(&socket);
    let peers_ka = Arc::clone(&peers);
    let nat_state_ka = Arc::clone(&nat_state);
    tokio::spawn(async move {
        keepalive_loop(socket_ka, peers_ka, nat_state_ka).await;
    });

    // 5) Handshake sender task
    let socket_hs = Arc::clone(&socket);
    let addr_hs = Arc::clone(&target_addr);
    let mk_hs = Arc::clone(&master_key);
    tokio::spawn(async move {
        loop {
            if mk_hs.read().await.is_some() {
                sleep(Duration::from_secs(10)).await;
                continue;
            }
            let target = addr_hs.read().await;
            // Generate ephemeral handshake
            let mut hs_temp_key = random_key();
            let hs_shares = shamir_split(&mut hs_temp_key);
            let hs_blob = vec![0u8; 480]; // placeholder blob — peer identity is embedded
            let hs_shards = vec![
                hs_blob[0..160].to_vec(),
                hs_blob[160..320].to_vec(),
                vec![0u8; 160],
            ];
            // Only send if we have no master key
            send_handshake_packets(&hs_shares, &hs_shards, &socket_hs, &target);
            tracing::debug!("Handshake broadcast to {}", target);
            drop(target);
            sleep(Duration::from_millis(1500)).await;
        }
    });

    // 6) UDP receiver task (for WAN shard transfer + handshake)
    let socket_rx = Arc::clone(&socket);
    let target_addr_rx = Arc::clone(&target_addr);
    let master_key_rx_clone = Arc::clone(&master_key_rx);
    let session_manager_rx = Arc::clone(&session_manager);
    let vault_rx = Arc::clone(&vault);
    let router_rx = Arc::clone(&router);

    tokio::spawn(async move {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let mut pool: std::collections::HashMap<u8, (Vec<Vec<u8>>, Vec<Vec<u8>>, usize, u64)> =
            std::collections::HashMap::new();

        loop {
            if let Ok((len, from_addr)) = socket_rx.recv_from(&mut buf) {
                let msg_id = buf[OFFSET_MSG_ID];
                let msg_len = buf[OFFSET_ORIG_LEN] as usize;

                // Dynamic peer address update for handshake
                if msg_id == HANDSHAKE_ID {
                    let mut t = target_addr_rx.write().await;
                    let new_addr = from_addr.to_string();
                    if *t != new_addr {
                        *t = new_addr;
                        tracing::info!("Peer address updated to {}", from_addr);
                    }
                }

                if msg_id == 0 {
                    continue; // Keepalive / dummy
                }

                if let Some(pkt) = ParsedPacket::parse(&buf, len) {
                    let entry = pool
                        .entry(msg_id)
                        .or_insert((Vec::new(), Vec::new(), msg_len, pkt.counter));
                    entry.0.push(pkt.share);
                    entry.1.push(pkt.shard);

                    // Need at least 2 shares for Shamir reconstruction
                    if entry.0.len() >= 2 {
                        let key_recovered = shamir_join(&entry.0[0], &entry.0[1]);
                        let mut recover = vec![
                            Some(entry.1[0].clone()),
                            Some(entry.1[1].clone()),
                            None,
                        ];

                        if crypto::rs_reconstruct(&mut recover).is_ok() {
                            let combined = [
                                recover[0].as_ref().unwrap().as_slice(),
                                recover[1].as_ref().unwrap().as_slice(),
                            ]
                            .concat();

                            if msg_id == HANDSHAKE_ID {
                                // Handshake processing
                                if master_key_rx_clone.read().await.is_some() {
                                    pool.remove(&msg_id);
                                    continue;
                                }

                                match PeerIdentity::verify_handshake_blob(&combined) {
                                    Ok(handshake_data) => {
                                        let ed_pk_bytes: [u8; 32] = handshake_data[832..864]
                                            .try_into()
                                            .expect("Ed key length");
                                        let peer_fp = hex::encode(&ed_pk_bytes[0..8]);

                                        tracing::info!(
                                            "[HANDSHAKE] Verified peer: {}",
                                            peer_fp
                                        );

                                        let mut mk = master_key_rx_clone.write().await;
                                        if mk.is_none() {
                                            let mut k = [0u8; 32];
                                            k.copy_from_slice(&key_recovered[0..32]);
                                            *mk = Some(k);

                                            // Create session
                                            let fp_clone = peer_fp.clone();
                                            let mut guard =
                                                SessionGuard::new(fp_clone);
                                            guard.set_master_key(k);
                                            session_manager_rx
                                                .upsert(peer_fp.clone(), guard)
                                                .await;

                                            // Mark peer as online in router
                                            router_rx.mark_online(&peer_fp).await;

                                            tracing::info!(
                                                "[TRUST] Session established with {}",
                                                peer_fp
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Handshake verification failed: {}",
                                            e
                                        );
                                    }
                                }
                            } else {
                                // Data message — could be shard transfer
                                if let Ok(dec) = decrypt_message(
                                    &key_recovered,
                                    entry.3,
                                    &mut combined.clone(),
                                ) {
                                    tracing::debug!("[RECV] {} bytes decoded", dec.len());
                                }
                            }
                        }
                        pool.remove(&msg_id);
                    }
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    });

    // ── HTTP/WebDAV API Server ──
    let api_state = AppState {
        config: cfg.clone(),
        session_manager: Arc::clone(&session_manager),
        vault: Arc::clone(&vault),
        truenas: Arc::clone(&truenas),
        node_fingerprint: node_fingerprint.clone(),
    };

    // ── WebDAV State ──
    let dav_state = DavState {
        directory: Arc::clone(&directory),
        vault: Arc::clone(&vault),
        router: Arc::clone(&router),
        rs_data_shards: cfg.nas.rs_data_shards,
        rs_parity_shards: cfg.nas.rs_parity_shards,
        block_size: cfg.nas.shard_block_size,
    };

    // ── Build combined router ──
    let api_router = build_router(api_state);
    let dav_router = build_dav_router(dav_state);

    // Merge: DAV routes are under /dav/ and /api/v1/files/
    let combined_router = api_router.merge(dav_router);

    let api_addr = format!("{}:{}", cfg.api.listen_addr, cfg.api.listen_port);
    tracing::info!("GHOST NAS server starting on {}", api_addr);
    tracing::info!("  WebDAV (LAN):  \\\\{}  (WebClient on port {})", api_addr, cfg.api.listen_port);
    tracing::info!("  Web UI (WAN):  https://{}:", api_addr);
    tracing::info!(
        "  Vault shards:  {}",
        cfg.vault.mount_path.join("shards").display()
    );
    tracing::info!("  Directory DB:  {}", cfg.nas.directory_db_path.display());

    let listener = tokio::net::TcpListener::bind(&api_addr).await?;
    axum::serve(listener, combined_router).await?;

    Ok(())
}