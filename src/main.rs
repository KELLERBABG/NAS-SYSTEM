// ═══════════════════════════════════════════════════════════════════════════
//  GHOST NAS — TrueNAS SCALE Full Integration Daemon
//  ═══════════════════════════════════════════════════════════════════════════
//
//  Architecture (from GHOST_NAS.json "GHOST Stack"):
//    Layer 0: Ed25519 Identity & Attestation
//    Layer 1: X25519 + Kyber512 Hybrid Key Exchange
//    Layer 2: ChaCha20-Poly1305 AEAD (encryption)
//    Layer 3: Shamir's Secret Sharing GF(256)
//    Layer 4: Reed-Solomon Erasure Coding
//    Layer 5: Noise Injection / Constant Flow
//    Layer 6: State & Replay Guard
//
//  TrueNAS SCALE Middleware Integration:
//    - ZFS dataset auto-provisioning (/mnt/tank/ghost-vault)
//    - REST API server on port 9443
//    - Health check & heartbeat to middleware
//    - Alert/event reporting
//    - Web UI served from /usr/share/ghost-nas/webui

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

use session::{SessionGuard, SessionManager, heartbeat_monitor_loop};
use crypto::{
    encrypt_message, decrypt_message,
    rs_encode, rs_reconstruct,
    shamir_split, shamir_join,
    random_key, PeerIdentity,
    merkle_root,
};
use network::{
    HANDSHAKE_ID,
    send_handshake_packets, send_data_packets,
    ParsedPacket,
    bind_udp, discover_interfaces,
    OFFSET_MSG_ID, OFFSET_ORIG_LEN,
    keepalive_loop, NatState, MAX_PACKET_SIZE,
};
use config::GhostConfig;
use truenas::TrueNASBridge;
use vault::Vault;
use api::{AppState, build_router};

use reed_solomon_erasure::galois_8::ReedSolomon;
use rand::Rng;
use x25519_dalek::EphemeralSecret;

// ──────────────────────────────────────────────────────────────────────────
// CLI Arguments
// ──────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ghost-nas", version, about = "GHOST NAS Daemon for TrueNAS SCALE")]
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

    /// HTTP API port (overrides config)
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

    // Pre-build the handshake blob
    let hs_blob = identity.build_handshake_blob();
    let mut hs_temp_key = random_key();
    let hs_shares = shamir_split(&mut hs_temp_key);
    let mut hs_shards = vec![
        hs_blob[0..480].to_vec(),
        hs_blob[480..960].to_vec(),
        vec![0u8; 480],
    ];
    ReedSolomon::new(2, 1).unwrap().encode(&mut hs_shards).unwrap();

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
    let master_key_tx = Arc::clone(&master_key);
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
    let hs_shares_ref = hs_shares.clone();
    let hs_shards_ref = hs_shards.clone();
    tokio::spawn(async move {
        loop {
            if mk_hs.read().await.is_some() {
                sleep(Duration::from_secs(10)).await;
                continue;
            }
            let target = addr_hs.read().await;
            send_handshake_packets(&hs_shares_ref, &hs_shards_ref, &socket_hs, &target);
            tracing::debug!("Handshake broadcast to {}", target);
            drop(target);
            sleep(Duration::from_millis(1500)).await;
        }
    });

    // 6) UDP receiver task
    let socket_rx = Arc::clone(&socket);
    let target_addr_rx = Arc::clone(&target_addr);
    let master_key_rx_clone = Arc::clone(&master_key_rx);
    let session_manager_rx = Arc::clone(&session_manager);

    tokio::spawn(async move {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        // pool: msg_id -> (shares, shards, original_len, counter)
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
                        let packet_counter = entry.3;

                        // For data messages, check replay
                        if msg_id != HANDSHAKE_ID {
                            // We need a session to exist — use a default guard
                            // (In production, the session is looked up by peer fingerprint)
                        }

                        let key_recovered = shamir_join(&entry.0[0], &entry.0[1]);
                        let mut recover = vec![
                            Some(entry.1[0].clone()),
                            Some(entry.1[1].clone()),
                            None,
                        ];

                        if rs_reconstruct(&mut recover).is_ok() {
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
                                        // handshake_data contains x_pub(32) + kyber_pub(800) + ed_vk(32)
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

                                            // Create session - clone fp before moving
                                            let fp_clone = peer_fp.clone();
                                            let mut guard =
                                                SessionGuard::new(fp_clone);
                                            guard.set_master_key(k);
                                            session_manager_rx
                                                .upsert(peer_fp.clone(), guard)
                                                .await;

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
                                // Data message
                                if let Ok(dec) = decrypt_message(
                                    &key_recovered,
                                    packet_counter,
                                    &mut combined.clone(),
                                ) {
                                    let text = String::from_utf8_lossy(dec);
                                    tracing::info!("[RECV] {}", text);
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

    // 7) IPC / Frontend bridge (TCP socket — cross-platform)
    let ipc_port = 9500;
    let socket_tx = Arc::clone(&socket);
    let target_addr_chat = Arc::clone(&target_addr);
    let master_key_tx = Arc::clone(&master_key_tx);
    let global_tx_counter = Arc::clone(&global_tx_counter);
    let nickname = cfg.node.nickname.clone();
    let vault_ipc = Arc::clone(&vault);

    let ipc_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ipc_port)).await?;
    tracing::info!("IPC TCP listener on port {}", ipc_port);

    tokio::spawn(async move {
        loop {
            let (mut stream, _addr) = match ipc_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("IPC accept error: {}", e);
                    continue;
                }
            };

            let nickname = nickname.clone();
            let mk = Arc::clone(&master_key_tx);
            let counter = Arc::clone(&global_tx_counter);
            let target = Arc::clone(&target_addr_chat);
            let sock = Arc::clone(&socket_tx);
            let vault = Arc::clone(&vault_ipc);

            tokio::spawn(async move {
                let mut buf = vec![0u8; 10 * 1024 * 1024]; // 10MB max
                let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };

                let payload = &buf[..n];
                let mk_guard = mk.read().await;
                if let Some(ref key) = *mk_guard {
                    let target_str = target.read().await.clone();
                    let msg = format!("{}: {}", nickname, String::from_utf8_lossy(payload).trim());
                    let mut data = msg.as_bytes().to_vec();
                    let original_len = data.len();

                    let mut c = counter.write().await;
                    *c += 1;
                    let current_c = *c;

                    // Encrypt + RS encode
                    let mut key_copy = *key;
                    encrypt_message(&key_copy, current_c, &mut data);
                    let shards = rs_encode(&mut data);
                    let shard_len = shards[0].len();

                    let id = rand::thread_rng().gen_range(1u8..254);
                    let mk_shares = shamir_split(&mut key_copy);

                    // Send via UDP
                    send_data_packets(
                        id,
                        original_len,
                        &mk_shares,
                        &shards,
                        shard_len,
                        current_c,
                        &sock,
                        &target_str,
                    );

                    // Store in vault
                    let group_id = hex::encode(&key_copy[0..4]); // simplified group ID
                    for (i, shard) in shards.iter().enumerate() {
                        let root = merkle_root(&shards);
                        if let Err(e) = vault
                            .store_shard(&group_id, i, shard, current_c, root, shards.len())
                            .await
                        {
                            tracing::warn!("Vault store error: {}", e);
                        }
                    }

                    tracing::info!("[SEND] {} ({} bytes, id={})", msg.trim(), original_len, id);
                } else {
                    let _ = tokio::io::AsyncWriteExt::write_all(
                        &mut stream,
                        b"GHOST_ERR: No handshake",
                    )
                    .await;
                }
            });
        }
    });

    // ── HTTP API Server ──
    let api_state = AppState {
        config: cfg.clone(),
        session_manager: Arc::clone(&session_manager),
        vault: Arc::clone(&vault),
        truenas: Arc::clone(&truenas),
        node_fingerprint: node_fingerprint.clone(),
    };

    let router = build_router(api_state);
    let api_addr = format!("{}:{}", cfg.api.listen_addr, cfg.api.listen_port);
    tracing::info!("API server starting on {}", api_addr);

    let listener = tokio::net::TcpListener::bind(&api_addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}