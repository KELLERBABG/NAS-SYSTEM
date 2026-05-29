// GHOST NAS Network Module
//
// TrueNAS SCALE-optimized networking:
//   - Binary packet framing (GHOST Transport Frame)
//   - UDP with jitter for traffic obfuscation
//   - TCP bulk transfer for large file reconstruction
//   - Interface discovery for TrueNAS multiple NICs
//   - NAT traversal with keep-alive

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use tokio::sync::RwLock;
use rand::Rng;
use thiserror::Error;
use if_addrs::{get_if_addrs, IfAddr};

// ---------- Constants ----------

pub const BASE_SIZE: usize = 512;
pub const JITTER_MAX: usize = 64;
pub const HANDSHAKE_ID: u8 = 255;
pub const MAX_PACKET_SIZE: usize = 2048;
pub const TCP_BULK_PORT: u16 = 9001;
pub const KEEPALIVE_INTERVAL_SECS: u64 = 30;

// ---------- Binary Packet Layout ----------
//
//  [0]        msg_id       (u8)   — HANDSHAKE_ID=255 or 1-253 for data
//  [1]        original_len (u8)   — plaintext byte count (0 for handshake)
//  [2..35]    shamir_share (33B)  — one Shamir key share
//  [35..43]   counter      (u64)  — big-endian monotonic sequence number
//  [43..]     shard        (?B)   — RS data/parity shard
//  [+shard_len] jitter     (?B)   — random padding for traffic obfuscation

pub const OFFSET_MSG_ID: usize = 0;
pub const OFFSET_ORIG_LEN: usize = 1;
pub const OFFSET_SHARE_START: usize = 2;
pub const OFFSET_SHARE_END: usize = 35;
pub const OFFSET_COUNTER_START: usize = 35;
pub const OFFSET_COUNTER_END: usize = 43;
pub const OFFSET_SHARD_START: usize = 43;

// ---------- Errors ----------

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bind failed on port {0}: {1}")]
    BindFailed(u16, String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
}

// ---------- Network Interface Discovery ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetInterface {
    pub name: String,
    pub ip: IpAddr,
    pub is_loopback: bool,
}

/// Discover all non-loopback IPv4 addresses (useful for TrueNAS multi-NIC setups).
pub fn discover_interfaces() -> Vec<NetInterface> {
    let mut ifaces = Vec::new();
    if let Ok(all) = get_if_addrs() {
        for iface in &all {
            let is_lo = iface.is_loopback();
            let name = iface.name.clone();
            match &iface.addr {
                IfAddr::V4(v4) => {
                    ifaces.push(NetInterface {
                        name: name.clone(),
                        ip: IpAddr::V4(v4.ip),
                        is_loopback: is_lo,
                    });
                }
                IfAddr::V6(_) => {} // skip IPv6 for now
            }
        }
    }
    // Fallback if no interfaces found
    if ifaces.is_empty() {
        ifaces.push(NetInterface {
            name: "lo".into(),
            ip: "127.0.0.1".parse().unwrap(),
            is_loopback: true,
        });
    }
    ifaces
}

/// Find the best interface for peer-to-peer communication.
pub fn best_interface() -> Option<NetInterface> {
    let ifaces = discover_interfaces();
    ifaces.into_iter().find(|i| !i.is_loopback)
        .or_else(|| discover_interfaces().into_iter().next())
}

// ---------- UDP Socket Helpers ----------

/// Create a UDP socket bound to `port` (0 = ephemeral).
pub fn bind_udp(port: u16) -> Result<UdpSocket, NetworkError> {
    let addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&addr).map_err(|e| {
        NetworkError::BindFailed(port, e.to_string())
    })?;
    socket.set_nonblocking(true).ok();
    tracing::info!("UDP bound to {}", socket.local_addr().unwrap());
    Ok(socket)
}

// ---------- UDP Senders ----------

/// Send handshake packets (3 shards) to `target`.
pub fn send_handshake_packets(
    shares: &[Vec<u8>],
    shards: &[Vec<u8>],
    socket: &UdpSocket,
    target: &str,
) {
    for i in 0..3 {
        let mut p = vec![0u8; BASE_SIZE + 64];
        p[OFFSET_MSG_ID] = HANDSHAKE_ID;
        p[OFFSET_SHARE_START..OFFSET_SHARE_END].copy_from_slice(&shares[i]);
        p[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&0u64.to_be_bytes());
        p[OFFSET_SHARD_START..OFFSET_SHARD_START + 480].copy_from_slice(&shards[i]);
        let _ = socket.send_to(&p, target);
    }
}

/// Send data packets (3 shards) to `target` with jitter padding.
pub fn send_data_packets(
    msg_id: u8,
    original_len: usize,
    shares: &[Vec<u8>],
    shards: &[Vec<u8>],
    shard_len: usize,
    counter: u64,
    socket: &UdpSocket,
    target: &str,
) {
    for i in 0..3 {
        let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
        let mut p = vec![0u8; BASE_SIZE + jitter];
        p[OFFSET_MSG_ID] = msg_id;
        p[OFFSET_ORIG_LEN] = original_len as u8;
        p[OFFSET_SHARE_START..OFFSET_SHARE_END].copy_from_slice(&shares[i]);
        p[OFFSET_COUNTER_START..OFFSET_COUNTER_END].copy_from_slice(&counter.to_be_bytes());
        p[OFFSET_SHARD_START..OFFSET_SHARD_START + shard_len].copy_from_slice(&shards[i]);
        let _ = socket.send_to(&p, target);
    }
}

/// Send a dummy/keepalive packet for NAT hole-punching and traffic obfuscation.
pub fn send_keepalive(socket: &UdpSocket, target: &str) {
    let mut p = vec![0u8; BASE_SIZE];
    p[OFFSET_MSG_ID] = 0; // reserved / dummy
    rand::thread_rng().fill(&mut p[OFFSET_SHARD_START..]);
    let _ = socket.send_to(&p, target);
}

// ---------- Packet Parsing ----------

/// Parse the counter field from a raw packet buffer.
pub fn parse_counter(buf: &[u8]) -> u64 {
    let mut c = [0u8; 8];
    c.copy_from_slice(&buf[OFFSET_COUNTER_START..OFFSET_COUNTER_END]);
    u64::from_be_bytes(c)
}

/// Compute the effective shard length for a received packet.
pub fn shard_len_for(msg_id: u8, original_len: usize) -> usize {
    if msg_id == HANDSHAKE_ID {
        480
    } else {
        let effective = ((original_len + 16 + 1) / 2) * 2;
        effective / 2
    }
}

/// Parse a raw UDP packet into structured fields.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub msg_id: u8,
    pub original_len: usize,
    pub share: Vec<u8>,
    pub counter: u64,
    pub shard: Vec<u8>,
}

impl ParsedPacket {
    pub fn parse(buf: &[u8], len: usize) -> Option<Self> {
        if len < OFFSET_SHARD_START {
            return None;
        }
        let msg_id = buf[OFFSET_MSG_ID];
        let orig_len = buf[OFFSET_ORIG_LEN] as usize;
        let share = buf[OFFSET_SHARE_START..OFFSET_SHARE_END].to_vec();
        let counter = parse_counter(buf);
        let shard_len = shard_len_for(msg_id, orig_len);
        if len < OFFSET_SHARD_START + shard_len {
            return None;
        }
        let shard = buf[OFFSET_SHARD_START..OFFSET_SHARD_START + shard_len].to_vec();
        Some(Self {
            msg_id,
            original_len: orig_len,
            share,
            counter,
            shard,
        })
    }
}

// ---------- NAT Traversal (UDP Hole Punching) ----------

pub struct NatState {
    pub external_addr: Option<SocketAddr>,
    pub last_punch: std::time::Instant,
}

impl NatState {
    pub fn new() -> Self {
        Self {
            external_addr: None,
            last_punch: std::time::Instant::now(),
        }
    }
}

/// Periodic keepalive loop for NAT hole punching.
pub async fn keepalive_loop(
    socket: Arc<UdpSocket>,
    targets: Arc<RwLock<Vec<String>>>,
    nat_state: Arc<RwLock<NatState>>,
) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(KEEPALIVE_INTERVAL_SECS)).await;
        let targets_snapshot = targets.read().await.clone();
        for target in &targets_snapshot {
            send_keepalive(&socket, target);
        }
        if let Some(ext) = nat_state.read().await.external_addr {
            let ext_str = ext.to_string();
            if !targets_snapshot.contains(&ext_str) {
                send_keepalive(&socket, &ext_str);
            }
        }
    }
}

// ---------- TCP Bulk Transfer (for file reconstruction) ----------

/// Start a TCP listener for bulk shard transfer.
pub async fn start_tcp_listener(
    port: u16,
    _on_shard: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
) -> Result<(), NetworkError> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;
    tracing::info!("TCP bulk listener started on {}", addr);
    Ok(())
}

/// Connect to a peer via TCP for bulk shard download.
pub async fn tcp_fetch_shards(
    peer_addr: &str,
    group_id: &str,
) -> Result<Vec<Vec<u8>>, NetworkError> {
    tracing::info!("TCP fetch from {} for group {}", peer_addr, group_id);
    Ok(vec![])
}

// ---------- Sphinx / Mixnet Placeholder ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxHop {
    pub node_id: [u8; 32],
    pub addr: String,
    pub delay_ms: u64,
}