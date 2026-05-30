//! WAN Shard Router
//!
//! Distributes RS-encoded file shards across geographically distributed peers.
//! Routing table maps group_id → [(peer_address, shard_index)] so that:
//!   - Data shards (0..data_shards) are stored on the primary node and trusted peers
//!   - Parity shards (data_shards..total) are stored on distinct WAN peers
//!
//! On reconstruct: if any shard is missing from the local vault, the router
//! fetches it from the peer that holds it. If enough peers are online,
//! the file can be reconstructed even with failures.

use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::config::WanPeer;

#[derive(Error, Debug)]
pub enum RouterError {
    #[error("No routing info for group {0}")]
    NoRoute(String),
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Network error fetching shard: {0}")]
    NetworkError(String),
    #[error("Timeout fetching shard from {0}")]
    Timeout(String),
}

/// Describes where a single shard lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardLocation {
    /// Peer address (ip:port)
    pub peer_addr: String,
    /// Peer nickname for display
    pub peer_nickname: String,
    /// Index of this shard in the RS encoding
    pub shard_index: usize,
    /// Whether this shard is data or parity
    pub shard_type: ShardType,
    /// Geo tag for latency optimization
    pub geo_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShardType {
    Data,
    Parity,
}

/// WAN routing entry for one group of shards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub group_id: String,
    pub total_shards: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub locations: Vec<ShardLocation>,
    pub created_at_ns: u64,
}

/// The WAN shard router.
pub struct WanRouter {
    /// Routing table: group_id → RouteEntry
    routes: Arc<RwLock<HashMap<String, RouteEntry>>>,
    /// Our own peer info (for local shards)
    our_nickname: String,
    our_address: String,
    our_public_key: String,
    /// Known WAN peers
    wan_peers: Arc<RwLock<Vec<WanPeer>>>,
    /// Map of peer_nickname → true if currently online
    peer_health: Arc<RwLock<HashMap<String, bool>>>,
}

impl WanRouter {
    pub fn new(
        our_nickname: String,
        our_address: String,
        our_public_key: String,
        wan_peers: Vec<WanPeer>,
    ) -> Self {
        let mut health = HashMap::new();
        health.insert(our_nickname.clone(), true);
        for p in &wan_peers {
            health.insert(p.nickname.clone(), false);
        }

        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            our_nickname,
            our_address,
            our_public_key,
            wan_peers: Arc::new(RwLock::new(wan_peers)),
            peer_health: Arc::new(RwLock::new(health)),
        }
    }

    /// Register a peer as online (called by heartbeat/keepalive).
    pub async fn mark_online(&self, nickname: &str) {
        let mut health = self.peer_health.write().await;
        health.insert(nickname.into(), true);
    }

    /// Mark a peer as offline.
    pub async fn mark_offline(&self, nickname: &str) {
        let mut health = self.peer_health.write().await;
        health.insert(nickname.into(), false);
    }

    /// Check if a peer is online.
    pub async fn is_online(&self, nickname: &str) -> bool {
        let health = self.peer_health.read().await;
        health.get(nickname).copied().unwrap_or(false)
    }

    /// Get all WAN peers.
    pub async fn get_wan_peers(&self) -> Vec<WanPeer> {
        self.wan_peers.read().await.clone()
    }

    /// Update the WAN peer list.
    pub async fn update_wan_peers(&self, peers: Vec<WanPeer>) {
        let mut current = self.wan_peers.write().await;
        *current = peers;
    }

    /// Compute shard placement for a new file block.
    /// Returns a RouteEntry with shard locations.
    ///
    /// Strategy:
    ///   - Shard 0 (data): local node
    ///   - Shard 1 (data): nearest online WAN peer (by geo-tag match)
    ///   - Shard 2 (parity): farthest online WAN peer
    pub async fn compute_route(
        &self,
        group_id: &str,
        total_shards: usize,
        data_shards: usize,
        parity_shards: usize,
    ) -> RouteEntry {
        let wan_peers = self.wan_peers.read().await;
        let health = self.peer_health.read().await;

        // Separate online vs offline peers
        let online_peers: Vec<&WanPeer> = wan_peers.iter()
            .filter(|p| health.get(&p.nickname).copied().unwrap_or(false))
            .collect();

        let mut locations = Vec::new();

        // Shard 0: always local
        locations.push(ShardLocation {
            peer_addr: self.our_address.clone(),
            peer_nickname: self.our_nickname.clone(),
            shard_index: 0,
            shard_type: ShardType::Data,
            geo_tag: "local".into(),
        });

        // Shard 1..data_shards: prefer online peers with same geo-tag, then any online peer
        for i in 1..data_shards {
            let peer = online_peers.get((i - 1) % online_peers.len().max(1));
            if let Some(p) = peer {
                locations.push(ShardLocation {
                    peer_addr: p.address.clone(),
                    peer_nickname: p.nickname.clone(),
                    shard_index: i,
                    shard_type: ShardType::Data,
                    geo_tag: p.geo_tag.clone(),
                });
            } else {
                // No online peers; store locally as fallback
                locations.push(ShardLocation {
                    peer_addr: self.our_address.clone(),
                    peer_nickname: self.our_nickname.clone(),
                    shard_index: i,
                    shard_type: ShardType::Data,
                    geo_tag: "local".into(),
                });
            }
        }

        // Parity shards: place on remaining peers (or locally if none available)
        for i in data_shards..total_shards {
            let peer_idx = (i - data_shards) % online_peers.len().max(1);
            let peer = online_peers.get(peer_idx);
            if let Some(p) = peer {
                locations.push(ShardLocation {
                    peer_addr: p.address.clone(),
                    peer_nickname: p.nickname.clone(),
                    shard_index: i,
                    shard_type: ShardType::Parity,
                    geo_tag: p.geo_tag.clone(),
                });
            } else {
                locations.push(ShardLocation {
                    peer_addr: self.our_address.clone(),
                    peer_nickname: self.our_nickname.clone(),
                    shard_index: i,
                    shard_type: ShardType::Parity,
                    geo_tag: "local".into(),
                });
            }
        }

        let entry = RouteEntry {
            group_id: group_id.to_string(),
            total_shards,
            data_shards,
            parity_shards,
            locations,
            created_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        };

        // Store in routing table
        self.routes.write().await.insert(group_id.to_string(), entry.clone());

        entry
    }

    /// Get route for an existing group_id.
    pub async fn get_route(&self, group_id: &str) -> Option<RouteEntry> {
        self.routes.read().await.get(group_id).cloned()
    }

    /// Get the best available shard location for reconstruction.
    /// This prefers local shards first, then online peers, then any peer.
    /// Returns a prioritized list of shard locations per index.
    pub async fn get_reconstruction_plan(
        &self,
        group_id: &str,
        have_indices: &[usize],
    ) -> Result<Vec<ShardLocation>, RouterError> {
        let entry = self.routes.read().await
            .get(group_id)
            .cloned()
            .ok_or_else(|| RouterError::NoRoute(group_id.into()))?;

        let health = self.peer_health.read().await;
        let mut plan = Vec::new();

        for loc in &entry.locations {
            if !have_indices.contains(&loc.shard_index) {
                // We need this shard — fetch from its location
                plan.push(loc.clone());
            }
        }

        // Sort plan: local first, then online peers, then offline
        plan.sort_by(|a, b| {
            let a_online = if a.peer_nickname == self.our_nickname {
                2
            } else if health.get(&a.peer_nickname).copied().unwrap_or(false) {
                1
            } else {
                0
            };
            let b_online = if b.peer_nickname == self.our_nickname {
                2
            } else if health.get(&b.peer_nickname).copied().unwrap_or(false) {
                1
            } else {
                0
            };
            b_online.cmp(&a_online)
        });

        Ok(plan)
    }

    /// Update routing table with a route discovered from a peer.
    pub async fn import_route(&self, entry: RouteEntry) {
        self.routes.write().await.insert(entry.group_id.clone(), entry);
    }

    /// Remove a route (when a file is deleted).
    pub async fn remove_route(&self, group_id: &str) {
        self.routes.write().await.remove(group_id);
    }

    /// Get all route group IDs.
    pub async fn all_group_ids(&self) -> Vec<String> {
        self.routes.read().await.keys().cloned().collect()
    }

    /// Get route count.
    pub async fn route_count(&self) -> usize {
        self.routes.read().await.len()
    }

    /// Check if we have enough shards available to reconstruct a file block.
    pub async fn can_reconstruct(&self, group_id: &str) -> bool {
        let entry = match self.routes.read().await.get(group_id) {
            Some(e) => e.clone(),
            None => return false,
        };

        let health = self.peer_health.read().await;
        let reachable = entry.locations.iter().filter(|loc| {
            loc.peer_nickname == self.our_nickname
                || health.get(&loc.peer_nickname).copied().unwrap_or(false)
        }).count();

        // We need at least `data_shards` reachable shards
        reachable >= entry.data_shards
    }

    /// Fetch a shard from a peer via TCP bulk transfer.
    /// This is a placeholder — in production, this would use the UDP/TCP
    /// transport from network.rs to request and receive shard data.
    pub async fn fetch_shard_from_peer(
        &self,
        group_id: &str,
        shard_index: usize,
        peer_addr: &str,
    ) -> Result<Vec<u8>, RouterError> {
        // TODO: Implement actual shard fetching over UDP/TCP transport
        // For now, return placeholder
        tracing::info!(
            "Would fetch shard {}/{} from peer {}",
            group_id, shard_index, peer_addr
        );
        Err(RouterError::NetworkError("Not yet implemented — connect to WAN peer first".into()))
    }

    /// Push a shard to a peer for remote storage.
    pub async fn push_shard_to_peer(
        &self,
        _group_id: &str,
        _shard_index: usize,
        _data: &[u8],
        _peer_addr: &str,
    ) -> Result<(), RouterError> {
        // TODO: Implement actual shard pushing over UDP/TCP transport
        tracing::info!("Would push shard {} to peer {}", _shard_index, _peer_addr);
        Ok(()) // Placeholder — actual transport coming in network.rs
    }
}