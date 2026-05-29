// GHOST NAS Session Guard
//
// Implements:
//   - Sliding-window replay protection (Replay Fenster)
//   - Hard and idle session timeouts (Session Timeout)
//   - Heartbeat monitoring with reactive wipe trigger
//   - Master Key Wipe on timeout (reaktive Vernichtung)
//   - Amnesic Persistence: session lives only in RAM

use tokio::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------- Constants ----------

pub const DEFAULT_WINDOW_SIZE: u64 = 128;
pub const DEFAULT_HARD_TIMEOUT: Duration = Duration::from_secs(86400);
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
pub const HEARTBEAT_MISSED_THRESHOLD: u32 = 3;

// ---------- Session State ----------

/// Serialisable session metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub peer_fingerprint: String,
    pub established_at: String,
    pub last_activity: String,
    pub expires_at: String,
    pub v_max: u64,
    pub packets_received: u64,
    pub packets_replayed: u64,
    pub is_alive: bool,
    pub is_encrypted: bool,
}

/// The master key with automatic zeroize on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; 32]);

impl MasterKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn wipe(&mut self) {
        self.0.zeroize();
        tracing::warn!("[ZEROIZE] Master key wiped from memory!");
    }
}

/// SessionGuard — per-peer session state.
pub struct SessionGuard {
    pub peer_fingerprint: String,
    pub start_time: Instant,
    pub last_activity: Instant,
    pub v_max: u64,
    pub bitmask: u128,
    pub window_size: u64,
    pub hard_timeout: Duration,
    pub idle_timeout: Duration,
    pub packets_received: u64,
    pub packets_replayed: u64,
    pub master_key: Option<MasterKey>,
    pub missed_heartbeats: u32,
}

// Manual Clone impl: MasterKey is zeroized on drop, we want copy semantics
impl Clone for SessionGuard {
    fn clone(&self) -> Self {
        let mk = self.master_key.as_ref().map(|mk| MasterKey::new(*mk.as_bytes()));
        Self {
            peer_fingerprint: self.peer_fingerprint.clone(),
            start_time: self.start_time,
            last_activity: self.last_activity,
            v_max: self.v_max,
            bitmask: self.bitmask,
            window_size: self.window_size,
            hard_timeout: self.hard_timeout,
            idle_timeout: self.idle_timeout,
            packets_received: self.packets_received,
            packets_replayed: self.packets_replayed,
            master_key: mk,
            missed_heartbeats: self.missed_heartbeats,
        }
    }
}

impl SessionGuard {
    pub fn new(peer_fingerprint: String) -> Self {
        Self {
            peer_fingerprint,
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
            window_size: DEFAULT_WINDOW_SIZE,
            hard_timeout: DEFAULT_HARD_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            packets_received: 0,
            packets_replayed: 0,
            master_key: None,
            missed_heartbeats: 0,
        }
    }

    pub fn with_timeouts(
        peer_fingerprint: String,
        hard_timeout_secs: u64,
        idle_timeout_secs: u64,
        window_size: u64,
    ) -> Self {
        Self {
            peer_fingerprint,
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
            window_size,
            hard_timeout: Duration::from_secs(hard_timeout_secs),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            packets_received: 0,
            packets_replayed: 0,
            master_key: None,
            missed_heartbeats: 0,
        }
    }

    pub fn set_master_key(&mut self, key: [u8; 32]) {
        if let Some(ref mut old) = self.master_key {
            old.wipe();
        }
        self.master_key = Some(MasterKey::new(key));
    }

    pub fn is_valid(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.start_time) < self.hard_timeout
            && now.duration_since(self.last_activity) < self.idle_timeout
    }

    pub fn is_expired(&self) -> bool {
        !self.is_valid()
    }

    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.is_valid() {
            return false;
        }

        self.packets_received += 1;

        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= self.window_size {
                self.bitmask = 1;
            } else {
                self.bitmask = (self.bitmask << shift) | 1;
            }
            self.v_max = counter;
            self.last_activity = Instant::now();
            self.missed_heartbeats = 0;
            true
        } else {
            if counter <= self.v_max.saturating_sub(self.window_size) {
                self.packets_replayed += 1;
                return false;
            }
            let offset = (self.v_max - counter) as u32;
            if (self.bitmask & (1u128 << offset)) != 0 {
                self.packets_replayed += 1;
                return false;
            }
            self.bitmask |= 1u128 << offset;
            self.last_activity = Instant::now();
            self.missed_heartbeats = 0;
            true
        }
    }

    pub fn heartbeat(&mut self) {
        self.last_activity = Instant::now();
        self.missed_heartbeats = 0;
    }

    pub fn miss_heartbeat(&mut self) -> bool {
        self.missed_heartbeats += 1;
        if self.missed_heartbeats >= HEARTBEAT_MISSED_THRESHOLD {
            tracing::warn!(
                "Heartbeat timeout for peer {} — triggering reactiver Wipe!",
                self.peer_fingerprint
            );
            self.trigger_wipe();
            true
        } else {
            false
        }
    }

    pub fn trigger_wipe(&mut self) {
        if let Some(ref mut key) = self.master_key {
            key.wipe();
            self.master_key = None;
        }
        tracing::info!(
            "[SESSION] Master key wiped for peer {}. Re-authentication required.",
            self.peer_fingerprint
        );
    }

    pub fn to_meta(&self) -> Option<SessionMeta> {
        if self.master_key.is_none() && self.start_time.elapsed().as_secs() > 10 {
            return None;
        }
        Some(SessionMeta {
            peer_fingerprint: self.peer_fingerprint.clone(),
            established_at: format_session_time(self.start_time),
            last_activity: format_session_time(self.last_activity),
            expires_at: format_session_time(
                self.start_time + self.hard_timeout,
            ),
            v_max: self.v_max,
            packets_received: self.packets_received,
            packets_replayed: self.packets_replayed,
            is_alive: self.is_valid() && self.master_key.is_some(),
            is_encrypted: self.master_key.is_some(),
        })
    }
}

// ---------- Session Manager ----------

pub struct SessionManager {
    sessions: Arc<RwLock<Vec<SessionGuard>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn upsert(&self, fp: String, session: SessionGuard) {
        let mut sessions = self.sessions.write().await;
        if let Some(existing) = sessions.iter_mut().find(|s| s.peer_fingerprint == fp) {
            if let Some(ref key) = session.master_key {
                existing.set_master_key(*key.as_bytes());
            }
            existing.last_activity = session.last_activity;
            existing.v_max = session.v_max;
            existing.bitmask = session.bitmask;
        } else {
            sessions.push(session);
        }
    }

    pub async fn find(&self, fp: &str) -> Option<SessionGuard> {
        let sessions = self.sessions.read().await;
        sessions.iter().find(|s| s.peer_fingerprint == fp).cloned()
    }

    pub async fn remove(&self, fp: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|s| {
            if s.peer_fingerprint == fp {
                // We can't mutate in retain, so we just remove
                false
            } else {
                true
            }
        });
    }

    pub async fn expire_stale(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|s| {
            if s.is_expired() {
                false
            } else {
                true
            }
        });
        before - sessions.len()
    }

    pub async fn all_meta(&self) -> Vec<SessionMeta> {
        let sessions = self.sessions.read().await;
        sessions.iter().filter_map(|s| s.to_meta()).collect()
    }

    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

// ---------- Heartbeat Monitor ----------

pub async fn heartbeat_monitor_loop(
    manager: Arc<SessionManager>,
    check_interval: Duration,
) {
    loop {
        tokio::time::sleep(check_interval).await;
        let expired = manager.expire_stale().await;
        if expired > 0 {
            tracing::info!("Heartbeat monitor expired {} stale sessions", expired);
        }
    }
}

// ---------- Helpers ----------

fn format_session_time(instant: Instant) -> String {
    let now = Instant::now();
    let elapsed = now.duration_since(instant).as_secs();
    let total_secs = if elapsed > 0 { elapsed } else { 0 };
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{:02}:{:02}:{:02} ago", hours, minutes, secs)
}

// ---------- Legacy Compatibility ----------

pub struct LegacySessionGuard {
    pub start_time: Instant,
    pub last_activity: Instant,
    pub v_max: u64,
    pub bitmask: u128,
}

impl LegacySessionGuard {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            last_activity: Instant::now(),
            v_max: 0,
            bitmask: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.start_time) < DEFAULT_HARD_TIMEOUT
            && now.duration_since(self.last_activity) < DEFAULT_IDLE_TIMEOUT
    }

    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if !self.is_valid() {
            return false;
        }
        if counter > self.v_max {
            let shift = counter - self.v_max;
            if shift >= DEFAULT_WINDOW_SIZE {
                self.bitmask = 1;
            } else {
                self.bitmask = (self.bitmask << shift) | 1;
            }
            self.v_max = counter;
            self.last_activity = Instant::now();
            true
        } else {
            if counter <= self.v_max.saturating_sub(DEFAULT_WINDOW_SIZE) {
                return false;
            }
            let offset = (self.v_max - counter) as u32;
            if (self.bitmask & (1 << offset)) != 0 {
                return false;
            }
            self.bitmask |= 1 << offset;
            self.last_activity = Instant::now();
            true
        }
    }
}