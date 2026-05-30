use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use directories::ProjectDirs;

/// GHOST NAS Configuration — stored as TOML on the TrueNAS boot pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostConfig {
    /// General node identity
    pub node: NodeConfig,
    /// TrueNAS SCALE middleware bridge settings
    pub truenas: TrueNASConfig,
    /// ZFS Vault (Black-Hole Storage) dataset configuration
    pub vault: VaultConfig,
    /// Peer discovery and DHT
    pub network: NetworkConfig,
    /// Session policy
    pub session: SessionConfig,
    /// HTTP API / WebDAV / Web UI
    pub api: ApiConfig,
    /// NAS filesystem + WAN routing
    pub nas: NasConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Human-readable label for this GHOST node
    pub nickname: String,
    /// Path to the persistent Ed25519 identity key (created on first run)
    pub identity_path: PathBuf,
    /// The pre-shared peer whitelist (Ed25519 public key hex)
    pub allowed_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrueNASConfig {
    /// TrueNAS SCALE middleware URL (e.g. "http://localhost:8080/api/v2.0")
    pub middleware_url: String,
    /// API key for TrueNAS middleware (generate in Web UI → API Keys)
    pub api_key: String,
    /// Should GHOST auto-provision ZFS datasets?
    pub auto_provision_dataset: bool,
    /// ZFS pool to use (e.g. "tank")
    pub zfs_pool: String,
    /// Interval (seconds) for health check pings to TrueNAS
    pub health_check_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Mount point for the BHS ZFS dataset (e.g. "/mnt/tank/ghost-vault")
    pub mount_path: PathBuf,
    /// ZFS dataset name (e.g. "tank/ghost-vault")
    pub dataset_name: String,
    /// Quota for the vault dataset (e.g. "100G")
    pub quota: String,
    /// Encryption at rest for the dataset (true = ZFS native encryption)
    pub encryption: bool,
    /// Shard TTL in seconds (after which unreconstructed shards are purged)
    pub shard_ttl_secs: u64,
    /// Number of shard replicas across peers
    pub replication_factor: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// UDP listen port (0 = OS picks random ephemeral)
    pub udp_port: u16,
    /// TCP listen port for bulk shard transfer between WAN peers
    pub tcp_port: u16,
    /// DHT bootstrap nodes (host:port)
    pub bootstrap_peers: Vec<String>,
    /// Enable distributed mode (false = standalone vault only)
    pub distributed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Hard session timeout (seconds)
    pub hard_timeout_secs: u64,
    /// Idle session timeout (seconds)
    pub idle_timeout_secs: u64,
    /// Replay window size (bits)
    pub window_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// HTTP API / WebDAV / WebUI listen address
    pub listen_addr: String,
    /// API port
    pub listen_port: u16,
    /// Enable CORS for web UI integration
    pub enable_cors: bool,
    /// Path to TLS cert for HTTPS (optional — leave empty for HTTP)
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

/// NAS filesystem configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NasConfig {
    /// Share name visible to clients (e.g. "GHOST")
    pub share_name: String,
    /// Block size for file sharding in bytes (default: 1MB = 1048576)
    pub shard_block_size: usize,
    /// Number of data shards for RS encoding
    pub rs_data_shards: usize,
    /// Number of parity shards for RS encoding
    pub rs_parity_shards: usize,
    /// WAN peer routing table: peer_nickname -> (address, public_key_hex)
    pub wan_peers: Vec<WanPeer>,
    /// Path to the encrypted directory tree database
    pub directory_db_path: PathBuf,
    /// Minimum number of shards required to reconstruct a file block
    pub reconstruct_threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanPeer {
    pub nickname: String,
    pub address: String,
    pub public_key_hex: String,
    pub geo_tag: String,
}

impl Default for GhostConfig {
    fn default() -> Self {
        Self {
            node: NodeConfig {
                nickname: "GHOST-NAS".into(),
                identity_path: PathBuf::from("/mnt/tank/ghost-config/identity.key"),
                allowed_peers: vec![],
            },
            truenas: TrueNASConfig {
                middleware_url: "http://localhost:8080/api/v2.0".into(),
                api_key: String::new(),
                auto_provision_dataset: true,
                zfs_pool: "tank".into(),
                health_check_interval_secs: 30,
            },
            vault: VaultConfig {
                mount_path: PathBuf::from("/mnt/tank/ghost-vault"),
                dataset_name: "tank/ghost-vault".into(),
                quota: "100G".into(),
                encryption: true,
                shard_ttl_secs: 86400,
                replication_factor: 3,
            },
            network: NetworkConfig {
                udp_port: 0,
                tcp_port: 9001,
                bootstrap_peers: vec![],
                distributed: true,
            },
            session: SessionConfig {
                hard_timeout_secs: 86400,
                idle_timeout_secs: 1800,
                window_size: 128,
            },
            api: ApiConfig {
                listen_addr: "0.0.0.0".into(),
                listen_port: 9443,
                enable_cors: true,
                tls_cert_path: None,
                tls_key_path: None,
            },
            nas: NasConfig {
                share_name: "GHOST".into(),
                shard_block_size: 1_048_576, // 1MB
                rs_data_shards: 2,
                rs_parity_shards: 1,
                wan_peers: vec![],
                directory_db_path: PathBuf::from("/mnt/tank/ghost-vault/.meta/directory.enc"),
                reconstruct_threshold: 2,
            },
        }
    }
}

impl GhostConfig {
    /// Load configuration from a TOML file, or create a default and write it.
    pub fn load_or_create(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&raw)?)
        } else {
            let cfg = GhostConfig::default();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let raw = toml::to_string_pretty(&cfg)?;
            std::fs::write(path, &raw)?;
            tracing::info!("Created default config at {:?}", path);
            Ok(cfg)
        }
    }

    /// Resolve the config path: first CLI override, then env var, then default.
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("GHOST_CONFIG") {
            return PathBuf::from(p);
        }
        if let Some(proj) = ProjectDirs::from("com", "ghost", "ghost-nas") {
            return proj.config_dir().join("ghost_nas.toml");
        }
        PathBuf::from("/etc/ghost/ghost_nas.toml")
    }
}