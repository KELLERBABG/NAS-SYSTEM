//! TrueNAS SCALE Middleware Bridge
//!
//! Integrates GHOST NAS with TrueNAS SCALE middleware API v2.0:
//!   - Health check & heartbeat
//!   - ZFS dataset auto-provisioning
//!   - Alert/event reporting
//!   - Quota management

use crate::config::GhostConfig;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum TrueNASError {
    #[error("Middleware request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("ZFS command failed: {0}")]
    Zfs(String),
    #[error("Authentication failed")]
    Auth,
    #[error("Dataset not found: {0}")]
    DatasetNotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrueNASHealth {
    pub system_version: String,
    pub pool_healthy: bool,
    pub dataset_mounted: bool,
    pub ghost_daemon_running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZFSDataset {
    pub name: String,
    pub pool: String,
    pub mountpoint: Option<String>,
    pub available: String,
    pub used: String,
    pub encryption: bool,
    pub encryption_root: Option<String>,
    pub quota: Option<String>,
    pub compressratio: Option<f64>,
}

pub struct TrueNASBridge {
    cfg: GhostConfig,
    client: reqwest::Client,
    cached_dataset: Arc<RwLock<Option<ZFSDataset>>>,
}

impl TrueNASBridge {
    pub fn new(cfg: &GhostConfig) -> reqwest::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", cfg.truenas.api_key).parse().unwrap(),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self {
            cfg: cfg.clone(),
            client,
            cached_dataset: Arc::new(RwLock::new(None)),
        })
    }

    /// Execute a ZFS command via `zfs` CLI (synchronous helper).
    fn zfs_exec(args: &[&str]) -> Result<String, TrueNASError> {
        let out = std::process::Command::new("zfs")
            .args(args)
            .output()
            .map_err(|e| TrueNASError::Zfs(format!("zfs exec failed: {}", e)))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(TrueNASError::Zfs(err.trim().to_string()))
        }
    }

    pub async fn provision_vault_dataset(&self) -> Result<(), TrueNASError> {
        let ds = &self.cfg.vault.dataset_name;
        match Self::zfs_exec(&["list", "-H", "-o", "name", ds]) {
            Ok(name) if name == *ds => {
                tracing::info!("Dataset {} already exists", ds);
                return Ok(());
            }
            _ => {}
        }

        let mountpoint_opt = format!("mountpoint={}", self.cfg.vault.mount_path.display());
        let quota_opt = format!("quota={}", self.cfg.vault.quota);
        let keyloc_opt = format!(
            "keylocation=file:///mnt/{}/system/ghost-vault.key",
            self.cfg.truenas.zfs_pool
        );
        let mut args = vec![
            "create",
            "-o", &mountpoint_opt,
            "-o", &quota_opt,
        ];
        if self.cfg.vault.encryption {
            args.push("-o");
            args.push("encryption=aes-256-gcm");
            args.push("-o");
            args.push("keyformat=raw");
            args.push("-o");
            args.push(&keyloc_opt);
        }
        args.push(ds);

        Self::zfs_exec(&args)?;
        tracing::info!("Created ZFS dataset {} with quota {}", ds, self.cfg.vault.quota);
        Ok(())
    }

    pub async fn set_vault_quota(&self, quota: &str) -> Result<(), TrueNASError> {
        let ds = &self.cfg.vault.dataset_name;
        Self::zfs_exec(&["set", &format!("quota={}", quota), ds])?;
        tracing::info!("Updated quota on {} to {}", ds, quota);
        Ok(())
    }

    pub async fn get_dataset_info(&self) -> Result<ZFSDataset, TrueNASError> {
        let ds = &self.cfg.vault.dataset_name;
        let out = Self::zfs_exec(&[
            "list", "-H", "-o", "name,pool,mountpoint,available,used,encryption,quota,compressratio",
            ds,
        ])?;
        let parts: Vec<&str> = out.split('\t').collect();
        if parts.len() < 8 {
            return Err(TrueNASError::DatasetNotFound(ds.clone()));
        }
        Ok(ZFSDataset {
            name: parts[0].into(),
            pool: parts[1].into(),
            mountpoint: Some(parts[2].into()),
            available: parts[3].into(),
            used: parts[4].into(),
            encryption: parts[5] == "on",
            encryption_root: None,
            quota: Some(parts[6].into()),
            compressratio: parts[7].parse().ok(),
        })
    }

    pub async fn mount_vault(&self) -> Result<(), TrueNASError> {
        let out = Self::zfs_exec(&[
            "mount", &self.cfg.vault.dataset_name,
        ]);
        match out {
            Ok(_) => {
                tracing::info!("Mounted {}", self.cfg.vault.dataset_name);
                Ok(())
            }
            Err(TrueNASError::Zfs(ref msg)) if msg.contains("already mounted") => {
                tracing::debug!("Dataset already mounted");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn health_check(&self) -> Result<TrueNASHealth, TrueNASError> {
        let url = format!("{}/system/health", self.cfg.truenas.middleware_url);
        let resp = self.client.get(&url).send().await?;
        if resp.status().is_success() {
            let health: TrueNASHealth = resp.json().await?;
            Ok(health)
        } else {
            let pool_ok = Self::zfs_exec(&[
                "list", "-H", "-o", "health", &self.cfg.truenas.zfs_pool,
            ]).unwrap_or_default().trim() == "ONLINE";
            Ok(TrueNASHealth {
                system_version: "unknown".into(),
                pool_healthy: pool_ok,
                dataset_mounted: self.cfg.vault.mount_path.exists(),
                ghost_daemon_running: true,
            })
        }
    }

    pub async fn send_alert(&self, severity: &str, message: &str) -> Result<(), TrueNASError> {
        let url = format!("{}/alert/list", self.cfg.truenas.middleware_url);
        #[derive(Serialize)]
        struct AlertPayload<'a> {
            source: &'a str,
            severity: &'a str,
            message: &'a str,
        }
        let payload = AlertPayload {
            source: "GHOST-NAS",
            severity,
            message,
        };
        let _ = self.client.post(&url).json(&payload).send().await?;
        Ok(())
    }

    pub async fn health_loop(bridge: Arc<Self>) {
        let interval = std::time::Duration::from_secs(
            bridge.cfg.truenas.health_check_interval_secs.max(10)
        );
        loop {
            match bridge.health_check().await {
                Ok(health) => {
                    tracing::info!(
                        "TrueNAS health: pool_ok={} mounted={}",
                        health.pool_healthy, health.dataset_mounted
                    );
                    if !health.dataset_mounted {
                        if let Err(e) = bridge.mount_vault().await {
                            tracing::warn!("Could not mount vault: {}", e);
                        }
                    }
                    if let Ok(info) = bridge.get_dataset_info().await {
                        *bridge.cached_dataset.write().await = Some(info);
                    }
                }
                Err(e) => tracing::warn!("TrueNAS health check failed: {}", e),
            }
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn cached_dataset(&self) -> Option<ZFSDataset> {
        self.cached_dataset.read().await.clone()
    }
}