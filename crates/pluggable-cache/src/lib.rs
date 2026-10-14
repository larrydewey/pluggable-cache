// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable, namespaced caching.
//!
//! The crate has two layers:
//!
//! - [`lru::LruCache`] is a generic, dependency-free LRU map with optional
//!   time-to-live and weight limit. It lives in the standalone `strict-lru` crate and can be
//!   used on its own.
//! - The [`Cache`] trait, its backends and [`CacheProvider`] form the pluggable
//!   layer. Components ask a provider for a cache in their own namespace and
//!   stay unaware of the backend the operator configured. Caches can be seeded
//!   from pluggable [`preload`] sources.
//!
//! Cached values are untrusted: a component must apply the same verification
//! to a cached value as to a freshly fetched one. A cache only saves the cost
//! of obtaining the value.

use std::{collections::HashMap, fmt::Debug, sync::Arc};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod disabled;
pub mod error;
pub mod key;
pub mod memory;
pub mod persistent;
pub mod preload;
pub mod provider;
pub mod store;
pub mod tiered;

#[cfg(feature = "oci")]
pub mod oci;

pub use error::{CacheError, Result};
pub use key::CacheKey;
pub use provider::{CacheProvider, ConfiguredCacheProvider};
/// The LRU core, re-exported from the standalone [`strict_lru`] crate.
pub use strict_lru as lru;

/// Default time-to-live of cache entries: one week.
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

/// Upper bound on configured durations (about 100 years), so that adding
/// them to the current time cannot overflow.
pub const MAX_DURATION_SECS: u64 = 100 * 365 * 24 * 3600;

/// Default upper bound on the size of a single cached value: 1 MiB.
pub const DEFAULT_MAX_VALUE_BYTES: usize = 1024 * 1024;

/// A namespaced cache of opaque byte values.
///
/// Values are bytes rather than a generic type so that out-of-process and
/// persistent backends work without changing callers.
#[async_trait]
pub trait Cache: Debug + Send + Sync {
    /// Look up `key`, marking it as recently used.
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>>;

    /// Insert or overwrite `key`. May evict other entries.
    async fn set(&self, key: &CacheKey, value: Vec<u8>) -> Result<()>;

    /// Remove `key`, returning its value if it was present.
    async fn delete(&self, key: &CacheKey) -> Result<Option<Vec<u8>>>;

    /// Remove all entries.
    async fn clear(&self) -> Result<()>;

    /// Keys of the stored entries.
    async fn keys(&self) -> Result<Vec<CacheKey>>;

    /// Usage counters and current occupancy.
    async fn stats(&self) -> Result<CacheStats>;

    /// Drop expired entries, returning how many were removed.
    async fn purge_expired(&self) -> Result<usize>;

    /// Seed the cache with `entries`, e.g. from an administrator-provided
    /// bundle in an air-gapped deployment. Returns how many were inserted.
    ///
    /// Preloaded entries are ordinary entries: they are subject to eviction
    /// and expiry like any other.
    async fn preload(&self, entries: Vec<(CacheKey, Vec<u8>)>) -> Result<usize> {
        let count = entries.len();
        for (key, value) in entries {
            self.set(&key, value).await?;
        }
        Ok(count)
    }
}

pub type CacheInstance = Arc<dyn Cache>;

/// Usage counters and occupancy of a single cache namespace.
///
/// Counters are local to this process, also for backends whose entries are
/// shared with other processes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub expirations: u64,
    /// Insertions refused because the value exceeded a size limit.
    pub rejections: u64,
    /// Entries currently held, possibly including expired ones not yet
    /// purged.
    pub entries: usize,
    /// Maximum number of entries, if bounded.
    pub capacity: Option<usize>,
    /// Bytes currently held, if tracked by the backend.
    pub bytes: Option<usize>,
    /// Maximum number of bytes, if bounded.
    pub max_bytes: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub enum CacheType {
    /// Bounded in-process LRU cache.
    #[default]
    #[serde(alias = "memory")]
    Memory,
    /// Entries stored in a key-value storage backend (local file system,
    /// PostgreSQL, Redis, ...). Survives restarts and, with a shared backend,
    /// is shared between replicas.
    #[serde(alias = "persistent")]
    Persistent,
    /// An in-memory LRU cache in front of a persistent one.
    #[serde(alias = "tiered")]
    Tiered,
    /// Store nothing; every lookup misses.
    #[serde(alias = "disabled")]
    Disabled,
}

/// Backend selection and settings for one cache namespace.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BackendConfig {
    pub cache_type: CacheType,

    /// Settings for [`CacheType::Memory`] and the first tier of
    /// [`CacheType::Tiered`].
    pub memory: memory::Config,

    /// Settings for [`CacheType::Persistent`] and the second tier of
    /// [`CacheType::Tiered`].
    pub persistent: persistent::Config,
}

impl BackendConfig {
    /// Check the settings without building anything.
    pub fn validate(&self) -> Result<()> {
        match self.cache_type {
            CacheType::Memory => self.memory.validate(),
            CacheType::Disabled => Ok(()),
            CacheType::Persistent => self.persistent.validate(),
            CacheType::Tiered => {
                self.memory.validate()?;
                self.persistent.validate()
            }
        }
    }
}

/// Configuration of a [`ConfiguredCacheProvider`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CacheConfig {
    /// Backend used for every namespace without an entry in `namespaces`.
    #[serde(flatten)]
    pub default: BackendConfig,

    /// Per-namespace backends, replacing `default` for that namespace.
    pub namespaces: HashMap<String, BackendConfig>,

    /// Sources to seed a namespace from when it is first registered, applied
    /// in order.
    pub preload: Vec<preload::PreloadSourceConfig>,

    /// Interval at which expired entries are purged in the background.
    /// `None` only drops expired entries when they are looked up or evicted.
    pub purge_interval_secs: Option<u64>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default: BackendConfig::default(),
            namespaces: HashMap::new(),
            preload: Vec::new(),
            purge_interval_secs: Some(3600),
        }
    }
}

impl CacheConfig {
    /// The backend settings for `namespace`.
    pub fn backend(&self, namespace: &str) -> &BackendConfig {
        self.namespaces.get(namespace).unwrap_or(&self.default)
    }

    /// Check every backend setting and the namespace names.
    pub fn validate(&self) -> Result<()> {
        self.default.validate()?;
        for (namespace, backend) in &self.namespaces {
            provider::validate_namespace(namespace)?;
            backend.validate()?;
        }
        if self
            .purge_interval_secs
            .is_some_and(|secs| secs == 0 || secs > MAX_DURATION_SECS)
        {
            return Err(CacheError::InvalidConfiguration {
                message: format!("purge_interval_secs must be between 1 and {MAX_DURATION_SECS}"),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_config() {
        let config: CacheConfig = serde_json::from_str(
            r#"{
                "cache_type": "memory",
                "memory": { "max_entries": 10, "ttl_secs": 3600 },
                "namespaces": {
                    "snp_vcek": { "cache_type": "Disabled" }
                },
                "preload": [
                    { "type": "Directory", "path": "/etc/trustee/cache" }
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(config.default.cache_type, CacheType::Memory);
        assert_eq!(config.default.memory.max_entries, 10);
        assert_eq!(config.default.memory.ttl_secs, Some(3600));
        assert_eq!(config.backend("snp_vcek").cache_type, CacheType::Disabled);
        assert_eq!(config.backend("other").cache_type, CacheType::Memory);
        assert_eq!(config.preload.len(), 1);
        config.validate().unwrap();
    }

    #[test]
    fn empty_config_uses_defaults() {
        let config: CacheConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config, CacheConfig::default());
        assert_eq!(config.default.memory.ttl_secs, Some(DEFAULT_TTL_SECS));
    }

    #[test]
    fn explicit_null_ttl_disables_expiry() {
        let config: CacheConfig =
            serde_json::from_str(r#"{ "memory": { "ttl_secs": null } }"#).unwrap();
        assert_eq!(config.default.memory.ttl_secs, None);
    }

    #[test]
    fn rejects_unknown_backend_fields() {
        assert!(serde_json::from_str::<CacheConfig>(r#"{ "memory": { "size": 1 } }"#).is_err());
    }

    #[test]
    fn validate_rejects_bad_namespace_override() {
        let config: CacheConfig =
            serde_json::from_str(r#"{ "namespaces": { "../x": {} } }"#).unwrap();
        assert!(config.validate().is_err());
    }
}
