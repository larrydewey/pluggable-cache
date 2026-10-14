// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Persistent cache backend on top of any [`crate::store::ByteStore`].
//!
//! Entries survive restarts and, with a shared storage backend such as
//! PostgreSQL or Redis, are shared between replicas. The storage has no notion
//! of recency, so this backend bounds its size by time-to-live only.
//!
//! Each value is stored in an envelope recording its expiry as wall-clock
//! time, so that expiry is honoured across restarts and processes.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{instrument, warn};

use crate::{
    store::ByteStoreInstance, Cache, CacheError, CacheKey, CacheStats, Result,
    DEFAULT_MAX_VALUE_BYTES, DEFAULT_TTL_SECS,
};

const ENVELOPE_MAGIC: &[u8; 4] = b"TCE1";
const ENVELOPE_HEADER_LEN: usize = ENVELOPE_MAGIC.len() + 8;

/// Prefix of the storage namespace backing a cache namespace.
pub const STORAGE_NAMESPACE_PREFIX: &str = "cache_";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Name of the storage backend to keep entries in, as understood by the
    /// [`crate::store::ByteStoreProvider`]. `None` uses the provider's default
    /// backend.
    pub storage_type: Option<String>,

    /// Expire entries this many seconds after they were written. `null`
    /// keeps entries until they are deleted.
    pub ttl_secs: Option<u64>,

    /// Reject values larger than this.
    pub max_value_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage_type: None,
            ttl_secs: Some(DEFAULT_TTL_SECS),
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        let invalid = |message: &str| {
            Err(CacheError::InvalidConfiguration {
                message: format!("persistent.{message}"),
            })
        };
        if self.max_value_bytes == 0 {
            return invalid("max_value_bytes must be greater than zero");
        }
        if self
            .ttl_secs
            .is_some_and(|secs| secs == 0 || secs > crate::MAX_DURATION_SECS)
        {
            return invalid("ttl_secs must be between 1 and MAX_DURATION_SECS (about 100 years)");
        }
        Ok(())
    }
}

fn encode(value: &[u8], expires_at: Option<SystemTime>) -> Vec<u8> {
    let expiry = expires_at
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        // `0` means "never"; an expiry at the epoch is in the past anyway.
        .map_or(0, |d| d.as_secs().max(1));
    let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_LEN + value.len());
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.extend_from_slice(&expiry.to_be_bytes());
    envelope.extend_from_slice(value);
    envelope
}

fn decode(mut envelope: Vec<u8>) -> Option<(Vec<u8>, Option<SystemTime>)> {
    if envelope.len() < ENVELOPE_HEADER_LEN || &envelope[..4] != ENVELOPE_MAGIC {
        return None;
    }
    let expiry = u64::from_be_bytes(envelope[4..ENVELOPE_HEADER_LEN].try_into().ok()?);
    let expires_at = (expiry != 0).then(|| UNIX_EPOCH + Duration::from_secs(expiry));
    envelope.drain(..ENVELOPE_HEADER_LEN);
    Some((envelope, expires_at))
}

#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    insertions: AtomicU64,
    expirations: AtomicU64,
    rejections: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A cache whose entries live in a key-value storage backend.
pub struct PersistentCache {
    storage: ByteStoreInstance,
    ttl: Option<Duration>,
    max_value_bytes: usize,
    counters: Counters,
}

impl std::fmt::Debug for PersistentCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentCache")
            .field("ttl", &self.ttl)
            .field("max_value_bytes", &self.max_value_bytes)
            .finish_non_exhaustive()
    }
}

impl PersistentCache {
    pub fn new(storage: ByteStoreInstance, config: &Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            storage,
            ttl: config.ttl_secs.map(Duration::from_secs),
            max_value_bytes: config.max_value_bytes,
            counters: Counters::default(),
        })
    }

    /// Look up `key`, returning its value and when it expires.
    #[instrument(skip_all, name = "PersistentCache::get", fields(key = %key))]
    pub async fn get_with_expiry(
        &self,
        key: &CacheKey,
    ) -> Result<Option<(Vec<u8>, Option<SystemTime>)>> {
        match self.load(key).await? {
            Some(entry) => {
                bump(&self.counters.hits);
                Ok(Some(entry))
            }
            None => {
                bump(&self.counters.misses);
                Ok(None)
            }
        }
    }

    /// Read and decode `key`, dropping it if it is expired or malformed.
    async fn load(&self, key: &CacheKey) -> Result<Option<(Vec<u8>, Option<SystemTime>)>> {
        let Some(envelope) = self.storage.get(key.as_str()).await? else {
            return Ok(None);
        };

        match decode(envelope) {
            Some((value, expires_at)) if !is_expired(expires_at, SystemTime::now()) => {
                Ok(Some((value, expires_at)))
            }
            Some(_) => {
                bump(&self.counters.expirations);
                self.storage.delete(key.as_str()).await?;
                Ok(None)
            }
            None => {
                warn!("dropping malformed persistent cache entry {key}");
                self.storage.delete(key.as_str()).await?;
                Ok(None)
            }
        }
    }
}

fn is_expired(expires_at: Option<SystemTime>, now: SystemTime) -> bool {
    expires_at.is_some_and(|deadline| deadline <= now)
}

#[async_trait]
impl Cache for PersistentCache {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        Ok(self.get_with_expiry(key).await?.map(|(value, _)| value))
    }

    #[instrument(skip_all, name = "PersistentCache::set", fields(key = %key))]
    async fn set(&self, key: &CacheKey, value: Vec<u8>) -> Result<()> {
        if value.len() > self.max_value_bytes {
            bump(&self.counters.rejections);
            return Err(CacheError::ValueTooLarge {
                key: key.to_string(),
                size: value.len(),
                limit: self.max_value_bytes,
            });
        }
        let expires_at = self.ttl.map(|ttl| SystemTime::now() + ttl);
        self.storage
            .set(key.as_str(), &encode(&value, expires_at))
            .await?;
        bump(&self.counters.insertions);
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        let previous = self.storage.delete(key.as_str()).await?;
        Ok(previous
            .and_then(decode)
            .filter(|(_, expires_at)| !is_expired(*expires_at, SystemTime::now()))
            .map(|(value, _)| value))
    }

    async fn clear(&self) -> Result<()> {
        for key in self.storage.list().await? {
            self.storage.delete(&key).await?;
        }
        Ok(())
    }

    async fn keys(&self) -> Result<Vec<CacheKey>> {
        let keys = self.storage.list().await?;
        // Anything else in the namespace was not written by this backend.
        Ok(keys
            .into_iter()
            .filter_map(|key| CacheKey::new(key).ok())
            .collect())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let entries = self.storage.list().await?.len();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Ok(CacheStats {
            hits: load(&self.counters.hits),
            misses: load(&self.counters.misses),
            insertions: load(&self.counters.insertions),
            evictions: 0,
            expirations: load(&self.counters.expirations),
            rejections: load(&self.counters.rejections),
            entries,
            capacity: None,
            bytes: None,
            max_bytes: None,
        })
    }

    async fn purge_expired(&self) -> Result<usize> {
        let before = self.counters.expirations.load(Ordering::Relaxed);
        for key in self.keys().await? {
            self.load(&key).await?;
        }
        Ok((self.counters.expirations.load(Ordering::Relaxed) - before) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryByteStore;
    use std::sync::Arc;

    fn key(k: &str) -> CacheKey {
        CacheKey::new(k).unwrap()
    }

    fn cache(config: &Config) -> (PersistentCache, ByteStoreInstance) {
        let storage: ByteStoreInstance = Arc::new(MemoryByteStore::default());
        (
            PersistentCache::new(storage.clone(), config).unwrap(),
            storage,
        )
    }

    #[test]
    fn envelope_round_trip() {
        let at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(
            decode(encode(b"value", Some(at))),
            Some((b"value".to_vec(), Some(at)))
        );
        assert_eq!(decode(encode(b"", None)), Some((vec![], None)));
        assert_eq!(decode(b"junk".to_vec()), None);
    }

    #[tokio::test]
    async fn round_trip() {
        let (cache, _) = cache(&Config::default());
        cache.set(&key("a/b"), b"v".to_vec()).await.unwrap();
        assert_eq!(cache.get(&key("a/b")).await.unwrap(), Some(b"v".to_vec()));
        assert_eq!(cache.keys().await.unwrap(), [key("a/b")]);
        assert_eq!(
            cache.delete(&key("a/b")).await.unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(cache.get(&key("a/b")).await.unwrap(), None);

        let stats = cache.stats().await.unwrap();
        assert_eq!((stats.hits, stats.misses, stats.insertions), (1, 1, 1));
    }

    #[tokio::test]
    async fn expired_entries_are_dropped() {
        let (cache, storage) = cache(&Config::default());
        let past = SystemTime::now() - Duration::from_secs(1);
        storage.set("old", &encode(b"v", Some(past))).await.unwrap();
        storage
            .set("older", &encode(b"v", Some(past)))
            .await
            .unwrap();

        assert_eq!(cache.get(&key("old")).await.unwrap(), None);
        assert_eq!(cache.purge_expired().await.unwrap(), 1);
        assert!(storage.list().await.unwrap().is_empty());
        assert_eq!(cache.stats().await.unwrap().expirations, 2);
    }

    #[tokio::test]
    async fn malformed_entries_are_dropped() {
        let (cache, storage) = cache(&Config::default());
        storage.set("bad", b"not an envelope").await.unwrap();
        assert_eq!(cache.get(&key("bad")).await.unwrap(), None);
        assert!(storage.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn enforces_value_limit() {
        let (cache, _) = cache(&Config {
            max_value_bytes: 2,
            ..Default::default()
        });
        assert!(matches!(
            cache.set(&key("a"), vec![0; 3]).await,
            Err(CacheError::ValueTooLarge { .. })
        ));
        assert_eq!(cache.stats().await.unwrap().rejections, 1);
    }

    #[tokio::test]
    async fn entries_survive_new_instance() {
        let (first, storage) = cache(&Config::default());
        first.set(&key("a"), b"v".to_vec()).await.unwrap();

        let second = PersistentCache::new(storage, &Config::default()).unwrap();
        assert_eq!(second.get(&key("a")).await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn clear_removes_everything() {
        let (cache, storage) = cache(&Config::default());
        cache.set(&key("a"), vec![]).await.unwrap();
        cache.set(&key("b"), vec![]).await.unwrap();
        cache.clear().await.unwrap();
        assert!(storage.list().await.unwrap().is_empty());
    }
}
