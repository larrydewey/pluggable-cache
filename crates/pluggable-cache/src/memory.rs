// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! In-memory cache backend built on the generic [`LruCache`].

use std::{
    num::NonZeroUsize,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{instrument, warn};

use crate::{
    lru::LruCache, Cache, CacheError, CacheKey, CacheStats, Result, DEFAULT_MAX_VALUE_BYTES,
    DEFAULT_TTL_SECS,
};

const DEFAULT_MAX_ENTRIES: usize = 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Maximum number of entries per namespace. The least recently used entry
    /// is evicted once it is reached.
    pub max_entries: usize,

    /// Maximum total size of keys and values per namespace, in bytes. The
    /// least recently used entries are evicted to stay below it. `None`
    /// bounds memory only by `max_entries * max_value_bytes`.
    pub max_bytes: Option<usize>,

    /// Expire entries this many seconds after they were written. `null`
    /// keeps entries until they are evicted.
    pub ttl_secs: Option<u64>,

    /// Reject values larger than this.
    pub max_value_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: None,
            ttl_secs: Some(DEFAULT_TTL_SECS),
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        let invalid = |message: &str| {
            Err(CacheError::InvalidConfiguration {
                message: format!("memory.{message}"),
            })
        };
        if self.max_entries == 0 {
            return invalid("max_entries must be greater than zero");
        }
        if self.max_value_bytes == 0 {
            return invalid("max_value_bytes must be greater than zero");
        }
        if self
            .ttl_secs
            .is_some_and(|secs| secs == 0 || secs > crate::MAX_DURATION_SECS)
        {
            return invalid("ttl_secs must be between 1 and MAX_DURATION_SECS (about 100 years)");
        }
        if self.max_bytes.is_some_and(|max| max < self.max_value_bytes) {
            return invalid("max_bytes must not be smaller than max_value_bytes");
        }
        Ok(())
    }
}

// The signature is fixed by `Weigher<CacheKey, Vec<u8>>`.
#[allow(clippy::ptr_arg)]
fn entry_bytes(key: &CacheKey, value: &Vec<u8>) -> usize {
    key.as_str().len() + value.len()
}

/// A thread-safe, bounded, in-memory LRU cache of byte values.
#[derive(Debug)]
pub struct MemoryCache {
    inner: Mutex<LruCache<CacheKey, Vec<u8>>>,
    max_value_bytes: usize,
}

impl MemoryCache {
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;
        let capacity =
            NonZeroUsize::new(config.max_entries).expect("validated max_entries is non-zero");

        let mut lru = LruCache::new(capacity);
        if let Some(secs) = config.ttl_secs {
            lru = lru.with_ttl(Duration::from_secs(secs));
        }
        if let Some(max_bytes) = config.max_bytes {
            lru = lru.with_max_weight(max_bytes, entry_bytes);
        }

        Ok(Self {
            inner: Mutex::new(lru),
            max_value_bytes: config.max_value_bytes,
        })
    }

    /// Insert `value` to expire after at most `ttl`, e.g. because it was
    /// copied from a slower tier that expires it earlier.
    pub fn set_with_ttl(&self, key: &CacheKey, value: Vec<u8>, ttl: Duration) -> Result<()> {
        self.check_size(key, &value)?;
        self.lock().insert_with_ttl(key.clone(), value, ttl);
        Ok(())
    }

    fn check_size(&self, key: &CacheKey, value: &[u8]) -> Result<()> {
        if value.len() > self.max_value_bytes {
            self.lock().note_rejection();
            return Err(CacheError::ValueTooLarge {
                key: key.to_string(),
                size: value.len(),
                limit: self.max_value_bytes,
            });
        }
        Ok(())
    }

    /// The lock is only ever held for O(1) map operations and never across an
    /// `.await`, so a blocking mutex is the right tool. A poisoned lock means
    /// a panic mid-operation may have left the list inconsistent; since this is
    /// only a cache, drop its contents and carry on.
    fn lock(&self) -> MutexGuard<'_, LruCache<CacheKey, Vec<u8>>> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            warn!("memory cache lock was poisoned, clearing cache");
            let mut guard = poisoned.into_inner();
            guard.clear();
            self.inner.clear_poison();
            guard
        })
    }
}

#[async_trait]
impl Cache for MemoryCache {
    #[instrument(skip_all, name = "MemoryCache::get", fields(key = %key))]
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        Ok(self.lock().get(key).cloned())
    }

    #[instrument(skip_all, name = "MemoryCache::set", fields(key = %key))]
    async fn set(&self, key: &CacheKey, value: Vec<u8>) -> Result<()> {
        self.check_size(key, &value)?;
        self.lock().insert(key.clone(), value);
        Ok(())
    }

    #[instrument(skip_all, name = "MemoryCache::delete", fields(key = %key))]
    async fn delete(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        Ok(self.lock().remove(key))
    }

    async fn clear(&self) -> Result<()> {
        self.lock().clear();
        Ok(())
    }

    async fn keys(&self) -> Result<Vec<CacheKey>> {
        let mut lru = self.lock();
        lru.purge_expired();
        Ok(lru.keys().cloned().collect())
    }

    async fn stats(&self) -> Result<CacheStats> {
        let lru = self.lock();
        let stats = lru.stats();
        Ok(CacheStats {
            hits: stats.hits,
            misses: stats.misses,
            insertions: stats.insertions,
            evictions: stats.evictions,
            expirations: stats.expirations,
            rejections: stats.rejections,
            entries: lru.len(),
            capacity: Some(lru.capacity().get()),
            bytes: lru.max_weight().map(|_| lru.weight()),
            max_bytes: lru.max_weight(),
        })
    }

    async fn purge_expired(&self) -> Result<usize> {
        Ok(self.lock().purge_expired())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn key(k: &str) -> CacheKey {
        CacheKey::new(k).unwrap()
    }

    #[tokio::test]
    async fn round_trip() {
        let cache = MemoryCache::new(&Config::default()).unwrap();
        assert_eq!(cache.get(&key("a")).await.unwrap(), None);
        cache.set(&key("a"), b"one".to_vec()).await.unwrap();
        assert_eq!(cache.get(&key("a")).await.unwrap(), Some(b"one".to_vec()));
        assert_eq!(cache.keys().await.unwrap(), [key("a")]);
        assert_eq!(
            cache.delete(&key("a")).await.unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(cache.get(&key("a")).await.unwrap(), None);

        let stats = cache.stats().await.unwrap();
        assert_eq!((stats.hits, stats.misses, stats.entries), (1, 2, 0));
        assert_eq!(stats.capacity, Some(1024));
        assert_eq!(stats.bytes, None);
    }

    #[tokio::test]
    async fn enforces_value_limit() {
        let config = Config {
            max_value_bytes: 4,
            ..Default::default()
        };
        let cache = MemoryCache::new(&config).unwrap();
        cache.set(&key("ok"), vec![0; 4]).await.unwrap();
        assert!(matches!(
            cache.set(&key("big"), vec![0; 5]).await,
            Err(CacheError::ValueTooLarge { size: 5, .. })
        ));
        assert_eq!(cache.get(&key("big")).await.unwrap(), None);
        assert_eq!(cache.stats().await.unwrap().rejections, 1);
    }

    #[tokio::test]
    async fn enforces_entry_limit() {
        let config = Config {
            max_entries: 2,
            ..Default::default()
        };
        let cache = MemoryCache::new(&config).unwrap();
        for k in ["a", "b", "c"] {
            cache.set(&key(k), vec![]).await.unwrap();
        }
        let stats = cache.stats().await.unwrap();
        assert_eq!(
            (stats.entries, stats.capacity, stats.evictions),
            (2, Some(2), 1)
        );
        assert_eq!(cache.get(&key("a")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn enforces_byte_limit() {
        let config = Config {
            max_bytes: Some(10),
            max_value_bytes: 8,
            ..Default::default()
        };
        let cache = MemoryCache::new(&config).unwrap();
        cache.set(&key("a"), vec![0; 4]).await.unwrap(); // 5 bytes
        cache.set(&key("b"), vec![0; 4]).await.unwrap(); // 5 bytes
        cache.set(&key("c"), vec![0; 4]).await.unwrap(); // evicts "a"

        let stats = cache.stats().await.unwrap();
        assert_eq!(
            (stats.entries, stats.bytes, stats.max_bytes),
            (2, Some(10), Some(10))
        );
        assert_eq!(cache.get(&key("a")).await.unwrap(), None);
    }

    #[rstest::rstest]
    #[case(Config { max_entries: 0, ..Default::default() })]
    #[case(Config { max_value_bytes: 0, ..Default::default() })]
    #[case(Config { ttl_secs: Some(0), ..Default::default() })]
    #[case(Config { max_bytes: Some(1), ..Default::default() })]
    #[case(Config { ttl_secs: Some(u64::MAX), ..Default::default() })]
    fn rejects_invalid_config(#[case] config: Config) {
        assert!(matches!(
            MemoryCache::new(&config),
            Err(CacheError::InvalidConfiguration { .. })
        ));
    }

    #[tokio::test]
    async fn recovers_from_poisoned_lock() {
        let cache = Arc::new(MemoryCache::new(&Config::default()).unwrap());
        cache.set(&key("a"), vec![1]).await.unwrap();

        let poisoner = cache.clone();
        std::thread::spawn(move || {
            let _guard = poisoner.inner.lock().unwrap();
            panic!("poison the lock");
        })
        .join()
        .unwrap_err();

        assert_eq!(cache.get(&key("a")).await.unwrap(), None);
        cache.set(&key("a"), vec![2]).await.unwrap();
        assert_eq!(cache.get(&key("a")).await.unwrap(), Some(vec![2]));
    }

    #[tokio::test]
    async fn concurrent_access() {
        let config = Config {
            max_entries: 16,
            ..Default::default()
        };
        let cache = Arc::new(MemoryCache::new(&config).unwrap());
        let tasks: Vec<_> = (0..8)
            .map(|t| {
                let cache = cache.clone();
                tokio::spawn(async move {
                    for i in 0..500u32 {
                        let k = key(&format!("k{}", (t * 7 + i) % 32));
                        cache.set(&k, i.to_be_bytes().to_vec()).await.unwrap();
                        cache.get(&k).await.unwrap();
                    }
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        let stats = cache.stats().await.unwrap();
        assert!(stats.entries <= 16);
        assert_eq!(stats.insertions, 8 * 500);
    }
}
