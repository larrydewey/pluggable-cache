// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Two-tier cache: an in-memory LRU cache in front of a persistent one.
//!
//! Reads are served from memory when possible and fall back to the persistent
//! tier, promoting what they find. Writes go to both tiers (write-through).
//! An entry promoted from the persistent tier never outlives its expiry there.
//!
//! With a persistent tier shared between replicas, a replica's memory tier can
//! keep serving an entry another replica deleted until it is evicted or
//! expires. Size the memory tier's `ttl_secs` to bound that window.

use std::time::SystemTime;

use async_trait::async_trait;
use tracing::warn;

use crate::{
    memory::MemoryCache, persistent::PersistentCache, Cache, CacheKey, CacheStats, Result,
};

#[derive(Debug)]
pub struct TieredCache {
    memory: MemoryCache,
    persistent: PersistentCache,
}

impl TieredCache {
    pub fn new(memory: MemoryCache, persistent: PersistentCache) -> Self {
        Self { memory, persistent }
    }
}

#[async_trait]
impl Cache for TieredCache {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.memory.get(key).await? {
            return Ok(Some(value));
        }
        let Some((value, expires_at)) = self.persistent.get_with_expiry(key).await? else {
            return Ok(None);
        };

        let promoted = match expires_at {
            Some(deadline) => match deadline.duration_since(SystemTime::now()) {
                Ok(remaining) => self.memory.set_with_ttl(key, value.clone(), remaining),
                // Expired in between; serve it this once, don't promote it.
                Err(_) => Ok(()),
            },
            None => self.memory.set(key, value.clone()).await,
        };
        if let Err(e) = promoted {
            warn!("failed to promote {key} to the memory tier: {e}");
        }
        Ok(Some(value))
    }

    async fn set(&self, key: &CacheKey, value: Vec<u8>) -> Result<()> {
        self.persistent.set(key, value.clone()).await?;
        if let Err(e) = self.memory.set(key, value).await {
            // The persistent tier holds the value; drop any stale copy.
            warn!("failed to write {key} to the memory tier: {e}");
            self.memory.delete(key).await?;
        }
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        let from_memory = self.memory.delete(key).await?;
        let from_persistent = self.persistent.delete(key).await?;
        Ok(from_persistent.or(from_memory))
    }

    async fn clear(&self) -> Result<()> {
        self.memory.clear().await?;
        self.persistent.clear().await
    }

    async fn keys(&self) -> Result<Vec<CacheKey>> {
        self.persistent.keys().await
    }

    async fn stats(&self) -> Result<CacheStats> {
        let memory = self.memory.stats().await?;
        let persistent = self.persistent.stats().await?;
        Ok(CacheStats {
            // A memory miss is retried against the persistent tier, so only
            // misses there are misses of the whole cache.
            hits: memory.hits + persistent.hits,
            misses: persistent.misses,
            insertions: persistent.insertions,
            evictions: memory.evictions,
            expirations: memory.expirations + persistent.expirations,
            rejections: memory.rejections + persistent.rejections,
            entries: persistent.entries,
            capacity: None,
            bytes: memory.bytes,
            max_bytes: memory.max_bytes,
        })
    }

    async fn purge_expired(&self) -> Result<usize> {
        let memory = self.memory.purge_expired().await?;
        let persistent = self.persistent.purge_expired().await?;
        Ok(memory + persistent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{memory, persistent};
    use key_value_storage::{memory::MemoryKeyValueStorage, KeyValueStorageInstance};
    use std::sync::Arc;

    fn key(k: &str) -> CacheKey {
        CacheKey::new(k).unwrap()
    }

    fn tiered(storage: KeyValueStorageInstance) -> TieredCache {
        TieredCache::new(
            MemoryCache::new(&memory::Config::default()).unwrap(),
            PersistentCache::new(storage, &persistent::Config::default()).unwrap(),
        )
    }

    #[tokio::test]
    async fn write_through_and_promote() {
        let storage: KeyValueStorageInstance = Arc::new(MemoryKeyValueStorage::default());
        let first = tiered(storage.clone());
        first.set(&key("a"), b"v".to_vec()).await.unwrap();

        // A second instance (e.g. after restart) starts with an empty memory
        // tier and promotes from the persistent one.
        let second = tiered(storage);
        assert_eq!(second.get(&key("a")).await.unwrap(), Some(b"v".to_vec()));
        assert_eq!(second.memory.stats().await.unwrap().entries, 1);
        assert_eq!(second.get(&key("a")).await.unwrap(), Some(b"v".to_vec()));

        let stats = second.stats().await.unwrap();
        assert_eq!((stats.hits, stats.misses, stats.entries), (2, 0, 1));
    }

    #[tokio::test]
    async fn delete_removes_both_tiers() {
        let storage: KeyValueStorageInstance = Arc::new(MemoryKeyValueStorage::default());
        let cache = tiered(storage.clone());
        cache.set(&key("a"), b"v".to_vec()).await.unwrap();
        assert_eq!(cache.delete(&key("a")).await.unwrap(), Some(b"v".to_vec()));
        assert_eq!(cache.get(&key("a")).await.unwrap(), None);
        assert!(storage.list().await.unwrap().is_empty());
    }
}
