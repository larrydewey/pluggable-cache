// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A cache backend that stores nothing.

use async_trait::async_trait;

use crate::{Cache, CacheKey, CacheStats, Result};

/// Discards every write, so every lookup misses. Lets operators switch
/// caching off without changing the code paths that use it.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledCache;

#[async_trait]
impl Cache for DisabledCache {
    async fn get(&self, _key: &CacheKey) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn set(&self, _key: &CacheKey, _value: Vec<u8>) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, _key: &CacheKey) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn clear(&self) -> Result<()> {
        Ok(())
    }

    async fn keys(&self) -> Result<Vec<CacheKey>> {
        Ok(Vec::new())
    }

    async fn stats(&self) -> Result<CacheStats> {
        Ok(CacheStats {
            capacity: Some(0),
            ..Default::default()
        })
    }

    async fn purge_expired(&self) -> Result<usize> {
        Ok(0)
    }

    async fn preload(&self, _entries: Vec<(CacheKey, Vec<u8>)>) -> Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_nothing() {
        let cache = DisabledCache;
        let key = CacheKey::new("a").unwrap();
        cache.set(&key, vec![1]).await.unwrap();
        assert_eq!(cache.get(&key).await.unwrap(), None);
        assert_eq!(cache.preload(vec![(key, vec![1])]).await.unwrap(), 0);
    }
}
