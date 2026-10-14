// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The storage interface behind persistent and tiered caches.
//!
//! The crate does not ship any durable storage itself. A host application
//! adapts whatever it already uses (a key-value store, a database, a file
//! tree) to [`ByteStore`] and hands a [`ByteStoreProvider`] to the
//! [`crate::ConfiguredCacheProvider`], which mints one store per namespace.
//! [`MemoryByteStore`] is provided for tests and for wiring examples.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use crate::Result;

/// A flat, namespaced map from string keys to byte values.
///
/// Implementations need not know anything about expiry or recency; the cache
/// layers those on top.
#[async_trait]
pub trait ByteStore: Send + Sync {
    /// Store `value` under `key`, replacing any previous value.
    async fn set(&self, key: &str, value: &[u8]) -> Result<()>;

    /// The value under `key`, if any.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Remove `key`, returning the value it held.
    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// All keys in the store.
    async fn list(&self) -> Result<Vec<String>>;
}

pub type ByteStoreInstance = Arc<dyn ByteStore>;

/// Mints one isolated [`ByteStore`] per namespace.
#[async_trait]
pub trait ByteStoreProvider: Send + Sync {
    /// Check that `backend` names a backend this provider can build, without
    /// building it. Called while the cache configuration is validated so that
    /// typos fail at startup rather than when a namespace is first used.
    fn validate_backend(&self, backend: &str) -> Result<()>;

    /// The store for `namespace`, on the named `backend` or on the provider's
    /// default backend if `None`. Repeated calls for the same namespace and
    /// backend return stores over the same data.
    async fn get_or_register(
        &self,
        namespace: &str,
        backend: Option<&str>,
    ) -> Result<ByteStoreInstance>;
}

/// An in-process [`ByteStore`].
#[derive(Debug, Default)]
pub struct MemoryByteStore {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryByteStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl ByteStore for MemoryByteStore {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.lock().insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.lock().get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.lock().remove(key))
    }

    async fn list(&self) -> Result<Vec<String>> {
        Ok(self.lock().keys().cloned().collect())
    }
}

/// A [`ByteStoreProvider`] handing out [`MemoryByteStore`]s, one per
/// namespace. It accepts no named backends.
#[derive(Debug, Default)]
pub struct MemoryByteStoreProvider {
    stores: Mutex<BTreeMap<String, Arc<MemoryByteStore>>>,
}

#[async_trait]
impl ByteStoreProvider for MemoryByteStoreProvider {
    fn validate_backend(&self, backend: &str) -> Result<()> {
        Err(crate::CacheError::InvalidConfiguration {
            message: format!("unknown storage backend `{backend}`"),
        })
    }

    async fn get_or_register(
        &self,
        namespace: &str,
        backend: Option<&str>,
    ) -> Result<ByteStoreInstance> {
        if let Some(backend) = backend {
            self.validate_backend(backend)?;
        }
        let mut stores = self.stores.lock().unwrap_or_else(|e| e.into_inner());
        Ok(stores.entry(namespace.to_owned()).or_default().clone())
    }
}
