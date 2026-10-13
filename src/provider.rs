// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! On-demand provider for namespaced caches.
//!
//! Mirrors `key_value_storage::StorageProvider`: a component is handed a
//! [`CacheProvider`] and mints the namespace it needs, e.g.
//!
//! ```ignore
//! let vcek_cache = provider.get_or_register("snp_vcek").await?;
//! ```
//!
//! Every namespace is a separate cache instance, so use cases cannot collide
//! on keys or evict each other's entries.

use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::{OnceCell, RwLock};
use tracing::{debug, error, info, warn};

#[cfg(feature = "persistent")]
use key_value_storage::StorageProvider;

use crate::{
    disabled::DisabledCache, memory::MemoryCache, preload::PreloadSource, BackendConfig,
    CacheConfig, CacheError, CacheInstance, CacheType, Result,
};

/// Mints namespaced cache instances on demand.
#[async_trait]
pub trait CacheProvider: Send + Sync {
    /// Return the cache for `namespace`, creating (and preloading) it if
    /// necessary.
    ///
    /// Idempotent: repeated calls for the same namespace return the same
    /// instance.
    async fn get_or_register(&self, namespace: &str) -> Result<CacheInstance>;

    /// The namespaces registered so far, sorted by name.
    async fn namespaces(&self) -> Vec<(String, CacheInstance)>;
}

/// The default [`CacheProvider`], building every namespace from a
/// [`CacheConfig`].
pub struct ConfiguredCacheProvider {
    config: CacheConfig,
    #[cfg(feature = "persistent")]
    storage: Option<Arc<dyn StorageProvider>>,
    preload: Vec<Arc<dyn PreloadSource>>,
    /// One cell per namespace, so that building and preloading one namespace
    /// never blocks lookups of others.
    instances: RwLock<BTreeMap<String, Arc<OnceCell<CacheInstance>>>>,
}

impl std::fmt::Debug for ConfiguredCacheProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfiguredCacheProvider")
            .field("config", &self.config)
            .field("preload", &self.preload)
            .finish_non_exhaustive()
    }
}

impl ConfiguredCacheProvider {
    /// Create a provider, failing early on invalid configuration.
    ///
    /// `storage` backs [`CacheType::Persistent`] and [`CacheType::Tiered`]
    /// namespaces; it may be `None` if neither is configured.
    ///
    /// If called within a Tokio runtime and `purge_interval_secs` is set, a
    /// background task purges expired entries until the provider is dropped.
    pub fn new(
        config: CacheConfig,
        #[cfg(feature = "persistent")] storage: Option<Arc<dyn StorageProvider>>,
    ) -> Result<Arc<Self>> {
        Self::with_preload_sources(
            config,
            #[cfg(feature = "persistent")]
            storage,
            Vec::new(),
        )
    }

    /// Like [`ConfiguredCacheProvider::new`], with `extra` preload sources
    /// applied after those in the configuration.
    pub fn with_preload_sources(
        config: CacheConfig,
        #[cfg(feature = "persistent")] storage: Option<Arc<dyn StorageProvider>>,
        extra: Vec<Arc<dyn PreloadSource>>,
    ) -> Result<Arc<Self>> {
        config.validate()?;

        #[cfg(feature = "persistent")]
        {
            let needs_storage = std::iter::once(&config.default)
                .chain(config.namespaces.values())
                .any(|b| matches!(b.cache_type, CacheType::Persistent | CacheType::Tiered));
            if needs_storage && storage.is_none() {
                return Err(CacheError::InvalidConfiguration {
                    message: "persistent and tiered caches need a storage provider".into(),
                });
            }
        }

        let mut preload = config
            .preload
            .iter()
            .map(|source| source.build())
            .collect::<Result<Vec<_>>>()?;
        preload.extend(extra);

        let provider = Arc::new(Self {
            config,
            #[cfg(feature = "persistent")]
            storage,
            preload,
            instances: RwLock::new(BTreeMap::new()),
        });
        provider.spawn_purge_task();
        Ok(provider)
    }

    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Purge expired entries in every registered namespace.
    pub async fn purge_expired(&self) -> usize {
        let mut purged = 0;
        for (namespace, cache) in self.namespaces().await {
            match cache.purge_expired().await {
                Ok(n) => purged += n,
                Err(e) => warn!(namespace, "failed to purge expired cache entries: {e}"),
            }
        }
        purged
    }

    fn spawn_purge_task(self: &Arc<Self>) {
        let Some(secs) = self.config.purge_interval_secs else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            debug!("no Tokio runtime, not purging expired cache entries in the background");
            return;
        };
        let provider: Weak<Self> = Arc::downgrade(self);
        runtime.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(secs));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(provider) = provider.upgrade() else {
                    return;
                };
                let purged = provider.purge_expired().await;
                if purged > 0 {
                    debug!(purged, "purged expired cache entries");
                }
            }
        });
    }

    async fn build(&self, namespace: &str, backend: &BackendConfig) -> Result<CacheInstance> {
        Ok(match backend.cache_type {
            CacheType::Memory => Arc::new(MemoryCache::new(&backend.memory)?),
            CacheType::Disabled => Arc::new(DisabledCache),
            #[cfg(feature = "persistent")]
            CacheType::Persistent => Arc::new(self.persistent(namespace, backend).await?),
            #[cfg(feature = "persistent")]
            CacheType::Tiered => Arc::new(crate::tiered::TieredCache::new(
                MemoryCache::new(&backend.memory)?,
                self.persistent(namespace, backend).await?,
            )),
            #[cfg(not(feature = "persistent"))]
            CacheType::Persistent | CacheType::Tiered => {
                let _ = namespace;
                return Err(CacheError::InvalidConfiguration {
                    message: "persistent caches require the `persistent` feature".into(),
                });
            }
        })
    }

    #[cfg(feature = "persistent")]
    async fn persistent(
        &self,
        namespace: &str,
        backend: &BackendConfig,
    ) -> Result<crate::persistent::PersistentCache> {
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| CacheError::InvalidConfiguration {
                message: "persistent and tiered caches need a storage provider".into(),
            })?;
        let storage_namespace =
            format!("{}{namespace}", crate::persistent::STORAGE_NAMESPACE_PREFIX);
        let storage = match backend.persistent.storage_type {
            Some(storage_type) => {
                storage
                    .get_or_register_with_type(&storage_namespace, storage_type)
                    .await
            }
            None => storage.get_or_register(&storage_namespace).await,
        }
        .map_err(|e| CacheError::Backend {
            source: Box::new(e),
        })?;
        crate::persistent::PersistentCache::new(storage, &backend.persistent)
    }

    async fn preload_namespace(&self, namespace: &str, cache: &CacheInstance) -> Result<()> {
        for source in &self.preload {
            let entries = source.entries(namespace).await?;
            if entries.is_empty() {
                continue;
            }
            let requested = entries.len();
            let inserted = cache.preload(entries).await?;
            let retained = cache.stats().await?.entries;
            info!(namespace, ?source, inserted, "preloaded cache");
            if retained < inserted.min(requested) {
                warn!(
                    namespace,
                    inserted,
                    retained,
                    "preload exceeded cache capacity, some entries were evicted"
                );
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CacheProvider for ConfiguredCacheProvider {
    /// A cache is an optimization, so failing to set one up must not take
    /// the component using it down: if the backend cannot be built (e.g. its
    /// storage is unreachable), the error is logged and a [`DisabledCache`]
    /// is returned for now; the next call tries again. Invalid namespaces
    /// are still an error.
    async fn get_or_register(&self, namespace: &str) -> Result<CacheInstance> {
        validate_namespace(namespace)?;

        let cell = {
            let existing = self.instances.read().await.get(namespace).cloned();
            match existing {
                Some(cell) => cell,
                None => self
                    .instances
                    .write()
                    .await
                    .entry(namespace.to_string())
                    .or_default()
                    .clone(),
            }
        };

        // Concurrent callers for the same namespace wait for one
        // initialization; callers for other namespaces are not blocked.
        let init = cell
            .get_or_try_init(|| async {
                let backend = self.config.backend(namespace);
                let cache = self.build(namespace, backend).await?;
                if let Err(e) = self.preload_namespace(namespace, &cache).await {
                    error!(namespace, "failed to preload cache: {e}");
                }
                info!(namespace, cache_type = ?backend.cache_type, "registered cache namespace");
                Ok::<_, CacheError>(cache)
            })
            .await;
        match init {
            Ok(cache) => Ok(cache.clone()),
            Err(e) => {
                error!(namespace, "cache unavailable, continuing without it: {e}");
                Ok(Arc::new(DisabledCache))
            }
        }
    }

    async fn namespaces(&self) -> Vec<(String, CacheInstance)> {
        self.instances
            .read()
            .await
            .iter()
            .filter_map(|(namespace, cell)| Some((namespace.clone(), cell.get()?.clone())))
            .collect()
    }
}

/// Namespaces double as directory names, storage table names and metric
/// labels, so they are restricted to lowercase ASCII alphanumerics and `_`.
pub fn validate_namespace(namespace: &str) -> Result<()> {
    let valid = !namespace.is_empty()
        && namespace.len() <= 64
        && namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        return Err(CacheError::InvalidNamespace {
            namespace: namespace.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{memory, preload, CacheKey};
    use std::path::PathBuf;

    fn key(k: &str) -> CacheKey {
        CacheKey::new(k).unwrap()
    }

    fn new_provider(config: CacheConfig) -> Result<Arc<ConfiguredCacheProvider>> {
        ConfiguredCacheProvider::new(
            config,
            #[cfg(feature = "persistent")]
            None,
        )
    }

    fn memory_provider(preload_dir: Option<PathBuf>) -> Arc<ConfiguredCacheProvider> {
        new_provider(CacheConfig {
            preload: preload_dir
                .into_iter()
                .map(|path| {
                    preload::PreloadSourceConfig::Directory(preload::DirectorySourceConfig {
                        path,
                        max_value_bytes: crate::DEFAULT_MAX_VALUE_BYTES,
                    })
                })
                .collect(),
            ..Default::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn get_or_register_is_idempotent() {
        let provider = memory_provider(None);
        let first = provider.get_or_register("ns").await.unwrap();
        first.set(&key("k"), b"v".to_vec()).await.unwrap();

        let second = provider.get_or_register("ns").await.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn namespaces_are_isolated_and_listed() {
        let provider = memory_provider(None);
        let a = provider.get_or_register("a").await.unwrap();
        let b = provider.get_or_register("b").await.unwrap();
        a.set(&key("k"), b"v".to_vec()).await.unwrap();
        assert_eq!(b.get(&key("k")).await.unwrap(), None);

        let names: Vec<_> = provider
            .namespaces()
            .await
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[rstest::rstest]
    #[case("")]
    #[case(".")]
    #[case("..")]
    #[case("a/b")]
    #[case("with-dash")]
    #[case("Upper")]
    #[case("with space")]
    #[tokio::test]
    async fn rejects_invalid_namespace(#[case] namespace: &str) {
        let provider = memory_provider(None);
        assert!(matches!(
            provider.get_or_register(namespace).await,
            Err(CacheError::InvalidNamespace { .. })
        ));
    }

    #[test]
    fn new_rejects_invalid_backend_config() {
        let config = CacheConfig {
            default: BackendConfig {
                memory: memory::Config {
                    max_entries: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(new_provider(config).is_err());
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn persistent_requires_storage() {
        let config = CacheConfig {
            default: BackendConfig {
                cache_type: CacheType::Persistent,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(new_provider(config).is_err());
    }

    #[tokio::test]
    async fn per_namespace_backend() {
        let mut config = CacheConfig::default();
        config.namespaces.insert(
            "off".into(),
            BackendConfig {
                cache_type: CacheType::Disabled,
                ..Default::default()
            },
        );
        let provider = new_provider(config).unwrap();

        let off = provider.get_or_register("off").await.unwrap();
        off.set(&key("k"), b"v".to_vec()).await.unwrap();
        assert_eq!(off.get(&key("k")).await.unwrap(), None);

        let on = provider.get_or_register("on").await.unwrap();
        on.set(&key("k"), b"v".to_vec()).await.unwrap();
        assert_eq!(on.get(&key("k")).await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn preloads_from_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("ns")).unwrap();
        std::fs::write(root.path().join("ns/k"), b"v").unwrap();

        let provider = memory_provider(Some(root.path().to_path_buf()));
        let cache = provider.get_or_register("ns").await.unwrap();
        assert_eq!(cache.get(&key("k")).await.unwrap(), Some(b"v".to_vec()));
    }

    #[derive(Debug)]
    struct StaticSource;

    #[async_trait]
    impl PreloadSource for StaticSource {
        async fn entries(&self, namespace: &str) -> Result<preload::Entries> {
            Ok(vec![(key("from"), namespace.as_bytes().to_vec())])
        }
    }

    #[tokio::test]
    async fn custom_preload_source() {
        let provider = ConfiguredCacheProvider::with_preload_sources(
            CacheConfig::default(),
            #[cfg(feature = "persistent")]
            None,
            vec![Arc::new(StaticSource)],
        )
        .unwrap();
        let cache = provider.get_or_register("ns").await.unwrap();
        assert_eq!(cache.get(&key("from")).await.unwrap(), Some(b"ns".to_vec()));
    }

    #[cfg(feature = "persistent")]
    #[tokio::test]
    async fn persistent_and_tiered_namespaces() {
        use key_value_storage::{KeyValueStorageStructConfig, KvStorageProvider};

        let storage = KvStorageProvider::new(key_value_storage::StorageBackendConfig {
            storage_type: key_value_storage::KeyValueStorageType::Memory,
            backends: KeyValueStorageStructConfig::default(),
        });
        let mut config = CacheConfig {
            default: BackendConfig {
                cache_type: CacheType::Tiered,
                ..Default::default()
            },
            ..Default::default()
        };
        config.namespaces.insert(
            "plain".into(),
            BackendConfig {
                cache_type: CacheType::Persistent,
                ..Default::default()
            },
        );
        let provider = ConfiguredCacheProvider::new(config, Some(storage.clone())).unwrap();

        for namespace in ["tiered", "plain"] {
            let cache = provider.get_or_register(namespace).await.unwrap();
            cache.set(&key("k"), b"v".to_vec()).await.unwrap();
            let backing = storage
                .get_or_register(&format!("cache_{namespace}"))
                .await
                .unwrap();
            assert_eq!(backing.list().await.unwrap(), ["k"]);
        }
    }

    #[cfg(feature = "persistent")]
    #[tokio::test]
    async fn unavailable_backend_falls_back_to_disabled() {
        use key_value_storage::{KeyValueStorageInstance, KeyValueStorageType, Result as KvResult};

        struct Unreachable;

        #[async_trait]
        impl StorageProvider for Unreachable {
            async fn get_or_register(&self, _: &str) -> KvResult<KeyValueStorageInstance> {
                Err(
                    key_value_storage::KeyValueStorageError::InvalidConfiguration {
                        message: "down".into(),
                    },
                )
            }

            async fn get_or_register_with_type(
                &self,
                namespace: &str,
                _: KeyValueStorageType,
            ) -> KvResult<KeyValueStorageInstance> {
                self.get_or_register(namespace).await
            }
        }

        let config = CacheConfig {
            default: BackendConfig {
                cache_type: CacheType::Persistent,
                ..Default::default()
            },
            ..Default::default()
        };
        let provider = ConfiguredCacheProvider::new(config, Some(Arc::new(Unreachable))).unwrap();
        let cache = provider.get_or_register("ns").await.unwrap();
        cache.set(&key("k"), b"v".to_vec()).await.unwrap();
        assert_eq!(cache.get(&key("k")).await.unwrap(), None);
        assert!(
            provider.namespaces().await.is_empty(),
            "retried on next use"
        );
    }

    #[tokio::test]
    async fn purge_expired_covers_all_namespaces() {
        let provider = memory_provider(None);
        provider.get_or_register("a").await.unwrap();
        assert_eq!(provider.purge_expired().await, 0);
    }
}
