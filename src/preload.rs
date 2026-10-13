// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable sources for seeding caches.
//!
//! A [`PreloadSource`] yields the entries of a namespace. The provider asks
//! every configured source when a namespace is first registered. Sources are
//! selected in [`PreloadSourceConfig`]; embedders can add their own with
//! [`crate::ConfiguredCacheProvider::with_preload_sources`].

use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::warn;

use crate::{CacheError, CacheKey, Result};

/// Entries for one namespace.
pub type Entries = Vec<(CacheKey, Vec<u8>)>;

#[async_trait]
pub trait PreloadSource: Debug + Send + Sync {
    /// The entries to seed `namespace` with. A source without data for the
    /// namespace returns no entries.
    async fn entries(&self, namespace: &str) -> Result<Entries>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum PreloadSourceConfig {
    /// A directory with one subdirectory per namespace.
    Directory(DirectorySourceConfig),

    /// A bundle pulled from an OCI registry.
    #[cfg(feature = "oci")]
    OciRegistry(crate::oci::RegistrySourceConfig),

    /// A bundle in an OCI image layout directory, e.g. carried into an
    /// air-gapped environment.
    #[cfg(feature = "oci")]
    OciLayout(crate::oci::LayoutSourceConfig),
}

impl PreloadSourceConfig {
    pub fn build(&self) -> Result<Arc<dyn PreloadSource>> {
        Ok(match self {
            Self::Directory(config) => Arc::new(
                DirectorySource::new(config.path.clone())
                    .with_max_value_bytes(config.max_value_bytes),
            ),
            #[cfg(feature = "oci")]
            Self::OciRegistry(config) => Arc::new(crate::oci::OciBundleSource::registry(config)?),
            #[cfg(feature = "oci")]
            Self::OciLayout(config) => Arc::new(crate::oci::OciBundleSource::layout(config)?),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectorySourceConfig {
    /// Each regular file under `<path>/<namespace>/` becomes one entry, keyed
    /// by its path relative to the namespace directory.
    pub path: PathBuf,

    /// Refuse files larger than this.
    #[serde(default = "default_max_value_bytes")]
    pub max_value_bytes: usize,
}

fn default_max_value_bytes() -> usize {
    crate::DEFAULT_MAX_VALUE_BYTES
}

/// Reads entries from `<root>/<namespace>/**`. Symbolic links and other
/// non-regular files are skipped; a file whose relative path is not a valid
/// [`CacheKey`] is an error, so misconfiguration is visible.
#[derive(Debug)]
pub struct DirectorySource {
    root: PathBuf,
    max_value_bytes: usize,
}

impl DirectorySource {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_value_bytes: crate::DEFAULT_MAX_VALUE_BYTES,
        }
    }

    pub fn with_max_value_bytes(mut self, max_value_bytes: usize) -> Self {
        self.max_value_bytes = max_value_bytes;
        self
    }
}

#[async_trait]
impl PreloadSource for DirectorySource {
    async fn entries(&self, namespace: &str) -> Result<Entries> {
        crate::provider::validate_namespace(namespace)?;
        read_tree(&self.root.join(namespace), self.max_value_bytes).await
    }
}

/// Collect every regular file under `root` as an entry keyed by its relative
/// path. A missing `root` yields no entries; a file larger than
/// `max_value_bytes` is an error, detected before it is read.
pub async fn read_tree(root: &Path, max_value_bytes: usize) -> Result<Entries> {
    let io_err = |path: &Path| {
        let path = path.to_path_buf();
        move |source| CacheError::PreloadIo { path, source }
    };

    match tokio::fs::symlink_metadata(root).await {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            warn!(path = %root.display(), "cache preload path is not a directory, ignoring");
            return Ok(Vec::new());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(root)(e)),
    }

    let mut entries = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut read_dir = tokio::fs::read_dir(&dir).await.map_err(io_err(&dir))?;
        while let Some(entry) = read_dir.next_entry().await.map_err(io_err(&dir))? {
            let path = entry.path();
            // `file_type` does not follow symlinks, so links are neither
            // traversed nor read.
            let file_type = entry.file_type().await.map_err(io_err(&path))?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let key = relative_key(root, &path)?;
                let size = entry.metadata().await.map_err(io_err(&path))?.len();
                if size > max_value_bytes as u64 {
                    return Err(CacheError::ValueTooLarge {
                        key: key.to_string(),
                        size: usize::try_from(size).unwrap_or(usize::MAX),
                        limit: max_value_bytes,
                    });
                }
                let value = tokio::fs::read(&path).await.map_err(io_err(&path))?;
                entries.push((key, value));
            } else {
                warn!(path = %path.display(), "skipping non-regular file in cache preload directory");
            }
        }
    }

    // Insert in a stable order so that eviction under pressure is predictable.
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(entries)
}

fn relative_key(root: &Path, path: &Path) -> Result<CacheKey> {
    let invalid = || CacheError::InvalidKey {
        key: path.display().to_string(),
        reason: "preload file path is not a valid cache key",
    };
    let relative = path.strip_prefix(root).map_err(|_| invalid())?;
    let segments = relative
        .components()
        .map(|c| c.as_os_str().to_str().ok_or_else(invalid))
        .collect::<Result<Vec<_>>>()?;
    CacheKey::new(segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &str) -> CacheKey {
        CacheKey::new(k).unwrap()
    }

    #[tokio::test]
    async fn reads_namespace_tree() {
        let root = tempfile::tempdir().unwrap();
        let ns_dir = root.path().join("ns");
        std::fs::create_dir_all(ns_dir.join("Milan/abcd")).unwrap();
        std::fs::write(ns_dir.join("top"), b"1").unwrap();
        std::fs::write(ns_dir.join("Milan/abcd/bl03_tee00"), b"2").unwrap();
        std::fs::create_dir_all(root.path().join("other")).unwrap();
        std::fs::write(root.path().join("other/top"), b"x").unwrap();

        let source = DirectorySource::new(root.path().to_path_buf());
        assert_eq!(
            source.entries("ns").await.unwrap(),
            vec![
                (key("Milan/abcd/bl03_tee00"), b"2".to_vec()),
                (key("top"), b"1".to_vec()),
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ignores_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"s").unwrap();

        let ns_dir = root.path().join("ns");
        std::fs::create_dir_all(&ns_dir).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), ns_dir.join("file")).unwrap();
        std::os::unix::fs::symlink(outside.path(), ns_dir.join("dir")).unwrap();

        let source = DirectorySource::new(root.path().to_path_buf());
        assert!(source.entries("ns").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_directory_is_empty() {
        let root = tempfile::tempdir().unwrap();
        let source = DirectorySource::new(root.path().to_path_buf());
        assert!(source.entries("ns").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_invalid_file_name() {
        let root = tempfile::tempdir().unwrap();
        let ns_dir = root.path().join("ns");
        std::fs::create_dir_all(&ns_dir).unwrap();
        std::fs::write(ns_dir.join("bad name"), b"1").unwrap();

        let source = DirectorySource::new(root.path().to_path_buf());
        assert!(matches!(
            source.entries("ns").await,
            Err(CacheError::InvalidKey { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("ns")).unwrap();
        std::fs::write(root.path().join("ns/big"), [0; 8]).unwrap();

        let source = DirectorySource::new(root.path().to_path_buf()).with_max_value_bytes(4);
        assert!(matches!(
            source.entries("ns").await,
            Err(CacheError::ValueTooLarge { size: 8, .. })
        ));
    }

    #[tokio::test]
    async fn rejects_namespace_traversal() {
        let root = tempfile::tempdir().unwrap();
        let source = DirectorySource::new(root.path().to_path_buf());
        assert!(source.entries("..").await.is_err());
    }
}
