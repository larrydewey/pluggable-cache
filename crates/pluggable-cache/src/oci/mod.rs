// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Preloading caches from OCI artifacts.
//!
//! A [`bundle`] of cache entries is pulled from any OCI distribution registry
//! or read from an OCI image layout directory, checked by a pluggable
//! [`verify::BundleVerifier`], and served to the provider namespace by
//! namespace. The bundle is loaded once, on first use.

use std::{collections::BTreeMap, fmt::Debug, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::OnceCell;
use tracing::info;

pub mod bundle;
pub mod manifest;
pub mod reference;
pub mod store;
pub mod verify;

pub use reference::{Digest, Reference};
pub use store::{Credentials, LayoutStore, OciStore, OciStoreWriter, RegistryStore};
pub use verify::{BundleVerifier, VerificationConfig};

use crate::{
    preload::{Entries, PreloadSource},
    provider::validate_namespace,
    CacheError, Result, DEFAULT_MAX_VALUE_BYTES,
};

fn default_max_value_bytes() -> usize {
    DEFAULT_MAX_VALUE_BYTES
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrySourceConfig {
    /// `registry/repository:tag` or `registry/repository@sha256:...`. Pinning
    /// a digest makes the source immutable.
    pub reference: String,

    /// How the bundle is authenticated. Required, so that skipping
    /// verification is always an explicit choice.
    pub verification: VerificationConfig,

    /// Use plain HTTP. The bundle signature is still verified, but registry
    /// credentials and bundle contents are exposed on the network.
    #[serde(default)]
    pub insecure_http: bool,

    /// Registry user name, if the registry requires authentication.
    #[serde(default)]
    pub username: Option<String>,

    /// File holding the registry password or token.
    #[serde(default)]
    pub password_file: Option<PathBuf>,

    /// Reject entries larger than this.
    #[serde(default = "default_max_value_bytes")]
    pub max_value_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LayoutSourceConfig {
    /// Root of the OCI image layout.
    pub path: PathBuf,

    /// Tag (`org.opencontainers.image.ref.name`) or digest of the bundle.
    pub reference: String,

    /// How the bundle is authenticated.
    pub verification: VerificationConfig,

    /// Reject entries larger than this.
    #[serde(default = "default_max_value_bytes")]
    pub max_value_bytes: usize,
}

/// A [`PreloadSource`] reading a verified bundle from an [`OciStore`].
pub struct OciBundleSource {
    description: String,
    store: Arc<dyn OciStore>,
    reference: String,
    verifier: Arc<dyn BundleVerifier>,
    max_value_bytes: usize,
    loaded: OnceCell<BTreeMap<String, Entries>>,
}

impl Debug for OciBundleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.description)
    }
}

impl OciBundleSource {
    pub fn new(
        description: String,
        store: Arc<dyn OciStore>,
        reference: String,
        verifier: Arc<dyn BundleVerifier>,
        max_value_bytes: usize,
    ) -> Self {
        Self {
            description,
            store,
            reference,
            verifier,
            max_value_bytes,
            loaded: OnceCell::new(),
        }
    }

    pub fn registry(config: &RegistrySourceConfig) -> Result<Self> {
        let reference: Reference = config.reference.parse()?;
        let credentials = match (&config.username, &config.password_file) {
            (Some(username), Some(path)) => {
                let password =
                    std::fs::read_to_string(path).map_err(|source| CacheError::PreloadIo {
                        path: path.clone(),
                        source,
                    })?;
                Some(Credentials {
                    username: username.clone(),
                    password: password.trim_end().to_string(),
                })
            }
            (None, None) => None,
            _ => {
                return Err(CacheError::InvalidConfiguration {
                    message: "OCI registry username and password_file must be set together".into(),
                })
            }
        };
        let store = RegistryStore::new(&reference, config.insecure_http, credentials, false)?;
        Ok(Self::new(
            format!("OCI registry bundle {reference}"),
            Arc::new(store),
            reference.manifest_reference(),
            config.verification.build()?,
            config.max_value_bytes,
        ))
    }

    pub fn layout(config: &LayoutSourceConfig) -> Result<Self> {
        if !reference::is_valid_manifest_reference(&config.reference) {
            return Err(CacheError::InvalidConfiguration {
                message: format!("invalid OCI layout reference `{}`", config.reference),
            });
        }
        Ok(Self::new(
            format!(
                "OCI layout bundle {}:{}",
                config.path.display(),
                config.reference
            ),
            Arc::new(LayoutStore::new(config.path.clone())),
            config.reference.clone(),
            config.verification.build()?,
            config.max_value_bytes,
        ))
    }

    async fn load(&self) -> Result<BTreeMap<String, Entries>> {
        // Verify the signature before downloading any entry, so untrusted
        // bundles cost no more than their manifest.
        let (digest, manifest) =
            bundle::read_manifest(self.store.as_ref(), &self.reference, self.max_value_bytes)
                .await?;
        self.verifier.verify(self.store.as_ref(), &digest).await?;
        let entries =
            bundle::read_entries(self.store.as_ref(), &manifest, self.max_value_bytes).await?;
        info!(
            source = %self.description,
            %digest,
            namespaces = entries.len(),
            "loaded verified cache bundle"
        );
        Ok(entries)
    }
}

#[async_trait]
impl PreloadSource for OciBundleSource {
    async fn entries(&self, namespace: &str) -> Result<Entries> {
        validate_namespace(namespace)?;
        let bundle = self.loaded.get_or_try_init(|| self.load()).await?;
        Ok(bundle.get(namespace).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CacheKey;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };

    #[tokio::test]
    async fn layout_source_requires_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let entries = bundle::BundleEntries::from([(
            "ns".to_string(),
            vec![(CacheKey::new("k").unwrap(), b"v".to_vec())],
        )]);
        let digest = bundle::write(&store, &entries, "v1").await.unwrap();

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let private = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let key_path = dir.path().join("cosign.pub");
        std::fs::write(&key_path, private.public_key_to_pem().unwrap()).unwrap();

        let config: LayoutSourceConfig = serde_json::from_value(serde_json::json!({
            "path": dir.path(),
            "reference": "v1",
            "verification": { "type": "CosignPublicKey", "public_keys": [key_path] }
        }))
        .unwrap();

        let unsigned = OciBundleSource::layout(&config).unwrap();
        assert!(matches!(
            unsigned.entries("ns").await,
            Err(CacheError::BundleVerification { .. })
        ));

        bundle::sign(&store, &digest, "local/cache", &private)
            .await
            .unwrap();
        let signed = OciBundleSource::layout(&config).unwrap();
        assert_eq!(signed.entries("ns").await.unwrap().len(), 1);
        assert!(signed.entries("other").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn entries_not_fetched_before_verification() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let entries = bundle::BundleEntries::from([(
            "ns".to_string(),
            vec![(CacheKey::new("k").unwrap(), b"entry".to_vec())],
        )]);
        bundle::write(&store, &entries, "v1").await.unwrap();
        // Without the entry blob, fetching it first would fail with an I/O
        // error instead of the verification error.
        std::fs::remove_file(
            dir.path()
                .join("blobs/sha256")
                .join(crate::oci::Digest::of(b"entry").hex()),
        )
        .unwrap();

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let key_path = dir.path().join("cosign.pub");
        std::fs::write(&key_path, key.public_key_to_pem().unwrap()).unwrap();
        let config: LayoutSourceConfig = serde_json::from_value(serde_json::json!({
            "path": dir.path(),
            "reference": "v1",
            "verification": { "type": "CosignPublicKey", "public_keys": [key_path] }
        }))
        .unwrap();
        assert!(matches!(
            OciBundleSource::layout(&config)
                .unwrap()
                .entries("ns")
                .await,
            Err(CacheError::BundleVerification { .. })
        ));
    }

    #[test]
    fn verification_is_required() {
        let config = serde_json::from_value::<RegistrySourceConfig>(serde_json::json!({
            "reference": "reg.io/cache:v1"
        }));
        assert!(config.is_err());
    }

    #[test]
    fn credentials_must_be_complete() {
        let config: RegistrySourceConfig = serde_json::from_value(serde_json::json!({
            "reference": "reg.io/cache:v1",
            "verification": { "type": "Unverified" },
            "username": "user"
        }))
        .unwrap();
        assert!(OciBundleSource::registry(&config).is_err());
    }
}
