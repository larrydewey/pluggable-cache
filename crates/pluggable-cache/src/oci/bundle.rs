// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The cache bundle format, and tooling to build, sign, read and copy
//! bundles.
//!
//! A bundle is an OCI artifact: an image manifest with artifact type
//! [`BUNDLE_ARTIFACT_TYPE`], an empty config and one layer per cache entry.
//! Each layer has media type [`ENTRY_MEDIA_TYPE`] and names its namespace and
//! key in the [`NAMESPACE_ANNOTATION`] and [`KEY_ANNOTATION`] annotations.
//!
//! Because bundles are plain OCI artifacts, any OCI tooling (`oras`,
//! `skopeo`, `crane`, `cosign`, ...) can copy, mirror and sign them.

use std::collections::{BTreeMap, HashMap};

use openssl::pkey::{PKey, Private};

use super::{
    manifest::{
        Descriptor, ImageManifest, EMPTY_BLOB, EMPTY_MEDIA_TYPE, IMAGE_CONFIG_MEDIA_TYPE,
        IMAGE_MANIFEST_MEDIA_TYPE,
    },
    store::{OciStore, OciStoreWriter, MAX_MANIFEST_BYTES},
    verify::{
        sign_payload, simple_signing_payload, SIGNATURE_ANNOTATION, SIMPLE_SIGNING_MEDIA_TYPE,
    },
    Digest,
};
use crate::{preload::Entries, provider::validate_namespace, CacheError, CacheKey, Result};

pub const BUNDLE_ARTIFACT_TYPE: &str =
    "application/vnd.confidential-containers.trustee.cache-bundle.v1";
pub const ENTRY_MEDIA_TYPE: &str = "application/vnd.confidential-containers.trustee.cache-entry.v1";
pub const NAMESPACE_ANNOTATION: &str = "io.confidential-containers.trustee.cache.namespace";
pub const KEY_ANNOTATION: &str = "io.confidential-containers.trustee.cache.key";

/// Upper bound on the number of entries in a bundle.
pub const MAX_BUNDLE_ENTRIES: usize = 100_000;

/// Upper bound on the total size of a bundle's entries: 256 MiB.
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

/// The entries of a bundle, by namespace.
pub type BundleEntries = BTreeMap<String, Entries>;

/// Write `entries` as a bundle to `store`, tagged `tag`. Returns the digest
/// of the bundle manifest.
pub async fn write(
    store: &dyn OciStoreWriter,
    entries: &BundleEntries,
    tag: &str,
) -> Result<Digest> {
    store.put_blob(EMPTY_BLOB).await?;
    let mut layers = Vec::new();
    for (namespace, entries) in entries {
        validate_namespace(namespace)?;
        for (key, value) in entries {
            store.put_blob(value).await?;
            let mut layer = Descriptor::for_blob(ENTRY_MEDIA_TYPE, value);
            layer
                .annotations
                .insert(NAMESPACE_ANNOTATION.into(), namespace.clone());
            layer
                .annotations
                .insert(KEY_ANNOTATION.into(), key.to_string());
            layers.push(layer);
        }
    }
    if layers.len() > MAX_BUNDLE_ENTRIES {
        return Err(CacheError::bundle(format!(
            "bundle has {} entries, the limit is {MAX_BUNDLE_ENTRIES}",
            layers.len()
        )));
    }

    let manifest = ImageManifest::new(
        Some(BUNDLE_ARTIFACT_TYPE),
        Descriptor::for_blob(EMPTY_MEDIA_TYPE, EMPTY_BLOB),
        layers,
    );
    store
        .put_manifest(&encode(&manifest)?, IMAGE_MANIFEST_MEDIA_TYPE, Some(tag))
        .await
}

/// Read the bundle `reference` from `store`: its manifest, then its entries.
///
/// The caller is responsible for verifying the returned digest before
/// trusting the entries. To avoid downloading untrusted data, prefer
/// [`read_manifest`], verify, then [`read_entries`].
pub async fn read(
    store: &dyn OciStore,
    reference: &str,
    max_value_bytes: usize,
) -> Result<(Digest, BundleEntries)> {
    let (digest, manifest) = read_manifest(store, reference, max_value_bytes).await?;
    let entries = read_entries(store, &manifest, max_value_bytes).await?;
    Ok((digest, entries))
}

/// Fetch and check the manifest of the bundle `reference`: its type, entry
/// count, and the declared size of every entry and of all entries together.
pub async fn read_manifest(
    store: &dyn OciStore,
    reference: &str,
    max_value_bytes: usize,
) -> Result<(Digest, ImageManifest)> {
    let (content, digest) = store
        .manifest(reference)
        .await?
        .ok_or_else(|| CacheError::bundle(format!("bundle {reference} not found")))?;
    let manifest: ImageManifest = serde_json::from_slice(&content)
        .map_err(|e| CacheError::bundle(format!("malformed bundle manifest: {e}")))?;

    let is_bundle = manifest.artifact_type.as_deref() == Some(BUNDLE_ARTIFACT_TYPE)
        || manifest.config.media_type == BUNDLE_ARTIFACT_TYPE;
    if !is_bundle {
        return Err(CacheError::bundle(format!(
            "{reference} is not a cache bundle (artifact type {:?})",
            manifest.artifact_type
        )));
    }
    if manifest.layers.len() > MAX_BUNDLE_ENTRIES {
        return Err(CacheError::bundle(format!(
            "bundle has {} entries, the limit is {MAX_BUNDLE_ENTRIES}",
            manifest.layers.len()
        )));
    }
    let mut total: u64 = 0;
    for layer in &manifest.layers {
        if layer.size > max_value_bytes as u64 {
            return Err(CacheError::bundle(format!(
                "entry {} exceeds {max_value_bytes} bytes",
                layer.digest
            )));
        }
        total = total.saturating_add(layer.size);
    }
    if total > MAX_BUNDLE_BYTES {
        return Err(CacheError::bundle(format!(
            "bundle entries total {total} bytes, the limit is {MAX_BUNDLE_BYTES}"
        )));
    }
    Ok((digest, manifest))
}

/// Fetch the entries of a bundle whose manifest passed [`read_manifest`].
/// Every blob must match its declared digest and size.
pub async fn read_entries(
    store: &dyn OciStore,
    manifest: &ImageManifest,
    max_value_bytes: usize,
) -> Result<BundleEntries> {
    let mut entries = BundleEntries::new();
    for layer in &manifest.layers {
        if layer.media_type != ENTRY_MEDIA_TYPE {
            return Err(CacheError::bundle(format!(
                "unexpected layer media type `{}`",
                layer.media_type
            )));
        }
        let annotation = |name: &str| {
            layer.annotations.get(name).ok_or_else(|| {
                CacheError::bundle(format!("layer {} lacks annotation {name}", layer.digest))
            })
        };
        let namespace = annotation(NAMESPACE_ANNOTATION)?;
        validate_namespace(namespace)?;
        let key = CacheKey::new(annotation(KEY_ANNOTATION)?.as_str())?;
        // The declared size was checked against the limits; hold the blob to
        // it so the aggregate budget holds too.
        let limit = usize::try_from(layer.size)
            .unwrap_or(usize::MAX)
            .min(max_value_bytes);
        let value = store.blob(&layer.digest.parse()?, limit).await?;
        entries
            .entry(namespace.clone())
            .or_default()
            .push((key, value));
    }
    Ok(entries)
}

/// Sign the manifest `digest` in `store` with `key`, in the cosign signature
/// format, recording `docker_reference` as the signed identity.
pub async fn sign(
    store: &dyn OciStoreWriter,
    digest: &Digest,
    docker_reference: &str,
    key: &PKey<Private>,
) -> Result<Digest> {
    let payload = simple_signing_payload(docker_reference, digest);
    let signature = sign_payload(key, &payload)?;

    store.put_blob(&payload).await?;
    store.put_blob(EMPTY_BLOB).await?;
    let mut layer = Descriptor::for_blob(SIMPLE_SIGNING_MEDIA_TYPE, &payload);
    layer.annotations.insert(
        SIGNATURE_ANNOTATION.into(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature),
    );
    let manifest = ImageManifest::new(
        None,
        Descriptor::for_blob(IMAGE_CONFIG_MEDIA_TYPE, EMPTY_BLOB),
        vec![layer],
    );
    store
        .put_manifest(
            &encode(&manifest)?,
            IMAGE_MANIFEST_MEDIA_TYPE,
            Some(&digest.cosign_signature_tag()),
        )
        .await
}

/// Copy the manifest `reference` and its blobs from `from` to `to`, tagging
/// it `tag`, together with its cosign signature if there is one.
pub async fn copy(
    from: &dyn OciStore,
    to: &dyn OciStoreWriter,
    reference: &str,
    tag: &str,
    max_blob_bytes: usize,
) -> Result<Digest> {
    let digest = copy_manifest(from, to, reference, Some(tag), max_blob_bytes).await?;
    let signature_tag = digest.cosign_signature_tag();
    if from.manifest(&signature_tag).await?.is_some() {
        copy_manifest(
            from,
            to,
            &signature_tag,
            Some(&signature_tag),
            max_blob_bytes,
        )
        .await?;
    }
    Ok(digest)
}

async fn copy_manifest(
    from: &dyn OciStore,
    to: &dyn OciStoreWriter,
    reference: &str,
    tag: Option<&str>,
    max_blob_bytes: usize,
) -> Result<Digest> {
    let (content, digest) = from
        .manifest(reference)
        .await?
        .ok_or_else(|| CacheError::bundle(format!("{reference} not found")))?;
    let manifest: ImageManifest = serde_json::from_slice(&content)
        .map_err(|e| CacheError::bundle(format!("malformed manifest {reference}: {e}")))?;
    for descriptor in std::iter::once(&manifest.config).chain(&manifest.layers) {
        let limit = if descriptor.digest == manifest.config.digest {
            MAX_MANIFEST_BYTES
        } else {
            max_blob_bytes
        };
        let blob = from.blob(&descriptor.digest.parse()?, limit).await?;
        to.put_blob(&blob).await?;
    }
    let media_type = manifest
        .media_type
        .as_deref()
        .unwrap_or(IMAGE_MANIFEST_MEDIA_TYPE);
    let written = to.put_manifest(&content, media_type, tag).await?;
    debug_assert_eq!(written, digest);
    Ok(digest)
}

/// Summarize the entries of a bundle: namespace to list of keys and sizes.
pub fn summarize(entries: &BundleEntries) -> HashMap<String, Vec<(String, usize)>> {
    entries
        .iter()
        .map(|(namespace, entries)| {
            (
                namespace.clone(),
                entries
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.len()))
                    .collect(),
            )
        })
        .collect()
}

fn encode(manifest: &ImageManifest) -> Result<Vec<u8>> {
    serde_json::to_vec(manifest)
        .map_err(|e| CacheError::bundle(format!("failed to encode manifest: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{
        store::LayoutStore,
        verify::{BundleVerifier, CosignKeyVerifier},
    };
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::Public,
    };

    fn key(k: &str) -> CacheKey {
        CacheKey::new(k).unwrap()
    }

    fn sample() -> BundleEntries {
        BundleEntries::from([
            (
                "snp_vcek".to_string(),
                vec![(key("Milan/abcd/bl03"), b"vcek".to_vec())],
            ),
            ("other".to_string(), vec![(key("k"), b"v".to_vec())]),
        ])
    }

    fn signing_key() -> (PKey<Private>, PKey<Public>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let private = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let public = PKey::public_key_from_pem(&private.public_key_to_pem().unwrap()).unwrap();
        (private, public)
    }

    #[tokio::test]
    async fn write_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let written = write(&store, &sample(), "v1").await.unwrap();

        let (digest, entries) = read(&store, "v1", 1024).await.unwrap();
        assert_eq!(digest, written);
        assert_eq!(entries, sample());

        assert!(read(&store, "v1", 2).await.is_err(), "value size limit");
    }

    #[tokio::test]
    async fn rejects_non_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let manifest = ImageManifest::new(
            None,
            Descriptor::for_blob(EMPTY_MEDIA_TYPE, EMPTY_BLOB),
            vec![],
        );
        store
            .put_manifest(
                &encode(&manifest).unwrap(),
                IMAGE_MANIFEST_MEDIA_TYPE,
                Some("v1"),
            )
            .await
            .unwrap();
        assert!(read(&store, "v1", 1024).await.is_err());
    }

    #[tokio::test]
    async fn signed_bundle_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let digest = write(&store, &sample(), "v1").await.unwrap();
        let (private, public) = signing_key();

        let verifier = CosignKeyVerifier::new(vec![public]).unwrap();
        assert!(verifier.verify(&store, &digest).await.is_err(), "unsigned");

        sign(&store, &digest, "reg.io/cache", &private)
            .await
            .unwrap();
        verifier.verify(&store, &digest).await.unwrap();

        // A signature by another key is not accepted.
        let (_, other) = signing_key();
        let verifier = CosignKeyVerifier::new(vec![other]).unwrap();
        assert!(verifier.verify(&store, &digest).await.is_err());
    }

    #[tokio::test]
    async fn signature_does_not_cover_other_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let signed = write(&store, &sample(), "v1").await.unwrap();
        let (private, public) = signing_key();
        sign(&store, &signed, "reg.io/cache", &private)
            .await
            .unwrap();

        // Graft the valid signature onto a different bundle's tag.
        let mut other = sample();
        other.insert("evil".into(), vec![(key("k"), b"x".to_vec())]);
        let unsigned = write(&store, &other, "v2").await.unwrap();
        let (signature, _) = store
            .manifest(&signed.cosign_signature_tag())
            .await
            .unwrap()
            .unwrap();
        store
            .put_manifest(
                &signature,
                IMAGE_MANIFEST_MEDIA_TYPE,
                Some(&unsigned.cosign_signature_tag()),
            )
            .await
            .unwrap();

        let verifier = CosignKeyVerifier::new(vec![public]).unwrap();
        assert!(verifier.verify(&store, &unsigned).await.is_err());
    }

    #[tokio::test]
    async fn copy_carries_signature() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = LayoutStore::init(src_dir.path()).await.unwrap();
        let dst = LayoutStore::init(dst_dir.path()).await.unwrap();
        let digest = write(&src, &sample(), "v1").await.unwrap();
        let (private, public) = signing_key();
        sign(&src, &digest, "reg.io/cache", &private).await.unwrap();

        let copied = copy(&src, &dst, "v1", "mirror", 1024).await.unwrap();
        assert_eq!(copied, digest);
        let (_, entries) = read(&dst, "mirror", 1024).await.unwrap();
        assert_eq!(entries, sample());
        CosignKeyVerifier::new(vec![public])
            .unwrap()
            .verify(&dst, &digest)
            .await
            .unwrap();
    }
}
