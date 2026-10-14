// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! The subset of the OCI image specification this crate reads and writes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
pub const IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// The empty JSON object used as config blob of artifacts.
pub const EMPTY_BLOB: &[u8] = b"{}";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl Descriptor {
    pub fn for_blob(media_type: &str, content: &[u8]) -> Self {
        Self {
            media_type: media_type.into(),
            digest: super::Digest::of(content).to_string(),
            size: content.len() as u64,
            annotations: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl ImageManifest {
    pub fn new(artifact_type: Option<&str>, config: Descriptor, layers: Vec<Descriptor>) -> Self {
        Self {
            schema_version: 2,
            media_type: Some(IMAGE_MANIFEST_MEDIA_TYPE.into()),
            artifact_type: artifact_type.map(str::to_string),
            config,
            layers,
            annotations: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub manifests: Vec<Descriptor>,
}

impl Default for ImageIndex {
    fn default() -> Self {
        Self {
            schema_version: 2,
            media_type: Some(IMAGE_INDEX_MEDIA_TYPE.into()),
            manifests: Vec::new(),
        }
    }
}
