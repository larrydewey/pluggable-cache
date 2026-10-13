// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Content stores: OCI image layout directories and OCI distribution
//! registries. Every blob and manifest read is checked against its digest.

use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::Mutex,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{header, Client, Method, RequestBuilder, Response, StatusCode, Url};
use serde::Deserialize;
use tracing::debug;

use super::{
    manifest::{
        Descriptor, ImageIndex, DOCKER_MANIFEST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE,
        REF_NAME_ANNOTATION,
    },
    reference::{is_valid_manifest_reference, Digest, Reference},
};
use crate::{CacheError, Result};

/// Upper bound on the size of a manifest or index.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

const OCI_LAYOUT_FILE: &str = "oci-layout";
const OCI_LAYOUT_CONTENT: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;

/// Read access to manifests and blobs.
#[async_trait]
pub trait OciStore: Debug + Send + Sync {
    /// Fetch the manifest named by `reference` (a tag or digest). Returns
    /// `None` if it does not exist.
    async fn manifest(&self, reference: &str) -> Result<Option<(Vec<u8>, Digest)>>;

    /// Fetch the blob `digest`, failing if it is larger than `max_bytes`.
    async fn blob(&self, digest: &Digest, max_bytes: usize) -> Result<Vec<u8>>;
}

/// Write access, used by bundle tooling.
#[async_trait]
pub trait OciStoreWriter: OciStore {
    async fn put_blob(&self, content: &[u8]) -> Result<Digest>;

    /// Store a manifest and, if `tag` is given, point the tag at it.
    async fn put_manifest(
        &self,
        content: &[u8],
        media_type: &str,
        tag: Option<&str>,
    ) -> Result<Digest>;
}

fn check_reference(reference: &str) -> Result<()> {
    if !is_valid_manifest_reference(reference) {
        return Err(CacheError::bundle(format!(
            "invalid tag or digest `{reference}`"
        )));
    }
    Ok(())
}

/// An OCI image layout directory.
#[derive(Debug)]
pub struct LayoutStore {
    root: PathBuf,
}

impl LayoutStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Create an empty layout at `root` if there is none.
    pub async fn init(root: impl Into<PathBuf>) -> Result<Self> {
        let store = Self::new(root);
        let blobs = store.root.join("blobs/sha256");
        tokio::fs::create_dir_all(&blobs)
            .await
            .map_err(io_err(&blobs))?;
        let layout = store.root.join(OCI_LAYOUT_FILE);
        if !tokio::fs::try_exists(&layout)
            .await
            .map_err(io_err(&layout))?
        {
            tokio::fs::write(&layout, OCI_LAYOUT_CONTENT)
                .await
                .map_err(io_err(&layout))?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        // `Digest` admits only hex, so this cannot leave `blobs/sha256`.
        self.root.join("blobs/sha256").join(digest.hex())
    }

    pub async fn index(&self) -> Result<ImageIndex> {
        let path = self.root.join("index.json");
        match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| CacheError::bundle(format!("malformed {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ImageIndex::default()),
            Err(e) => Err(io_err(&path)(e)),
        }
    }

    async fn write_index(&self, index: &ImageIndex) -> Result<()> {
        let path = self.root.join("index.json");
        let bytes = serde_json::to_vec_pretty(index)
            .map_err(|e| CacheError::bundle(format!("failed to encode index: {e}")))?;
        tokio::fs::write(&path, bytes).await.map_err(io_err(&path))
    }

    async fn read_blob(&self, digest: &Digest, max_bytes: usize) -> Result<Vec<u8>> {
        let path = self.blob_path(digest);
        let meta = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(io_err(&path))?;
        if !meta.is_file() {
            return Err(CacheError::bundle(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        if meta.len() > max_bytes as u64 {
            return Err(too_large(digest, max_bytes));
        }
        let content = tokio::fs::read(&path).await.map_err(io_err(&path))?;
        digest.verify(&content)?;
        Ok(content)
    }
}

#[async_trait]
impl OciStore for LayoutStore {
    async fn manifest(&self, reference: &str) -> Result<Option<(Vec<u8>, Digest)>> {
        check_reference(reference)?;
        let digest = match reference.parse::<Digest>() {
            Ok(digest) => digest,
            Err(_) => {
                let index = self.index().await?;
                let Some(descriptor) = index.manifests.iter().find(|d| {
                    d.annotations.get(REF_NAME_ANNOTATION).map(String::as_str) == Some(reference)
                }) else {
                    return Ok(None);
                };
                descriptor.digest.parse()?
            }
        };
        match self.read_blob(&digest, MAX_MANIFEST_BYTES).await {
            Ok(content) => Ok(Some((content, digest))),
            Err(CacheError::PreloadIo { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    async fn blob(&self, digest: &Digest, max_bytes: usize) -> Result<Vec<u8>> {
        self.read_blob(digest, max_bytes).await
    }
}

#[async_trait]
impl OciStoreWriter for LayoutStore {
    async fn put_blob(&self, content: &[u8]) -> Result<Digest> {
        let digest = Digest::of(content);
        let path = self.blob_path(&digest);
        tokio::fs::write(&path, content)
            .await
            .map_err(io_err(&path))?;
        Ok(digest)
    }

    async fn put_manifest(
        &self,
        content: &[u8],
        media_type: &str,
        tag: Option<&str>,
    ) -> Result<Digest> {
        let digest = self.put_blob(content).await?;
        let Some(tag) = tag else {
            return Ok(digest);
        };
        check_reference(tag)?;

        let mut index = self.index().await?;
        index
            .manifests
            .retain(|d| d.annotations.get(REF_NAME_ANNOTATION).map(String::as_str) != Some(tag));
        let mut descriptor = Descriptor::for_blob(media_type, content);
        descriptor
            .annotations
            .insert(REF_NAME_ANNOTATION.into(), tag.into());
        index.manifests.push(descriptor);
        self.write_index(&index).await?;
        Ok(digest)
    }
}

/// Credentials for a registry.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

/// A repository in an OCI distribution registry.
///
/// Supports anonymous access as well as basic and bearer token
/// authentication as negotiated through `WWW-Authenticate` challenges.
pub struct RegistryStore {
    client: Client,
    base: Url,
    repository: String,
    credentials: Option<Credentials>,
    push: bool,
    authorization: Mutex<Option<String>>,
}

impl Debug for RegistryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryStore")
            .field("base", &self.base.as_str())
            .field("repository", &self.repository)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl RegistryStore {
    /// Access the repository of `reference`. `push` requests write access
    /// when authenticating.
    pub fn new(
        reference: &Reference,
        insecure_http: bool,
        credentials: Option<Credentials>,
        push: bool,
    ) -> Result<Self> {
        let scheme = if insecure_http { "http" } else { "https" };
        let base = Url::parse(&format!("{scheme}://{}/", reference.api_host()))
            .map_err(|e| CacheError::bundle(format!("invalid registry URL: {e}")))?;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(backend)?;
        Ok(Self {
            client,
            base,
            repository: reference.repository.clone(),
            credentials,
            push,
            authorization: Mutex::new(None),
        })
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base
            .join(&format!("v2/{}/{path}", self.repository))
            .map_err(|e| CacheError::bundle(format!("invalid registry URL: {e}")))
    }

    fn cached_authorization(&self) -> Option<String> {
        self.authorization
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Send the request built by `build`, authenticating once if challenged.
    async fn send(&self, build: impl Fn() -> RequestBuilder) -> Result<Response> {
        let with_auth = |request: RequestBuilder| match self.cached_authorization() {
            Some(auth) => request.header(header::AUTHORIZATION, auth),
            None => request,
        };

        let response = with_auth(build()).send().await.map_err(backend)?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let authorization = self.authenticate(&challenge).await?;
        *self.authorization.lock().unwrap_or_else(|e| e.into_inner()) = Some(authorization);
        with_auth(build()).send().await.map_err(backend)
    }

    async fn authenticate(&self, challenge: &str) -> Result<String> {
        let (scheme, params) = challenge.split_once(' ').unwrap_or((challenge, ""));
        let params = parse_challenge_params(params);

        if scheme.eq_ignore_ascii_case("basic") {
            let Some(credentials) = &self.credentials else {
                return Err(CacheError::bundle("registry requires credentials"));
            };
            let token =
                STANDARD.encode(format!("{}:{}", credentials.username, credentials.password));
            return Ok(format!("Basic {token}"));
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(CacheError::bundle(format!(
                "unsupported registry authentication challenge `{challenge}`"
            )));
        }

        let realm = params
            .iter()
            .find(|(k, _)| k == "realm")
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| CacheError::bundle("bearer challenge without realm"))?;
        let mut url = Url::parse(realm)
            .map_err(|e| CacheError::bundle(format!("invalid token realm `{realm}`: {e}")))?;
        // The registry chooses the token service, but credentials must not
        // leave over plain HTTP unless plain HTTP was explicitly allowed.
        let plain_http_allowed = url.scheme() == "http" && self.base.scheme() == "http";
        if url.scheme() != "https" && !plain_http_allowed {
            return Err(CacheError::bundle(format!(
                "refusing token realm `{realm}`: not HTTPS"
            )));
        }
        let actions = if self.push { "pull,push" } else { "pull" };
        {
            let mut query = url.query_pairs_mut();
            if let Some((_, service)) = params.iter().find(|(k, _)| k == "service") {
                query.append_pair("service", service);
            }
            query.append_pair(
                "scope",
                &format!("repository:{}:{actions}", self.repository),
            );
        }

        let mut request = self.client.get(url);
        if let Some(credentials) = &self.credentials {
            request = request.basic_auth(&credentials.username, Some(&credentials.password));
        }
        let response = request.send().await.map_err(backend)?;
        if !response.status().is_success() {
            return Err(CacheError::bundle(format!(
                "registry token request failed with {}",
                response.status()
            )));
        }
        let token: TokenResponse = response.json().await.map_err(backend)?;
        let token = token
            .token
            .or(token.access_token)
            .ok_or_else(|| CacheError::bundle("registry token response without token"))?;
        Ok(format!("Bearer {token}"))
    }

    /// Read a response body, aborting as soon as it exceeds `max_bytes`,
    /// whether or not the server declared its length.
    async fn read_body(mut response: Response, max_bytes: usize, what: &str) -> Result<Vec<u8>> {
        let too_large = || CacheError::bundle(format!("{what} exceeds {max_bytes} bytes"));
        if response
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(backend)? {
            if body.len() + chunk.len() > max_bytes {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn has_blob(&self, digest: &Digest) -> Result<bool> {
        let url = self.url(&format!("blobs/{digest}"))?;
        let response = self.send(|| self.client.head(url.clone())).await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl OciStore for RegistryStore {
    async fn manifest(&self, reference: &str) -> Result<Option<(Vec<u8>, Digest)>> {
        check_reference(reference)?;
        let url = self.url(&format!("manifests/{reference}"))?;
        let response = self
            .send(|| {
                self.client.get(url.clone()).header(
                    header::ACCEPT,
                    format!("{IMAGE_MANIFEST_MEDIA_TYPE}, {DOCKER_MANIFEST_MEDIA_TYPE}"),
                )
            })
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND => return Ok(None),
            status if !status.is_success() => {
                return Err(CacheError::bundle(format!(
                    "fetching manifest {reference} failed with {status}"
                )))
            }
            _ => {}
        }
        let content = Self::read_body(response, MAX_MANIFEST_BYTES, "manifest").await?;
        let digest = Digest::of(&content);
        if let Ok(expected) = reference.parse::<Digest>() {
            expected.verify(&content)?;
        }
        debug!(%digest, reference, "fetched manifest");
        Ok(Some((content, digest)))
    }

    async fn blob(&self, digest: &Digest, max_bytes: usize) -> Result<Vec<u8>> {
        let url = self.url(&format!("blobs/{digest}"))?;
        let response = self.send(|| self.client.get(url.clone())).await?;
        if !response.status().is_success() {
            return Err(CacheError::bundle(format!(
                "fetching blob {digest} failed with {}",
                response.status()
            )));
        }
        let content = Self::read_body(response, max_bytes, "blob").await?;
        digest.verify(&content)?;
        Ok(content)
    }
}

#[async_trait]
impl OciStoreWriter for RegistryStore {
    async fn put_blob(&self, content: &[u8]) -> Result<Digest> {
        let digest = Digest::of(content);
        if self.has_blob(&digest).await? {
            return Ok(digest);
        }

        let url = self.url("blobs/uploads/")?;
        let response = self.send(|| self.client.post(url.clone())).await?;
        if response.status() != StatusCode::ACCEPTED {
            return Err(CacheError::bundle(format!(
                "starting blob upload failed with {}",
                response.status()
            )));
        }
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| CacheError::bundle("blob upload response without location"))?;
        let mut upload = url
            .join(location)
            .map_err(|e| CacheError::bundle(format!("invalid upload location: {e}")))?;
        upload
            .query_pairs_mut()
            .append_pair("digest", digest.as_str());

        let request = || {
            self.client
                .request(Method::PUT, upload.clone())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(content.to_vec())
        };
        // Registries may hand uploads to other hosts (e.g. object storage);
        // registry credentials are only sent to the registry itself.
        let response = if upload.origin() == self.base.origin() {
            self.send(request).await?
        } else {
            request().send().await.map_err(backend)?
        };
        if response.status() != StatusCode::CREATED {
            return Err(CacheError::bundle(format!(
                "uploading blob {digest} failed with {}",
                response.status()
            )));
        }
        Ok(digest)
    }

    async fn put_manifest(
        &self,
        content: &[u8],
        media_type: &str,
        tag: Option<&str>,
    ) -> Result<Digest> {
        let digest = Digest::of(content);
        let reference = tag.map_or_else(|| digest.to_string(), str::to_string);
        check_reference(&reference)?;
        let url = self.url(&format!("manifests/{reference}"))?;
        let response = self
            .send(|| {
                self.client
                    .request(Method::PUT, url.clone())
                    .header(header::CONTENT_TYPE, media_type)
                    .body(content.to_vec())
            })
            .await?;
        if !response.status().is_success() {
            return Err(CacheError::bundle(format!(
                "pushing manifest {reference} failed with {}",
                response.status()
            )));
        }
        Ok(digest)
    }
}

/// Parse `key="value", key2=value2` challenge parameters.
fn parse_challenge_params(params: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut rest = params.trim();
    while !rest.is_empty() {
        let Some((key, after)) = rest.split_once('=') else {
            break;
        };
        let key = key.trim().to_ascii_lowercase();
        let (value, after) = match after.strip_prefix('"') {
            Some(quoted) => match quoted.split_once('"') {
                Some((value, after)) => (value, after),
                None => (quoted, ""),
            },
            None => after.split_once(',').unwrap_or((after, "")),
        };
        result.push((key, value.trim().to_string()));
        rest = after.trim_start_matches([',', ' ']);
    }
    result
}

fn backend(e: reqwest::Error) -> CacheError {
    CacheError::Backend {
        source: Box::new(e),
    }
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> CacheError {
    let path = path.to_path_buf();
    move |source| CacheError::PreloadIo { path, source }
}

fn too_large(digest: &Digest, max_bytes: usize) -> CacheError {
    CacheError::bundle(format!("blob {digest} exceeds {max_bytes} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge() {
        let params = parse_challenge_params(
            r#"realm="https://auth.example.com/token",service="registry.example.com",scope="repository:a:pull""#,
        );
        assert_eq!(
            params,
            [
                ("realm".into(), "https://auth.example.com/token".into()),
                ("service".into(), "registry.example.com".into()),
                ("scope".into(), "repository:a:pull".into()),
            ]
        );
    }

    #[tokio::test]
    async fn layout_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();

        let blob = store.put_blob(b"hello").await.unwrap();
        assert_eq!(store.blob(&blob, 16).await.unwrap(), b"hello");
        assert!(store.blob(&blob, 2).await.is_err(), "size limit enforced");

        let manifest = store
            .put_manifest(b"{\"m\":1}", IMAGE_MANIFEST_MEDIA_TYPE, Some("v1"))
            .await
            .unwrap();
        let (content, digest) = store.manifest("v1").await.unwrap().unwrap();
        assert_eq!(
            (content.as_slice(), &digest),
            (&b"{\"m\":1}"[..], &manifest)
        );
        assert!(store.manifest(manifest.as_str()).await.unwrap().is_some());
        assert!(store.manifest("v2").await.unwrap().is_none());

        // Retagging replaces the index entry.
        store
            .put_manifest(b"{\"m\":2}", IMAGE_MANIFEST_MEDIA_TYPE, Some("v1"))
            .await
            .unwrap();
        assert_eq!(store.index().await.unwrap().manifests.len(), 1);
    }

    #[tokio::test]
    async fn layout_detects_tampered_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        let digest = store.put_blob(b"hello").await.unwrap();
        std::fs::write(store.blob_path(&digest), b"HELLO").unwrap();
        assert!(store.blob(&digest, 16).await.is_err());
    }

    #[tokio::test]
    async fn layout_rejects_bad_reference() {
        let dir = tempfile::tempdir().unwrap();
        let store = LayoutStore::init(dir.path()).await.unwrap();
        assert!(store.manifest("../x").await.is_err());
    }
}
