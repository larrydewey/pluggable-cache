// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test of bundle push, pull and verification against a minimal
//! in-process OCI distribution registry with bearer token authentication.

#![cfg(feature = "oci")]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use pluggable_cache::{
    oci::{
        bundle::{self, BundleEntries},
        store::OciStore,
        verify::{BundleVerifier, CosignKeyVerifier},
        Credentials, LayoutStore, Reference, RegistryStore,
    },
    preload::PreloadSource,
    CacheKey,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

const TOKEN: &str = "t0k3n";
const USER: &str = "user";
const PASSWORD: &str = "secret";

#[derive(Default)]
struct Registry {
    blobs: HashMap<String, Vec<u8>>,
    manifests: HashMap<String, (Vec<u8>, String)>,
    uploads: usize,
}

struct Request {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }

    fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

fn sha256(content: &[u8]) -> String {
    pluggable_cache::oci::Digest::of(content).to_string()
}

fn handle(state: &Mutex<Registry>, addr: SocketAddr, request: Request) -> Reply {
    let (path, query) = request
        .target
        .split_once('?')
        .unwrap_or((request.target.as_str(), ""));

    if path == "/token" {
        let expected = format!(
            "Basic {}",
            base64_encode(format!("{USER}:{PASSWORD}").as_bytes())
        );
        if request.headers.get("authorization") != Some(&expected) {
            return Reply::status(401);
        }
        return Reply::status(200).body(format!(r#"{{"token":"{TOKEN}"}}"#).into_bytes());
    }

    if request.headers.get("authorization").map(String::as_str) != Some(&format!("Bearer {TOKEN}"))
    {
        return Reply::status(401).header(
            "WWW-Authenticate",
            format!(r#"Bearer realm="http://{addr}/token",service="test""#),
        );
    }

    let Some(rest) = path.strip_prefix("/v2/test/cache/") else {
        return Reply::status(404);
    };
    let mut state = state.lock().unwrap();
    match (request.method.as_str(), rest) {
        ("HEAD", blob) if blob.starts_with("blobs/sha256:") => {
            let digest = &blob["blobs/".len()..];
            Reply::status(if state.blobs.contains_key(digest) {
                200
            } else {
                404
            })
        }
        ("GET", blob) if blob.starts_with("blobs/sha256:") => {
            match state.blobs.get(&blob["blobs/".len()..]) {
                Some(content) => Reply::status(200).body(content.clone()),
                None => Reply::status(404),
            }
        }
        ("POST", "blobs/uploads/") => {
            state.uploads += 1;
            Reply::status(202).header(
                "Location",
                format!("/v2/test/cache/blobs/uploads/{}", state.uploads),
            )
        }
        ("PUT", upload) if upload.starts_with("blobs/uploads/") => {
            let digest = query
                .split('&')
                .find_map(|p| p.strip_prefix("digest="))
                .unwrap()
                .replace("%3A", ":");
            assert_eq!(sha256(&request.body), digest);
            state.blobs.insert(digest, request.body);
            Reply::status(201)
        }
        ("PUT", manifest) if manifest.starts_with("manifests/") => {
            let reference = &manifest["manifests/".len()..];
            let media_type = request.headers["content-type"].clone();
            let digest = sha256(&request.body);
            state
                .manifests
                .insert(digest.clone(), (request.body.clone(), media_type.clone()));
            state
                .manifests
                .insert(reference.to_string(), (request.body, media_type));
            Reply::status(201).header("Docker-Content-Digest", digest)
        }
        ("GET", manifest) if manifest.starts_with("manifests/") => {
            match state.manifests.get(&manifest["manifests/".len()..]) {
                Some((content, media_type)) => Reply::status(200)
                    .header("Content-Type", media_type.clone())
                    .body(content.clone()),
                None => Reply::status(404),
            }
        }
        _ => Reply::status(405),
    }
}

fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

async fn serve() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(Registry::default()));
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();

                let mut headers = HashMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).await.unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                }
                let length: usize = headers
                    .get("content-length")
                    .map_or(0, |v| v.parse().unwrap());
                let mut body = vec![0; length];
                reader.read_exact(&mut body).await.unwrap();

                let reply = handle(
                    &state,
                    addr,
                    Request {
                        method,
                        target,
                        headers,
                        body,
                    },
                );
                let mut response = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in reply.headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str("\r\n");
                let mut stream = reader.into_inner();
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&reply.body).await.unwrap();
            });
        }
    });
    addr
}

#[tokio::test]
async fn push_pull_and_verify_through_registry() {
    let addr = serve().await;
    let reference: Reference = format!("{addr}/test/cache:v1").parse().unwrap();
    let credentials = Credentials {
        username: USER.into(),
        password: PASSWORD.into(),
    };

    // Build and sign a bundle locally, as an operator would.
    let layout_dir = tempfile::tempdir().unwrap();
    let layout = LayoutStore::init(layout_dir.path()).await.unwrap();
    let entries = BundleEntries::from([(
        "snp_vcek".to_string(),
        vec![(CacheKey::new("Milan/abcd/tcb").unwrap(), b"vcek".to_vec())],
    )]);
    let digest = bundle::write(&layout, &entries, "v1").await.unwrap();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    bundle::sign(&layout, &digest, &reference.name(), &key)
        .await
        .unwrap();

    // Push it to the registry.
    let push = RegistryStore::new(&reference, true, Some(credentials.clone()), true).unwrap();
    bundle::copy(&layout, &push, "v1", "v1", 1024)
        .await
        .unwrap();

    // Pull and verify it as Trustee would.
    let pull = RegistryStore::new(&reference, true, Some(credentials), false).unwrap();
    let (pulled, read) = bundle::read(&pull, "v1", 1024).await.unwrap();
    assert_eq!(pulled, digest);
    assert_eq!(read, entries);
    let public = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();
    CosignKeyVerifier::new(vec![public.clone()])
        .unwrap()
        .verify(&pull, &digest)
        .await
        .unwrap();

    // Pinning by digest works too, through the preload source.
    let source = pluggable_cache::oci::OciBundleSource::new(
        "test".into(),
        Arc::new(pull),
        digest.to_string(),
        Arc::new(CosignKeyVerifier::new(vec![public]).unwrap()),
        1024,
    );
    assert_eq!(source.entries("snp_vcek").await.unwrap().len(), 1);
}

#[tokio::test]
async fn registry_without_credentials_is_refused() {
    let addr = serve().await;
    let reference: Reference = format!("{addr}/test/cache:v1").parse().unwrap();
    let store = RegistryStore::new(&reference, true, None, false).unwrap();
    assert!(store.manifest("v1").await.is_err());
}
