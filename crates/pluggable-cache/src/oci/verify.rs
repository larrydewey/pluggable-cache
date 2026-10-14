// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable verification of preload bundles.
//!
//! [`CosignKeyVerifier`] accepts bundles signed with `cosign sign --key` (or
//! [`super::bundle::sign`]) using the classic cosign signature format: a
//! "simple signing" payload naming the bundle's manifest digest, stored in a
//! manifest tagged `sha256-<hex>.sig` next to the bundle. Verification is
//! done locally against configured public keys; no transparency log or
//! certificate authority is contacted, so it works air-gapped.

use std::{fmt::Debug, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public},
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{manifest::ImageManifest, store::OciStore, store::MAX_MANIFEST_BYTES, Digest};
use crate::{CacheError, Result};

pub const SIMPLE_SIGNING_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
pub const SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
const SIGNATURE_TYPE: &str = "cosign container image signature";

/// Decides whether a bundle may be loaded.
#[async_trait]
pub trait BundleVerifier: Debug + Send + Sync {
    /// Fail unless the manifest `digest` in `store` is trusted.
    async fn verify(&self, store: &dyn OciStore, digest: &Digest) -> Result<()>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum VerificationConfig {
    /// Require a cosign signature by one of these PEM public keys (ECDSA
    /// P-256/P-384/P-521, RSA or Ed25519).
    CosignPublicKey { public_keys: Vec<PathBuf> },

    /// Load the bundle without checking any signature. Only for testing:
    /// anyone able to tamper with the bundle controls the cache contents.
    Unverified {},
}

impl VerificationConfig {
    pub fn build(&self) -> Result<Arc<dyn BundleVerifier>> {
        Ok(match self {
            Self::CosignPublicKey { public_keys } => {
                Arc::new(CosignKeyVerifier::from_pem_files(public_keys)?)
            }
            Self::Unverified {} => {
                warn!("cache preload bundle signatures are NOT verified");
                Arc::new(Unverified)
            }
        })
    }
}

/// Trusts every bundle.
#[derive(Debug)]
pub struct Unverified;

#[async_trait]
impl BundleVerifier for Unverified {
    async fn verify(&self, _store: &dyn OciStore, _digest: &Digest) -> Result<()> {
        Ok(())
    }
}

/// Trusts bundles carrying a cosign signature by any of its keys.
pub struct CosignKeyVerifier {
    keys: Vec<PKey<Public>>,
}

impl Debug for CosignKeyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CosignKeyVerifier")
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl CosignKeyVerifier {
    pub fn new(keys: Vec<PKey<Public>>) -> Result<Self> {
        if keys.is_empty() {
            return Err(CacheError::InvalidConfiguration {
                message: "at least one cosign public key is required".into(),
            });
        }
        for key in &keys {
            signing_digest(key)?;
        }
        Ok(Self { keys })
    }

    pub fn from_pem_files(paths: &[PathBuf]) -> Result<Self> {
        let keys = paths
            .iter()
            .map(|path| {
                let pem = std::fs::read(path).map_err(|source| CacheError::PreloadIo {
                    path: path.clone(),
                    source,
                })?;
                PKey::public_key_from_pem(&pem).map_err(|e| CacheError::InvalidConfiguration {
                    message: format!("invalid public key {}: {e}", path.display()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Self::new(keys)
    }

    fn verifies(&self, payload: &[u8], signature: &[u8]) -> bool {
        self.keys.iter().any(|key| {
            verify_signature(key, payload, signature).unwrap_or_else(|e| {
                debug!("signature check failed: {e}");
                false
            })
        })
    }
}

#[async_trait]
impl BundleVerifier for CosignKeyVerifier {
    async fn verify(&self, store: &dyn OciStore, digest: &Digest) -> Result<()> {
        let tag = digest.cosign_signature_tag();
        let (content, _) = store
            .manifest(&tag)
            .await?
            .ok_or_else(|| CacheError::verification(format!("no signature found for {digest}")))?;
        let manifest: ImageManifest = serde_json::from_slice(&content)
            .map_err(|e| CacheError::verification(format!("malformed signature manifest: {e}")))?;

        for layer in &manifest.layers {
            if layer.media_type != SIMPLE_SIGNING_MEDIA_TYPE {
                continue;
            }
            let Some(signature) = layer.annotations.get(SIGNATURE_ANNOTATION) else {
                continue;
            };
            let Ok(signature) = STANDARD.decode(signature) else {
                debug!("skipping signature that is not valid base64");
                continue;
            };
            let payload = store
                .blob(&layer.digest.parse()?, MAX_MANIFEST_BYTES)
                .await?;
            if !self.verifies(&payload, &signature) {
                continue;
            }
            // The signature is genuine; it must also be about this bundle.
            match serde_json::from_slice::<SimpleSigning>(&payload) {
                Ok(claim)
                    if claim.critical.kind == SIGNATURE_TYPE
                        && claim.critical.image.docker_manifest_digest == digest.as_str() =>
                {
                    return Ok(());
                }
                Ok(_) => debug!("signature is for a different image"),
                Err(e) => debug!("malformed signature payload: {e}"),
            }
        }

        Err(CacheError::verification(format!(
            "no valid signature by a trusted key for {digest}"
        )))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SimpleSigning {
    critical: Critical,
    #[serde(default)]
    optional: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Critical {
    identity: Identity,
    image: Image,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Identity {
    #[serde(rename = "docker-reference")]
    docker_reference: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Image {
    #[serde(rename = "docker-manifest-digest")]
    docker_manifest_digest: String,
}

/// The payload cosign signs for an image: `docker_reference` names the
/// repository, `digest` the manifest.
pub fn simple_signing_payload(docker_reference: &str, digest: &Digest) -> Vec<u8> {
    let payload = SimpleSigning {
        critical: Critical {
            identity: Identity {
                docker_reference: docker_reference.into(),
            },
            image: Image {
                docker_manifest_digest: digest.to_string(),
            },
            kind: SIGNATURE_TYPE.into(),
        },
        optional: None,
    };
    serde_json::to_vec(&payload).expect("serializing a fixed structure cannot fail")
}

/// The hash cosign uses with `key`, `None` for schemes that hash internally.
fn signing_digest<T: HasPublic>(key: &PKeyRef<T>) -> Result<Option<MessageDigest>> {
    let unsupported = || CacheError::InvalidConfiguration {
        message: format!("unsupported cosign key type {:?}", key.id()),
    };
    match key.id() {
        Id::EC => {
            let ec = key.ec_key().map_err(|_| unsupported())?;
            match ec.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => Ok(Some(MessageDigest::sha256())),
                Some(Nid::SECP384R1) => Ok(Some(MessageDigest::sha384())),
                Some(Nid::SECP521R1) => Ok(Some(MessageDigest::sha512())),
                _ => Err(unsupported()),
            }
        }
        Id::RSA => Ok(Some(MessageDigest::sha256())),
        Id::ED25519 => Ok(None),
        _ => Err(unsupported()),
    }
}

fn verify_signature(key: &PKey<Public>, payload: &[u8], signature: &[u8]) -> Result<bool> {
    let crypto = |e: openssl::error::ErrorStack| CacheError::verification(e.to_string());
    let mut verifier = match signing_digest(key)? {
        Some(digest) => Verifier::new(digest, key),
        None => Verifier::new_without_digest(key),
    }
    .map_err(crypto)?;
    verifier.verify_oneshot(signature, payload).map_err(crypto)
}

/// Sign `payload` the way cosign does with `key`.
pub fn sign_payload(key: &PKey<Private>, payload: &[u8]) -> Result<Vec<u8>> {
    let crypto = |e: openssl::error::ErrorStack| CacheError::bundle(format!("signing failed: {e}"));
    let mut signer = match signing_digest(key)? {
        Some(digest) => Signer::new(digest, key),
        None => Signer::new_without_digest(key),
    }
    .map_err(crypto)?;
    signer.sign_oneshot_to_vec(payload).map_err(crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        rsa::Rsa,
    };

    fn public(key: &PKey<Private>) -> PKey<Public> {
        PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap()
    }

    fn keys() -> Vec<PKey<Private>> {
        let ec = |nid| {
            PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(nid).unwrap()).unwrap())
                .unwrap()
        };
        vec![
            ec(Nid::X9_62_PRIME256V1),
            ec(Nid::SECP384R1),
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            PKey::generate_ed25519().unwrap(),
        ]
    }

    #[test]
    fn sign_and_verify_all_key_types() {
        let digest = Digest::of(b"bundle");
        let payload = simple_signing_payload("reg.io/a", &digest);
        for key in keys() {
            let signature = sign_payload(&key, &payload).unwrap();
            assert!(verify_signature(&public(&key), &payload, &signature).unwrap());
            assert!(!verify_signature(&public(&key), b"other", &signature).unwrap_or(false));
        }
    }

    #[test]
    fn payload_matches_cosign_format() {
        let digest = Digest::of(b"bundle");
        let payload: serde_json::Value =
            serde_json::from_slice(&simple_signing_payload("reg.io/a", &digest)).unwrap();
        assert_eq!(
            payload["critical"]["image"]["docker-manifest-digest"],
            digest.as_str()
        );
        assert_eq!(
            payload["critical"]["identity"]["docker-reference"],
            "reg.io/a"
        );
        assert_eq!(payload["critical"]["type"], SIGNATURE_TYPE);
    }

    #[test]
    fn rejects_empty_key_list() {
        assert!(CosignKeyVerifier::new(vec![]).is_err());
    }
}
