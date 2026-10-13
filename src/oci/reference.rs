// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! OCI references and content digests.

use std::{fmt, str::FromStr};

use sha2::{Digest as _, Sha256};

use crate::{CacheError, Result};

const DOCKER_HUB: &str = "docker.io";
const DOCKER_HUB_API: &str = "registry-1.docker.io";

/// A validated `sha256:<hex>` content digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(String);

impl Digest {
    /// The digest of `content`.
    pub fn of(content: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(content))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The hex-encoded hash, without the algorithm prefix.
    pub fn hex(&self) -> &str {
        &self.0["sha256:".len()..]
    }

    /// The tag under which cosign stores the signature of this digest.
    pub fn cosign_signature_tag(&self) -> String {
        format!("sha256-{}.sig", self.hex())
    }

    /// Fail unless `content` hashes to this digest.
    pub fn verify(&self, content: &[u8]) -> Result<()> {
        let actual = Self::of(content);
        if &actual != self {
            return Err(CacheError::bundle(format!(
                "content digest mismatch: expected {self}, got {actual}"
            )));
        }
        Ok(())
    }
}

impl FromStr for Digest {
    type Err = CacheError;

    fn from_str(s: &str) -> Result<Self> {
        let valid = s.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64 && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        });
        if !valid {
            return Err(CacheError::bundle(format!(
                "unsupported or malformed digest `{s}`, expected sha256:<64 hex>"
            )));
        }
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reference to a manifest in a registry:
/// `[registry[:port]/]repository[:tag][@digest]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<Digest>,
}

impl Reference {
    /// The host to send registry API requests to.
    pub fn api_host(&self) -> &str {
        if self.registry == DOCKER_HUB {
            DOCKER_HUB_API
        } else {
            &self.registry
        }
    }

    /// The tag or digest to request the manifest by; the digest wins if both
    /// are given, the tag defaults to `latest`.
    pub fn manifest_reference(&self) -> String {
        match (&self.digest, &self.tag) {
            (Some(digest), _) => digest.to_string(),
            (None, Some(tag)) => tag.clone(),
            (None, None) => "latest".into(),
        }
    }

    /// `registry/repository`, as recorded in cosign signatures.
    pub fn name(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }
}

impl FromStr for Reference {
    type Err = CacheError;

    fn from_str(s: &str) -> Result<Self> {
        let invalid =
            |reason: &str| CacheError::bundle(format!("invalid reference `{s}`: {reason}"));

        let (name, digest) = match s.split_once('@') {
            Some((name, digest)) => (name, Some(digest.parse::<Digest>()?)),
            None => (s, None),
        };

        // A `:` after the last `/` separates the tag; one before it belongs
        // to a registry port.
        let last_slash = name.rfind('/').map_or(0, |i| i + 1);
        let (name, tag) = match name[last_slash..].find(':') {
            Some(i) => (&name[..last_slash + i], Some(&name[last_slash + i + 1..])),
            None => (name, None),
        };
        if let Some(tag) = tag {
            if !is_valid_tag(tag) {
                return Err(invalid("malformed tag"));
            }
        }

        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            _ if !name.contains('/') => (DOCKER_HUB.to_string(), format!("library/{name}")),
            _ => (DOCKER_HUB.to_string(), name.to_string()),
        };
        if !is_valid_repository(&repository) {
            return Err(invalid("malformed repository"));
        }
        if registry.is_empty()
            || !registry
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        {
            return Err(invalid("malformed registry"));
        }

        Ok(Self {
            registry,
            repository,
            tag: tag.map(str::to_string),
            digest,
        })
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// A tag or digest naming a manifest within a repository or image layout.
pub(crate) fn is_valid_manifest_reference(reference: &str) -> bool {
    is_valid_tag(reference) || reference.parse::<Digest>().is_ok()
}

pub(crate) fn is_valid_tag(tag: &str) -> bool {
    let mut chars = tag.chars();
    tag.len() <= 128
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_valid_repository(repository: &str) -> bool {
    !repository.is_empty()
        && repository.split('/').all(|component| {
            !component.is_empty()
                && component.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
                })
                && component.starts_with(|c: char| c.is_ascii_alphanumeric())
                && component.ends_with(|c: char| c.is_ascii_alphanumeric())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const HEX: &str = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

    #[test]
    fn digest_of_content() {
        let digest = Digest::of(b"{}");
        assert_eq!(digest.hex(), HEX);
        assert_eq!(digest.cosign_signature_tag(), format!("sha256-{HEX}.sig"));
        digest.verify(b"{}").unwrap();
        digest.verify(b"[]").unwrap_err();
    }

    #[rstest]
    #[case("sha256:abc")]
    #[case("sha512:00")]
    #[case("sha256:44136FA355B3678A1146AD16F7E8649E94FB4FC21FE77E8310C060F61CAAFF8A")]
    fn rejects_bad_digest(#[case] digest: &str) {
        assert!(digest.parse::<Digest>().is_err());
    }

    #[rstest]
    #[case(
        "registry.example.com/trustee/cache:v1",
        "registry.example.com",
        "trustee/cache",
        Some("v1"),
        false
    )]
    #[case("localhost:5000/cache", "localhost:5000", "cache", None, false)]
    #[case("busybox", "docker.io", "library/busybox", None, false)]
    #[case("org/cache:latest", "docker.io", "org/cache", Some("latest"), false)]
    #[case(
        "reg.io/a/b@sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "reg.io",
        "a/b",
        None,
        true
    )]
    fn parses_references(
        #[case] input: &str,
        #[case] registry: &str,
        #[case] repository: &str,
        #[case] tag: Option<&str>,
        #[case] has_digest: bool,
    ) {
        let reference: Reference = input.parse().unwrap();
        assert_eq!(reference.registry, registry);
        assert_eq!(reference.repository, repository);
        assert_eq!(reference.tag.as_deref(), tag);
        assert_eq!(reference.digest.is_some(), has_digest);
    }

    #[test]
    fn digest_takes_precedence() {
        let reference: Reference = format!("reg.io/a:v1@sha256:{HEX}").parse().unwrap();
        assert_eq!(reference.manifest_reference(), format!("sha256:{HEX}"));
        assert_eq!(reference.to_string(), format!("reg.io/a:v1@sha256:{HEX}"));
    }

    #[rstest]
    #[case("reg.io/UPPER")]
    #[case("reg.io/a:bad tag")]
    #[case("reg.io/a/../b")]
    #[case("reg.io//a")]
    #[case("reg.io/a@sha256:short")]
    fn rejects_bad_references(#[case] input: &str) {
        assert!(input.parse::<Reference>().is_err());
    }

    #[test]
    fn docker_hub_api_host() {
        let reference: Reference = "busybox".parse().unwrap();
        assert_eq!(reference.api_host(), "registry-1.docker.io");
    }
}
