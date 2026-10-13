// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CacheError>;

#[derive(Error, Debug)]
pub enum CacheError {
    #[error("invalid cache configuration: {message}")]
    InvalidConfiguration { message: String },

    #[error("invalid cache key `{key}`: {reason}")]
    InvalidKey { key: String, reason: &'static str },

    #[error("invalid cache namespace `{namespace}`")]
    InvalidNamespace { namespace: String },

    #[error("value for key `{key}` is {size} bytes, exceeding the limit of {limit} bytes")]
    ValueTooLarge {
        key: String,
        size: usize,
        limit: usize,
    },

    #[error("cache backend error: {source}")]
    Backend {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("failed to read preload data from `{path}`: {source}")]
    PreloadIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to load preload bundle: {message}")]
    Bundle { message: String },

    #[error("preload bundle verification failed: {message}")]
    BundleVerification { message: String },
}

#[cfg(feature = "oci")]
impl CacheError {
    pub(crate) fn bundle(message: impl Into<String>) -> Self {
        Self::Bundle {
            message: message.into(),
        }
    }

    pub(crate) fn verification(message: impl Into<String>) -> Self {
        Self::BundleVerification {
            message: message.into(),
        }
    }
}
