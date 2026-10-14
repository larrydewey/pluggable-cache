// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::{CacheError, Result};

/// Upper bound on the length of a [`CacheKey`] in bytes.
pub const MAX_KEY_LEN: usize = 512;

/// A validated cache key.
///
/// Keys are `/`-separated segments of ASCII alphanumerics, `-`, `_` and `.`.
/// Empty segments, `.` and `..` are rejected, so a key can be mapped onto a
/// relative file path (e.g. for preloading or a future on-disk backend)
/// without escaping its namespace. Backends may rely on keys having been
/// validated and need not re-check them.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey(String);

impl CacheKey {
    pub fn new(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        if let Err(reason) = validate(&key) {
            return Err(CacheError::InvalidKey { key, reason });
        }
        Ok(Self(key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

fn validate(key: &str) -> std::result::Result<(), &'static str> {
    if key.is_empty() {
        return Err("key is empty");
    }
    if key.len() > MAX_KEY_LEN {
        return Err("key is too long");
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        return Err("only ASCII alphanumerics, `-`, `_`, `.` and `/` are allowed");
    }
    if key
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("segments must not be empty, `.` or `..`");
    }
    Ok(())
}

impl TryFrom<String> for CacheKey {
    type Error = CacheError;

    fn try_from(key: String) -> Result<Self> {
        Self::new(key)
    }
}

impl TryFrom<&str> for CacheKey {
    type Error = CacheError;

    fn try_from(key: &str) -> Result<Self> {
        Self::new(key)
    }
}

impl AsRef<str> for CacheKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("vcek")]
    #[case("Milan/0a1b/bl03_tee00_snp08_ucode115")]
    #[case("a.b-c_d")]
    #[case("..a/b..")]
    fn accepts_valid_keys(#[case] key: &str) {
        assert_eq!(CacheKey::new(key).unwrap().as_str(), key);
    }

    #[rstest]
    #[case("")]
    #[case("/abs")]
    #[case("trailing/")]
    #[case("a//b")]
    #[case("../escape")]
    #[case("a/./b")]
    #[case("a/..")]
    #[case("space here")]
    #[case("semi;colon")]
    #[case("back\\slash")]
    #[case("nul\0")]
    #[case("ünïcode")]
    fn rejects_invalid_keys(#[case] key: &str) {
        assert!(matches!(
            CacheKey::new(key),
            Err(CacheError::InvalidKey { .. })
        ));
    }

    #[test]
    fn rejects_overlong_key() {
        assert!(CacheKey::new("a".repeat(MAX_KEY_LEN)).is_ok());
        assert!(CacheKey::new("a".repeat(MAX_KEY_LEN + 1)).is_err());
    }
}
