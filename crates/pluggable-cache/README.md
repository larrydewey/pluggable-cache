# pluggable-cache

Namespaced caches of opaque byte values with a pluggable backend, persistent and
tiered storage, and signed OCI preload bundles. Built on the standalone
[`strict-lru`](../strict-lru) crate. Developed for
[Confidential Containers Trustee](https://github.com/confidential-containers/trustee),
but it has no dependency on it.

## Overview

The crate has two layers:

- **`lru::LruCache<K, V>`** (re-exported from `strict-lru`): a generic,
  bounded least-recently-used map with an optional time-to-live and an
  optional weight limit (e.g. bytes). It has no dependencies, uses no
  `unsafe`, and every operation is O(1). It is single-threaded; wrap it in a
  lock to share it.
- **The pluggable layer**: the `Cache` trait, its backends, `CacheProvider`
  and pluggable preload sources. A component asks a provider for a cache in its
  own namespace and stays unaware of the backend the operator configured.
  Durable storage is supplied by the host through the `ByteStore` and
  `ByteStoreProvider` traits.

```rust
let provider = ConfiguredCacheProvider::new(config, Some(byte_store_provider))?;
let cache = provider.get_or_register("snp_vcek").await?;

let key = CacheKey::new("Milan/0a1b2c/bl03_tee00_snp08_ucode115")?;
if let Some(vcek) = cache.get(&key).await? {
    // verify `vcek` exactly as if it had just been fetched
}
```

Every extension point is a trait, so nothing is tied to one vendor or service:

| Extension point  | Trait            | Implementations in this crate                              |
|------------------|------------------|------------------------------------------------------------|
| Cache backend    | `Cache`          | `MemoryCache`, `PersistentCache`, `TieredCache`, `DisabledCache` |
| Durable storage  | `ByteStore`, `ByteStoreProvider` | `MemoryByteStore` (tests); the host adapts its own storage |
| Namespace source | `CacheProvider`  | `ConfiguredCacheProvider`                                  |
| Seeding          | `PreloadSource`  | `DirectorySource`, `OciBundleSource`                       |
| Bundle trust     | `BundleVerifier` | `CosignKeyVerifier`, `Unverified`                          |
| Bundle transport | `OciStore`       | `RegistryStore` (any OCI distribution registry), `LayoutStore` (OCI image layout) |

## Security Considerations

- **Cached values are untrusted.** Consumers verify a cached value the same
  way as a freshly fetched one, and only write values that passed
  verification. A cached value that fails verification is discarded and
  fetched again.
- **Some values are trust anchors.** JWK sets (`kbs_jwks`,
  `nvidia_nras_jwks`) cannot be verified independently. Anyone able to write
  their namespace can substitute keys. Back those namespaces only with storage
  trusted as much as the configuration itself; the in-memory default is. The
  KBS admin API refuses to write them, and the NVIDIA key set is only fetched
  over HTTPS.
- **Untrusted bundles are cheap to reject.** A bundle's signature is checked
  before any entry is downloaded, entry and total sizes (256 MiB) are bounded
  by the manifest and enforced while streaming, and registry credentials are
  only sent over HTTPS (unless `insecure_http`) and never to upload hosts
  other than the registry.
- **Setup failures degrade, they don't fail.** If a backend cannot be built
  (e.g. its storage is down), the namespace runs without a cache and setup is
  retried on next use.
- **A cache failure never fails an operation.** Consumers treat cache errors
  as misses, and a failed preload is logged, not fatal.
- **Namespaces isolate use cases.** Every namespace is a separate instance,
  so keys cannot collide and one use case cannot evict another's entries.
  Namespaces are lowercase ASCII alphanumerics and `_`.
- **Keys are validated.** `CacheKey` only admits `/`-separated segments of
  ASCII alphanumerics, `-`, `_` and `.`, without empty, `.` or `..` segments,
  and at most 512 bytes, so keys map safely onto file paths and storage keys.
- **Memory is bounded.** The memory backend holds at most `max_entries`
  values of at most `max_value_bytes` each, and optionally at most
  `max_bytes` in total, per namespace.
- **Bundles are authenticated.** OCI preload sources require an explicit
  `verification` setting. Every blob is checked against its digest, the
  bundle manifest against a cosign signature by a configured key, and sizes
  against limits before data is accepted.

## Backends

| `cache_type` | Description |
|--------------|-------------|
| `Memory`     | Bounded in-process LRU cache with time-to-live. Default. |
| `Persistent` | Entries in a `ByteStore` supplied by the host, in the storage namespace `cache_<namespace>`. Survives restarts; with a shared store, entries are shared between replicas. Bounded by time-to-live only. |
| `Tiered`     | `Memory` in front of `Persistent`: reads are served from memory when possible, writes go to both. An entry promoted from the persistent tier never outlives its expiry there. |
| `Disabled`   | Stores nothing; every lookup misses. Switches caching off. |

New backends implement `Cache` and get a `CacheType` variant. Values are
opaque bytes so that out-of-process backends work without changing
consumers.

> [!Note]
> Stores backed by a database may need a table or collection per
> namespace, named `cache_<namespace>`, created ahead of time.

## Configuration

All fields are optional. The top level selects the default backend; entries
under `namespaces` replace it for individual namespaces.

```json
{
    "cache_type": "Tiered",
    "memory": {
        "max_entries": 1024,
        "max_bytes": 67108864,
        "ttl_secs": 3600,
        "max_value_bytes": 1048576
    },
    "persistent": {
        "storage_type": "Redis",
        "ttl_secs": 604800
    },
    "namespaces": {
        "kbs_jwks": { "cache_type": "Memory" }
    },
    "preload": [
        { "type": "Directory", "path": "/opt/confidential-containers/cache" }
    ],
    "purge_interval_secs": 3600
}
```

| Property              | Description | Default |
|-----------------------|-------------|---------|
| `cache_type`          | Default backend | `Memory` |
| `memory.max_entries`  | Entries per namespace before LRU eviction | `1024` |
| `memory.max_bytes`    | Total key and value bytes per namespace before LRU eviction | unbounded |
| `memory.ttl_secs`     | Expire entries this long after writing; `null` disables expiry | `604800` (7 days) |
| `memory.max_value_bytes` | Reject larger values | `1048576` |
| `persistent.storage_type` | Name of the storage backend, checked by `ByteStoreProvider::validate_backend` at construction | the provider's default |
| `persistent.ttl_secs` | As `memory.ttl_secs` | `604800` |
| `persistent.max_value_bytes` | As `memory.max_value_bytes` | `1048576` |
| `namespaces`          | Map of namespace to a backend configuration replacing the default | `{}` |
| `preload`             | Sources to seed namespaces from, applied in order when a namespace is first registered | `[]` |
| `purge_interval_secs` | Interval of the background task dropping expired entries; `null` only drops them lazily | `3600` |

## Preloading

Preloaded entries are ordinary entries: they are subject to eviction and
expiry. For guaranteed availability, size the cache so that preloaded entries
fit, or use a consumer's own offline mechanism (e.g. the SNP verifier's
[offline store](../../attestation-service/docs/amd-offline-certificate-cache.md)).

### `Directory`

```json
{ "type": "Directory", "path": "/opt/confidential-containers/cache" }
```

Every regular file under `<path>/<namespace>/` becomes one entry, keyed by its
path relative to the namespace directory. Symbolic links and other non-regular
files are skipped. A file whose path is not a valid key is an error. So is a
file larger than `max_value_bytes` (default `1048576`), checked before it is
read.

### `OciRegistry` and `OciLayout`

A cache bundle is an OCI artifact, so it can be stored in any OCI distribution
registry and handled by any OCI tooling (`oras`, `skopeo`, `crane`,
`cosign`, ...). It is signed in the cosign signature format.

```json
{
    "type": "OciRegistry",
    "reference": "registry.example.com/trustee/cache:v1",
    "verification": {
        "type": "CosignPublicKey",
        "public_keys": ["/etc/trustee/cache-bundle.pub"]
    },
    "username": "robot",
    "password_file": "/etc/trustee/registry-password"
}
```

```json
{
    "type": "OciLayout",
    "path": "/opt/confidential-containers/cache-bundle",
    "reference": "v1",
    "verification": {
        "type": "CosignPublicKey",
        "public_keys": ["/etc/trustee/cache-bundle.pub"]
    }
}
```

| Property | Description |
|----------|-------------|
| `reference` | Registry reference (`registry/repository:tag` or `@sha256:...`), or tag or digest within the layout. Pin a digest to make the source immutable. |
| `path` | (`OciLayout`) Root of the OCI image layout |
| `verification` | Required. `{"type": "CosignPublicKey", "public_keys": [...]}` accepts a signature by any of the PEM public keys (ECDSA P-256/P-384/P-521, RSA, Ed25519). `{"type": "Unverified"}` skips verification and is only meant for testing. |
| `username`, `password_file` | (`OciRegistry`) Registry credentials, for basic or bearer token authentication |
| `insecure_http` | (`OciRegistry`) Use plain HTTP |
| `max_value_bytes` | Reject larger entries; default `1048576` |

Signatures are verified locally against the configured keys; no transparency
log or certificate authority is contacted, so verification works air-gapped.

#### Bundle format

An OCI image manifest with artifact type
`application/vnd.confidential-containers.trustee.cache-bundle.v1`, the empty
config, and one layer per entry with media type
`application/vnd.confidential-containers.trustee.cache-entry.v1` and the
annotations `io.confidential-containers.trustee.cache.namespace` and
`io.confidential-containers.trustee.cache.key`.

## Bundle compatibility

The OCI media types and annotations still carry the `trustee` prefix
(`application/vnd.confidential-containers.trustee.cache-bundle.v1`, ...) so
that bundles created by earlier Trustee tooling keep working.
