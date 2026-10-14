# strict-lru

A small, bounded, strictly least-recently-used cache.

- No dependencies and no `unsafe`; every operation is O(1) (slab plus an
  index-linked recency list).
- Optional per-entry time-to-live and an optional total weight limit (for
  example bytes), computed by a caller-supplied `Weigher`.
- Deterministic: eviction is always strict LRU, a freshly inserted value is
  always admitted, and exact statistics (hits, misses, evictions, expirations)
  are kept.
- Single-threaded (`&mut self` for lookups); wrap it in a lock to share it.

```rust
use std::num::NonZeroUsize;
use strict_lru::LruCache;

let mut cache = LruCache::new(NonZeroUsize::new(2).unwrap());
cache.insert("a", 1);
cache.insert("b", 2);
cache.get("a");
cache.insert("c", 3); // evicts "b", the least recently used
assert!(cache.get("b").is_none());
```

Unlike TinyLFU-based caches such as `moka`, nothing is rejected on admission
and eviction is never deferred, which keeps behavior predictable at low
concurrency.
