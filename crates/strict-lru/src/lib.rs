// Copyright (c) 2026 Larry Dewey.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A generic, bounded least-recently-used (LRU) cache.
//!
//! [`LruCache`] has no dependencies and can hold any `K`/`V`. It is
//! deliberately single-threaded (`&mut self` for mutating lookups); wrap it in
//! a lock to share it between threads.
//!
//! Entries live in a slab (`Vec<Option<Node>>`) and are threaded onto a doubly
//! linked recency list by index, so every operation is O(1) and the
//! implementation needs no `unsafe`. Freed slots are recycled through a free
//! list, which keeps the slab at most `capacity` long.
//!
//! Optionally, every entry carries a time-to-live. Expired entries are dropped
//! lazily when touched, when they reach the tail of the recency list, or
//! eagerly via [`LruCache::purge_expired`].
//!
//! Besides the entry count, the cache can be bounded by a total weight, e.g.
//! the number of bytes held, computed per entry by a caller-supplied
//! [`Weigher`].

use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt,
    hash::Hash,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

/// Counters describing how a cache has been used since it was created.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Lookups that found a live entry.
    pub hits: u64,
    /// Lookups that found no entry, or only an expired one.
    pub misses: u64,
    /// Values written, including overwrites of an existing key.
    pub insertions: u64,
    /// Live entries dropped to make room for a new one.
    pub evictions: u64,
    /// Entries dropped because their time-to-live elapsed.
    pub expirations: u64,
    /// Insertions refused because the entry alone exceeds the weight limit.
    pub rejections: u64,
}

/// Computes the weight of an entry for [`LruCache::with_max_weight`].
pub type Weigher<K, V> = fn(&K, &V) -> usize;

struct Node<K, V> {
    key: K,
    value: V,
    weight: usize,
    expires_at: Option<Instant>,
    /// Towards the most recently used end.
    prev: Option<usize>,
    /// Towards the least recently used end.
    next: Option<usize>,
}

impl<K, V> Node<K, V> {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|deadline| deadline <= now)
    }
}

/// A bounded map that evicts the least recently used entry when full.
pub struct LruCache<K, V> {
    index: HashMap<K, usize>,
    slots: Vec<Option<Node<K, V>>>,
    free: Vec<usize>,
    /// Most recently used entry.
    head: Option<usize>,
    /// Least recently used entry, the next eviction candidate.
    tail: Option<usize>,
    capacity: NonZeroUsize,
    ttl: Option<Duration>,
    weight_limit: Option<(usize, Weigher<K, V>)>,
    weight: usize,
    stats: Stats,
}

impl<K, V> fmt::Debug for LruCache<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LruCache")
            .field("len", &self.index.len())
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .field("weight", &self.weight)
            .field("max_weight", &self.weight_limit.map(|(max, _)| max))
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<K: Hash + Eq + Clone, V> LruCache<K, V> {
    /// Create a cache holding at most `capacity` entries that never expire.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            index: HashMap::with_capacity(capacity.get()),
            slots: Vec::new(),
            free: Vec::new(),
            head: None,
            tail: None,
            capacity,
            ttl: None,
            weight_limit: None,
            weight: 0,
            stats: Stats::default(),
        }
    }

    /// Additionally bound the sum of all entry weights by `max_weight`,
    /// evicting least recently used entries to stay within it. An entry that
    /// alone weighs more than `max_weight` is not stored.
    pub fn with_max_weight(mut self, max_weight: usize, weigher: Weigher<K, V>) -> Self {
        self.weight_limit = Some((max_weight, weigher));
        self
    }

    /// Expire every entry `ttl` after it was last written.
    ///
    /// A zero `ttl` makes every entry expire immediately.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    /// Sum of the weights of all stored entries, `0` without a weight limit.
    pub fn weight(&self) -> usize {
        self.weight
    }

    pub fn max_weight(&self) -> Option<usize> {
        self.weight_limit.map(|(max, _)| max)
    }

    /// Number of stored entries, including expired ones not yet purged.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Look up `key` and mark it as most recently used.
    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.get_at(key, Instant::now())
    }

    /// Look up `key` without touching recency order or statistics.
    pub fn peek<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now = Instant::now();
        let node = self.node(*self.index.get(key)?);
        (!node.is_expired(now)).then_some(&node.value)
    }

    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.peek(key).is_some()
    }

    /// Insert `value` under `key` as the most recently used entry, evicting
    /// least recently used entries if the cache is full.
    ///
    /// Returns the previous value for `key`, if it was still live.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let now = Instant::now();
        let expires_at = self.ttl.map(|ttl| now + ttl);
        self.insert_at(key, value, expires_at, now)
    }

    /// Like [`LruCache::insert`], but expire the entry after `ttl`, capped by
    /// the cache-wide time-to-live. Useful when the value is copied from a
    /// source that will itself expire it earlier.
    pub fn insert_with_ttl(&mut self, key: K, value: V, ttl: Duration) -> Option<V> {
        let now = Instant::now();
        let ttl = self.ttl.map_or(ttl, |default| default.min(ttl));
        self.insert_at(key, value, Some(now + ttl), now)
    }

    /// Keys from most to least recently used, including expired entries not
    /// yet purged.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        let mut cursor = self.head;
        std::iter::from_fn(move || {
            let node = self.node(cursor?);
            cursor = node.next;
            Some(&node.key)
        })
    }

    /// Remove `key`, returning its value if it was still live.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now = Instant::now();
        let idx = self.index.remove(key)?;
        let node = self.release(idx);
        (!node.is_expired(now)).then_some(node.value)
    }

    /// Drop all entries. Statistics are kept.
    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.free.clear();
        self.head = None;
        self.tail = None;
        self.weight = 0;
    }

    /// Count an insertion that a wrapper refused before reaching the cache,
    /// so that statistics stay in one place.
    pub fn note_rejection(&mut self) {
        self.stats.rejections += 1;
    }

    /// Drop every expired entry, returning how many were removed.
    pub fn purge_expired(&mut self) -> usize {
        self.purge_expired_at(Instant::now())
    }

    pub(crate) fn get_at<Q>(&mut self, key: &Q, now: Instant) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(&idx) = self.index.get(key) else {
            self.stats.misses += 1;
            return None;
        };

        if self.node(idx).is_expired(now) {
            self.index.remove(key);
            self.release(idx);
            self.stats.expirations += 1;
            self.stats.misses += 1;
            return None;
        }

        self.stats.hits += 1;
        self.detach(idx);
        self.attach_front(idx);
        Some(&self.node(idx).value)
    }

    pub(crate) fn insert_at(
        &mut self,
        key: K,
        value: V,
        expires_at: Option<Instant>,
        now: Instant,
    ) -> Option<V> {
        let weight = match self.weight_limit {
            Some((max, weigher)) => {
                let weight = weigher(&key, &value);
                if weight > max {
                    // Dropping any stale value keeps readers from seeing data
                    // the caller meant to replace.
                    self.stats.rejections += 1;
                    if let Some(idx) = self.index.remove(&key) {
                        self.release(idx);
                    }
                    return None;
                }
                weight
            }
            None => 0,
        };
        self.stats.insertions += 1;

        let previous = match self.index.get(&key) {
            Some(&idx) => {
                let node = self.node_mut(idx);
                let was_live = !node.is_expired(now);
                let previous = std::mem::replace(&mut node.value, value);
                let old_weight = std::mem::replace(&mut node.weight, weight);
                node.expires_at = expires_at;
                self.weight = self.weight - old_weight + weight;
                self.detach(idx);
                self.attach_front(idx);
                was_live.then_some(previous)
            }
            None => {
                if self.len() == self.capacity.get() {
                    self.evict_tail(now);
                }
                let idx = self.allocate(Node {
                    key: key.clone(),
                    value,
                    weight,
                    expires_at,
                    prev: None,
                    next: None,
                });
                self.weight += weight;
                self.attach_front(idx);
                self.index.insert(key, idx);
                None
            }
        };

        // The new entry is at the head and fits on its own, so this never
        // evicts it.
        while self.weight_limit.is_some_and(|(max, _)| self.weight > max) {
            self.evict_tail(now);
        }
        previous
    }

    pub(crate) fn purge_expired_at(&mut self, now: Instant) -> usize {
        let mut purged = 0;
        let mut cursor = self.tail;
        while let Some(idx) = cursor {
            let node = self.node(idx);
            cursor = node.prev;
            if node.is_expired(now) {
                let key = node.key.clone();
                self.index.remove(&key);
                self.release(idx);
                purged += 1;
            }
        }
        self.stats.expirations += purged as u64;
        purged
    }

    fn evict_tail(&mut self, now: Instant) {
        let Some(idx) = self.tail else {
            return;
        };
        let node = self.release(idx);
        self.index.remove(&node.key);
        if node.is_expired(now) {
            self.stats.expirations += 1;
        } else {
            self.stats.evictions += 1;
        }
    }

    fn allocate(&mut self, node: Node<K, V>) -> usize {
        match self.free.pop() {
            Some(idx) => {
                self.slots[idx] = Some(node);
                idx
            }
            None => {
                self.slots.push(Some(node));
                self.slots.len() - 1
            }
        }
    }

    /// Unlink `idx` from the recency list and return its slot to the free
    /// list. The caller is responsible for the `index` entry.
    fn release(&mut self, idx: usize) -> Node<K, V> {
        self.detach(idx);
        self.free.push(idx);
        let node = self.slots[idx]
            .take()
            .expect("LruCache invariant: released slot must be occupied");
        self.weight -= node.weight;
        node
    }

    fn detach(&mut self, idx: usize) {
        let (prev, next) = {
            let node = self.node_mut(idx);
            (node.prev.take(), node.next.take())
        };
        match prev {
            Some(p) => self.node_mut(p).next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.node_mut(n).prev = prev,
            None => self.tail = prev,
        }
    }

    fn attach_front(&mut self, idx: usize) {
        let old_head = self.head.replace(idx);
        self.node_mut(idx).next = old_head;
        match old_head {
            Some(h) => self.node_mut(h).prev = Some(idx),
            None => self.tail = Some(idx),
        }
    }

    fn node(&self, idx: usize) -> &Node<K, V> {
        self.slots[idx]
            .as_ref()
            .expect("LruCache invariant: indexed slot must be occupied")
    }

    fn node_mut(&mut self, idx: usize) -> &mut Node<K, V> {
        self.slots[idx]
            .as_mut()
            .expect("LruCache invariant: indexed slot must be occupied")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(capacity: usize) -> LruCache<String, u32> {
        LruCache::new(NonZeroUsize::new(capacity).unwrap())
    }

    /// Walk the recency list both ways and check it agrees with the index.
    fn assert_consistent<K: Hash + Eq + Clone + fmt::Debug, V>(cache: &LruCache<K, V>) {
        let mut forward = Vec::new();
        let mut cursor = cache.head;
        let mut prev = None;
        while let Some(idx) = cursor {
            let node = cache.node(idx);
            assert_eq!(node.prev, prev, "broken back link at {idx}");
            assert_eq!(cache.index.get(&node.key), Some(&idx));
            forward.push(idx);
            prev = Some(idx);
            cursor = node.next;
        }
        assert_eq!(cache.tail, prev);
        assert_eq!(forward.len(), cache.len());
        let weight: usize = forward.iter().map(|&idx| cache.node(idx).weight).sum();
        assert_eq!(weight, cache.weight);
        if let Some(max) = cache.max_weight() {
            assert!(cache.weight <= max);
        }
        assert!(cache.len() <= cache.capacity.get());
        assert_eq!(
            cache.slots.iter().filter(|s| s.is_none()).count(),
            cache.free.len()
        );
    }

    /// Keys from most to least recently used.
    fn order(cache: &LruCache<String, u32>) -> Vec<String> {
        let mut keys = Vec::new();
        let mut cursor = cache.head;
        while let Some(idx) = cursor {
            keys.push(cache.node(idx).key.clone());
            cursor = cache.node(idx).next;
        }
        keys
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut c = cache(2);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        assert_eq!(c.get("a"), Some(&1));
        c.insert("c".into(), 3);

        assert!(!c.contains("b"));
        assert_eq!(order(&c), ["c", "a"]);
        assert_eq!(c.stats().evictions, 1);
        assert_consistent(&c);
    }

    #[test]
    fn overwrite_returns_previous_and_promotes() {
        let mut c = cache(2);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        assert_eq!(c.insert("a".into(), 10), Some(1));
        assert_eq!(c.len(), 2);
        assert_eq!(order(&c), ["a", "b"]);

        c.insert("c".into(), 3);
        assert_eq!(c.peek("a"), Some(&10));
        assert!(!c.contains("b"));
        assert_consistent(&c);
    }

    #[test]
    fn peek_does_not_promote_or_count() {
        let mut c = cache(2);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        assert_eq!(c.peek("a"), Some(&1));
        c.insert("c".into(), 3);

        assert!(!c.contains("a"));
        assert_eq!(c.stats().hits, 0);
        assert_eq!(c.stats().misses, 0);
    }

    #[test]
    fn remove_and_reuse_slots() {
        let mut c = cache(3);
        for (i, k) in ["a", "b", "c"].into_iter().enumerate() {
            c.insert(k.into(), i as u32);
        }
        assert_eq!(c.remove("b"), Some(1));
        assert_eq!(c.remove("b"), None);
        c.insert("d".into(), 3);

        assert_eq!(c.slots.len(), 3, "freed slot should be recycled");
        assert_eq!(order(&c), ["d", "c", "a"]);
        assert_consistent(&c);
    }

    #[test]
    fn capacity_one() {
        let mut c = cache(1);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("b"), Some(&2));
        assert_eq!(c.get("a"), None);
        assert_consistent(&c);
    }

    #[test]
    fn clear_keeps_stats() {
        let mut c = cache(2);
        c.insert("a".into(), 1);
        c.get("a");
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.stats().hits, 1);
        assert_consistent(&c);
    }

    #[test]
    fn hit_and_miss_counters() {
        let mut c = cache(2);
        c.insert("a".into(), 1);
        c.get("a");
        c.get("a");
        c.get("missing");
        let stats = c.stats();
        assert_eq!((stats.hits, stats.misses, stats.insertions), (2, 1, 1));
    }

    #[test]
    fn entries_expire_after_ttl() {
        let ttl = Duration::from_secs(60);
        let mut c = cache(2).with_ttl(ttl);
        let t0 = Instant::now();
        c.insert_at("a".into(), 1, Some(t0 + ttl), t0);

        assert_eq!(c.get_at("a", t0 + ttl - Duration::from_secs(1)), Some(&1));
        assert_eq!(c.get_at("a", t0 + ttl), None);
        assert!(c.is_empty());
        assert_eq!(c.stats().expirations, 1);
        assert_consistent(&c);
    }

    #[test]
    fn overwrite_refreshes_ttl() {
        let ttl = Duration::from_secs(60);
        let mut c = cache(2).with_ttl(ttl);
        let t0 = Instant::now();
        c.insert_at("a".into(), 1, Some(t0 + ttl), t0);
        let previous = c.insert_at("a".into(), 2, Some(t0 + ttl + ttl), t0 + ttl);

        assert_eq!(previous, None, "expired value is not reported as previous");
        assert_eq!(c.get_at("a", t0 + ttl + Duration::from_secs(1)), Some(&2));
    }

    #[test]
    fn purge_expired_only_drops_expired() {
        let ttl = Duration::from_secs(60);
        let mut c = cache(4).with_ttl(ttl);
        let t0 = Instant::now();
        c.insert_at("old1".into(), 1, Some(t0 + ttl), t0);
        c.insert_at("new".into(), 2, Some(t0 + Duration::from_secs(90)), t0);
        c.insert_at("old2".into(), 3, Some(t0 + ttl), t0);

        assert_eq!(c.purge_expired_at(t0 + ttl), 2);
        assert_eq!(order(&c), ["new"]);
        assert_eq!(c.stats().expirations, 2);
        assert_consistent(&c);
    }

    #[test]
    fn full_cache_evicting_expired_tail_counts_expiration() {
        let ttl = Duration::from_secs(60);
        let mut c = cache(1).with_ttl(ttl);
        let t0 = Instant::now();
        c.insert_at("a".into(), 1, Some(t0 + ttl), t0);
        c.insert_at("b".into(), 2, Some(t0 + ttl + ttl), t0 + ttl);

        let stats = c.stats();
        assert_eq!((stats.evictions, stats.expirations), (0, 1));
    }

    #[allow(clippy::ptr_arg)] // signature fixed by `Weigher`
    fn byte_weigher(k: &String, v: &u32) -> usize {
        k.len() + *v as usize
    }

    #[test]
    fn evicts_to_stay_within_weight() {
        let mut c = cache(10).with_max_weight(10, byte_weigher);
        c.insert("a".into(), 3); // weight 4
        c.insert("b".into(), 3); // weight 4
        c.insert("c".into(), 3); // weight 4, evicts "a"

        assert_eq!(order(&c), ["c", "b"]);
        assert_eq!(c.weight(), 8);
        assert_eq!(c.stats().evictions, 1);
        assert_consistent(&c);
    }

    #[test]
    fn overwrite_adjusts_weight() {
        let mut c = cache(10).with_max_weight(10, byte_weigher);
        c.insert("a".into(), 1);
        c.insert("b".into(), 1);
        c.insert("a".into(), 8); // weight 9, evicts "b"

        assert_eq!(order(&c), ["a"]);
        assert_eq!(c.weight(), 9);
        assert_consistent(&c);
    }

    #[test]
    fn rejects_entry_heavier_than_limit() {
        let mut c = cache(10).with_max_weight(10, byte_weigher);
        c.insert("a".into(), 1);
        c.insert("b".into(), 1);
        c.insert("b".into(), 100);

        assert_eq!(order(&c), ["a"], "stale `b` dropped, `a` untouched");
        assert_eq!(c.stats().rejections, 1);
        assert_consistent(&c);
    }

    #[test]
    fn insert_with_ttl_is_capped_by_default_ttl() {
        let mut c = cache(2).with_ttl(Duration::from_secs(60));
        c.insert_with_ttl("a".into(), 1, Duration::from_secs(3600));
        let deadline = c.node(c.head.unwrap()).expires_at.unwrap();
        assert!(deadline <= Instant::now() + Duration::from_secs(60));
    }

    #[test]
    fn keys_in_recency_order() {
        let mut c = cache(3);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        c.get("a");
        assert_eq!(c.keys().cloned().collect::<Vec<_>>(), ["a", "b"]);
    }

    #[test]
    fn randomized_against_model() {
        // Deterministic xorshift so the test needs no extra dependency.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let capacity = 8;
        let mut c = cache(capacity);
        // Model: keys ordered from least to most recently used.
        let mut model: Vec<(String, u32)> = Vec::new();

        for step in 0..10_000u32 {
            let key = format!("k{}", next() % 16);
            match next() % 3 {
                0 => {
                    c.insert(key.clone(), step);
                    model.retain(|(k, _)| *k != key);
                    if model.len() == capacity {
                        model.remove(0);
                    }
                    model.push((key, step));
                }
                1 => {
                    let expected = model.iter().position(|(k, _)| *k == key).map(|pos| {
                        let entry = model.remove(pos);
                        let value = entry.1;
                        model.push(entry);
                        value
                    });
                    assert_eq!(c.get(&key).copied(), expected);
                }
                _ => {
                    let expected = model
                        .iter()
                        .position(|(k, _)| *k == key)
                        .map(|pos| model.remove(pos).1);
                    assert_eq!(c.remove(&key), expected);
                }
            }
            assert_eq!(c.len(), model.len());
        }
        assert_consistent(&c);
    }
}
