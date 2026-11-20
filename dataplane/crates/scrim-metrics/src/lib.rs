// SPDX-License-Identifier: AGPL-3.0-only

//! Metric primitives the scrim data plane aggregates locally.
//!
//! The request path only ever touches atomics: [`Counter::inc`], [`Gauge::set`] and
//! [`Histogram::observe`] are a relaxed `fetch_add` or `store` each, with no lock and no
//! allocation. Series keyed by a label value live in a [`Labelled`] map that the request path
//! reads under an uncontended read lock, once per request, and only writes the first time a
//! label value appears. The number of label values per map is capped; past the cap new values
//! share one [`OVERFLOW`] series, so a misbehaving label can never grow memory without bound.
//!
//! Nothing here formats Prometheus text: owners turn their series into [`Family`] values on
//! demand (one control-plane scrape), which the data plane sends over the boundary protocol.
//!
//! Label values must be configured names (routes), codec names or enumerations. Never a secret
//! reference, a placeholder or a value: callers pass only those, and the control plane scrubs
//! the page again before it serves it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

/// The label value every series past a [`Labelled`] map's cap is folded into.
pub const OVERFLOW: &str = "_other";

/// A monotonically increasing count.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// A zero counter.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n`.
    pub fn add(&self, n: u64) {
        if n > 0 {
            self.0.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// The current count.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A value that goes up and down.
#[derive(Debug, Default)]
pub struct Gauge(AtomicI64);

impl Gauge {
    /// A zero gauge.
    pub const fn new() -> Self {
        Self(AtomicI64::new(0))
    }

    /// Sets the value.
    pub fn set(&self, v: i64) {
        self.0.store(v, Ordering::Relaxed);
    }

    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Subtracts one.
    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    /// The current value.
    pub fn get(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Adds one now and subtracts it again when the guard drops: an "in progress" count, such
    /// as open connections.
    pub fn track(self: &Arc<Self>) -> GaugeGuard {
        self.inc();
        GaugeGuard(Arc::clone(self))
    }
}

/// Subtracts one from its gauge when dropped. See [`Gauge::track`].
#[derive(Debug)]
pub struct GaugeGuard(Arc<Gauge>);

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Fixed histogram buckets: upper bounds in raw units (nanoseconds, bytes) and the factor that
/// turns a raw unit into the exported base unit (seconds, bytes).
#[derive(Debug)]
pub struct Buckets {
    /// Upper bounds in raw units, ascending, without +Inf.
    pub bounds: &'static [u64],
    /// Base units per raw unit: `1e-9` for nanoseconds to seconds, `1.0` for bytes.
    pub scale: f64,
}

impl Buckets {
    /// The bounds in base units, for export.
    pub fn exported(&self) -> Vec<f64> {
        self.bounds
            .iter()
            .map(|&b| to_f64(b) * self.scale)
            .collect()
    }
}

/// Added latency per request (redaction, guard, both): 50 µs to 50 ms, with the 5 ms and 10 ms
/// budgets (specs/performance) on bucket bounds.
pub const REQUEST_LATENCY: Buckets = Buckets {
    bounds: &[
        50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 25_000_000,
        50_000_000,
    ],
    scale: 1e-9,
};

/// Added latency per streamed chunk: 1 µs to 1 ms, with the 50 µs budget on a bound.
pub const CHUNK_LATENCY: Buckets = Buckets {
    bounds: &[
        1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
    ],
    scale: 1e-9,
};

/// Upstream time to response headers: 50 ms to 2 min (model calls are slow).
pub const UPSTREAM_LATENCY: Buckets = Buckets {
    bounds: &[
        50_000_000,
        100_000_000,
        250_000_000,
        500_000_000,
        1_000_000_000,
        2_500_000_000,
        5_000_000_000,
        10_000_000_000,
        30_000_000_000,
        60_000_000_000,
        120_000_000_000,
    ],
    scale: 1e-9,
};

/// Snapshot apply time: 1 ms to 10 s.
pub const APPLY_LATENCY: Buckets = Buckets {
    bounds: &[
        1_000_000,
        5_000_000,
        10_000_000,
        50_000_000,
        100_000_000,
        250_000_000,
        500_000_000,
        1_000_000_000,
        2_500_000_000,
        10_000_000_000,
    ],
    scale: 1e-9,
};

/// Request body sizes: 1 KiB to 16 MiB in steps of four.
pub const BODY_BYTES: Buckets = Buckets {
    bounds: &[
        1 << 10,
        1 << 12,
        1 << 14,
        1 << 16,
        1 << 18,
        1 << 20,
        1 << 22,
        1 << 24,
    ],
    scale: 1.0,
};

/// A histogram over fixed buckets.
#[derive(Debug)]
pub struct Histogram {
    buckets: &'static Buckets,
    /// One count per bound plus the +Inf bucket; not cumulative.
    counts: Box<[AtomicU64]>,
    /// Sum of observations in raw units.
    sum: AtomicU64,
}

impl Histogram {
    /// An empty histogram over `buckets`.
    pub fn new(buckets: &'static Buckets) -> Self {
        Self {
            buckets,
            counts: (0..=buckets.bounds.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            sum: AtomicU64::new(0),
        }
    }

    /// Records one observation in raw units.
    pub fn observe(&self, raw: u64) {
        let bounds = self.buckets.bounds;
        let i = bounds
            .iter()
            .position(|&b| raw <= b)
            .unwrap_or(bounds.len());
        self.counts[i].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(raw, Ordering::Relaxed);
    }

    /// Records a duration (for buckets in nanoseconds).
    pub fn observe_duration(&self, d: Duration) {
        self.observe(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    }

    /// Cumulative counts per bound (without +Inf), the total count and the sum in base units.
    /// The total is the sum of the buckets read, so it always equals the +Inf bucket.
    pub fn read(&self) -> (Vec<u64>, u64, f64) {
        let mut cumulative = Vec::with_capacity(self.buckets.bounds.len());
        let mut acc = 0u64;
        for (i, c) in self.counts.iter().enumerate() {
            acc = acc.saturating_add(c.load(Ordering::Relaxed));
            if i < self.buckets.bounds.len() {
                cumulative.push(acc);
            }
        }
        let sum = to_f64(self.sum.load(Ordering::Relaxed)) * self.buckets.scale;
        (cumulative, acc, sum)
    }

    /// The buckets this histogram uses.
    pub fn buckets(&self) -> &'static Buckets {
        self.buckets
    }
}

/// Series keyed by one label value, created on first use, capped at a number of values.
#[derive(Debug)]
pub struct Labelled<T> {
    cap: usize,
    make: fn() -> T,
    map: RwLock<HashMap<Box<str>, Arc<T>>>,
}

impl<T> Labelled<T> {
    /// A map of at most `cap` label values (plus [`OVERFLOW`]); `make` builds a new series.
    pub fn new(cap: usize, make: fn() -> T) -> Self {
        Self {
            cap,
            make,
            map: RwLock::new(HashMap::new()),
        }
    }

    /// The series for `key`, created on first use. Past the cap, the [`OVERFLOW`] series.
    pub fn get(&self, key: &str) -> Arc<T> {
        if let Some(v) = self
            .map
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
        {
            return Arc::clone(v);
        }
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(v) = map.get(key) {
            return Arc::clone(v);
        }
        let key = if map.len() >= self.cap { OVERFLOW } else { key };
        Arc::clone(
            map.entry(key.into())
                .or_insert_with(|| Arc::new((self.make)())),
        )
    }

    /// Calls `f` with every label value and series, sorted by label value.
    pub fn each(&self, mut f: impl FnMut(&str, &T)) {
        let mut all: Vec<(Box<str>, Arc<T>)> = self
            .map
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(k, v)| (k.clone(), Arc::clone(v)))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        for (k, v) in &all {
            f(k, v);
        }
    }

    /// How many label values exist.
    pub fn len(&self) -> usize {
        self.map
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no series exists yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a family measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Monotonic count.
    Counter,
    /// Current value.
    Gauge,
    /// Distribution over fixed buckets.
    Histogram,
}

/// One series of an exported family.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Label values, by position of [`Family::labels`].
    pub labels: Vec<String>,
    /// Counter or gauge value.
    pub value: f64,
    /// Cumulative bucket counts (histograms).
    pub buckets: Vec<u64>,
    /// Observation count (histograms).
    pub count: u64,
    /// Observation sum in base units (histograms).
    pub sum: f64,
}

/// An exported metric family.
#[derive(Debug, Clone, PartialEq)]
pub struct Family {
    /// Full metric name, `scrim_dataplane_...`.
    pub name: &'static str,
    /// Help text.
    pub help: &'static str,
    /// Type.
    pub kind: Kind,
    /// Label names.
    pub labels: &'static [&'static str],
    /// Histogram upper bounds in base units.
    pub bounds: Vec<f64>,
    /// Series.
    pub samples: Vec<Sample>,
}

impl Family {
    /// An empty counter family.
    pub fn counter(
        name: &'static str,
        help: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        Self::new(name, help, Kind::Counter, labels, Vec::new())
    }

    /// An empty gauge family.
    pub fn gauge(name: &'static str, help: &'static str, labels: &'static [&'static str]) -> Self {
        Self::new(name, help, Kind::Gauge, labels, Vec::new())
    }

    /// An empty histogram family over `buckets`.
    pub fn histogram(
        name: &'static str,
        help: &'static str,
        labels: &'static [&'static str],
        buckets: &Buckets,
    ) -> Self {
        Self::new(name, help, Kind::Histogram, labels, buckets.exported())
    }

    fn new(
        name: &'static str,
        help: &'static str,
        kind: Kind,
        labels: &'static [&'static str],
        bounds: Vec<f64>,
    ) -> Self {
        Self {
            name,
            help,
            kind,
            labels,
            bounds,
            samples: Vec::new(),
        }
    }

    /// Adds a counter or gauge series.
    pub fn value(&mut self, labels: &[&str], value: f64) -> &mut Self {
        debug_assert_eq!(labels.len(), self.labels.len(), "{}", self.name);
        self.samples.push(Sample {
            labels: labels.iter().map(|&s| s.to_owned()).collect(),
            value,
            buckets: Vec::new(),
            count: 0,
            sum: 0.0,
        });
        self
    }

    /// Adds a counter series.
    pub fn count(&mut self, labels: &[&str], c: &Counter) -> &mut Self {
        self.value(labels, to_f64(c.get()))
    }

    /// Adds a histogram series. A histogram with no observation is left out.
    pub fn observed(&mut self, labels: &[&str], h: &Histogram) -> &mut Self {
        debug_assert_eq!(labels.len(), self.labels.len(), "{}", self.name);
        let (buckets, count, sum) = h.read();
        if count == 0 {
            return self;
        }
        self.samples.push(Sample {
            labels: labels.iter().map(|&s| s.to_owned()).collect(),
            value: 0.0,
            buckets,
            count,
            sum,
        });
        self
    }
}

/// Converts a count to the exported float. Counts above 2^53 lose precision, which Prometheus
/// counters accept.
#[allow(clippy::cast_precision_loss)]
pub fn to_f64(v: u64) -> f64 {
    v as f64
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]
    use super::*;

    #[test]
    fn histogram_buckets_are_cumulative_and_count_matches_inf() {
        let h = Histogram::new(&REQUEST_LATENCY);
        h.observe(10_000); // first bucket
        h.observe(5_000_000); // exactly on the 5 ms bound
        h.observe(5_000_001); // next bucket
        h.observe(u64::MAX / 4); // +Inf
        let (b, count, sum) = h.read();
        assert_eq!(b.len(), REQUEST_LATENCY.bounds.len());
        assert_eq!(b[0], 1);
        assert_eq!(b[6], 2, "5 ms bound is inclusive");
        assert_eq!(b[7], 3);
        assert_eq!(*b.last().unwrap_or(&0), 3);
        assert_eq!(count, 4);
        assert!(sum > 0.0);
        assert_eq!(REQUEST_LATENCY.exported()[6], 0.005);
    }

    #[test]
    fn labelled_caps_cardinality() {
        let l: Labelled<Counter> = Labelled::new(2, Counter::new);
        l.get("a").inc();
        l.get("b").inc();
        l.get("c").inc();
        l.get("d").inc();
        l.get("a").inc();
        let mut seen = Vec::new();
        l.each(|k, c| seen.push((k.to_owned(), c.get())));
        assert_eq!(
            seen,
            [("_other".into(), 2), ("a".into(), 2), ("b".into(), 1)]
        );
    }

    #[test]
    fn gauge_guard_decrements() {
        let g = Arc::new(Gauge::new());
        let a = g.track();
        let b = g.track();
        assert_eq!(g.get(), 2);
        drop(a);
        drop(b);
        assert_eq!(g.get(), 0);
    }

    #[test]
    fn empty_histogram_is_not_exported() {
        let h = Histogram::new(&CHUNK_LATENCY);
        let mut f = Family::histogram("x", "x", &["route"], &CHUNK_LATENCY);
        f.observed(&["r"], &h);
        assert_eq!(f.samples.len(), 0);
        h.observe_duration(Duration::from_micros(3));
        f.observed(&["r"], &h);
        assert_eq!(f.samples[0].count, 1);
        assert_eq!(f.samples[0].buckets[2], 1);
    }
}
