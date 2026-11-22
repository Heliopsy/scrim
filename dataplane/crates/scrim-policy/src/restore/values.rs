// SPDX-License-Identifier: AGPL-3.0-only

//! What the restore policy knows about each value: its reference, slug, class, catalog name,
//! store and labels, and the [`ValueTraits`] the streaming path needs. Never the value itself.

use std::collections::HashMap;
use std::sync::Arc;

use scrim_proto::v1 as pb;

use crate::escape::ValueTraits;

/// How a value may be used once a placeholder resolves to it (design D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueClass {
    /// Never restored into responses; injected toward bound hosts only.
    Credential,
    /// Restored under the tool policy.
    Display,
}

impl ValueClass {
    /// Converts a wire class; unspecified and unknown values are credentials.
    pub fn from_proto(c: i32) -> ValueClass {
        match pb::ValueClass::try_from(c) {
            Ok(pb::ValueClass::Display) => ValueClass::Display,
            _ => ValueClass::Credential,
        }
    }

    /// `credential` or `display`, as rules see `secret.class`.
    pub fn as_str(self) -> &'static str {
        match self {
            ValueClass::Credential => "credential",
            ValueClass::Display => "display",
        }
    }
}

/// Metadata of one value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueInfo {
    /// Store reference (`ValueEntry.ref`).
    pub reference: Arc<str>,
    /// Placeholder slug.
    pub slug: Arc<str>,
    /// Class.
    pub class: ValueClass,
    /// Catalog name.
    pub name: Arc<str>,
    /// Store instance.
    pub store: Arc<str>,
    /// Character classes of the value.
    pub traits: ValueTraits,
    /// The value's labels that the snapshot's policy reads (`ValueEntry.labels`). `None` when
    /// the control plane sent no labels (`Snapshot.value_labels` false): rules on
    /// `secret.labels` are then unknown. Identical maps are shared ([`LabelInterner`]).
    pub labels: Option<Labels>,
}

/// A value's labels, shared between values whose maps are equal.
pub type Labels = Arc<HashMap<String, String>>;

/// Shares one allocation between values whose label maps are equal: a policy reads few label
/// keys, so most values carry one of a handful of maps (often the empty one).
#[derive(Default)]
pub struct LabelInterner {
    seen: HashMap<Vec<(String, String)>, Labels>,
}

impl LabelInterner {
    /// The shared copy of `m`.
    pub fn intern(&mut self, m: &HashMap<String, String>) -> Labels {
        let mut key: Vec<(String, String)> =
            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        key.sort_unstable();
        Arc::clone(self.seen.entry(key).or_insert_with(|| Arc::new(m.clone())))
    }

    /// `ValueInfo::labels` for an entry: `None` unless `known` (`Snapshot.value_labels`).
    pub fn labels(&mut self, m: &HashMap<String, String>, known: bool) -> Option<Labels> {
        known.then(|| self.intern(m))
    }
}

/// Every value of a snapshot, by reference and by slug.
#[derive(Clone, Debug, Default)]
pub struct ValueIndex {
    items: Vec<ValueInfo>,
    by_ref: HashMap<Arc<str>, usize>,
    by_slug: HashMap<Arc<str>, Vec<usize>>,
}

impl ValueIndex {
    /// An empty index.
    pub fn new() -> ValueIndex {
        ValueIndex::default()
    }

    /// Indexes the snapshot's value dictionary. Entry `i` is at position `i`, so a data plane
    /// that builds its scrim-redact entries with `EntryId(i)` can look them up with
    /// [`ValueIndex::by_position`]. The values are read once to compute their traits and not
    /// kept.
    /// `value_labels` is `Snapshot.value_labels`.
    pub fn from_entries(entries: &[pb::ValueEntry], value_labels: bool) -> ValueIndex {
        let mut ix = ValueIndex::new();
        let mut labels = LabelInterner::default();
        for e in entries {
            ix.push(ValueInfo {
                reference: e.r#ref.as_str().into(),
                slug: e.slug.as_str().into(),
                class: ValueClass::from_proto(e.class),
                name: e.name.as_str().into(),
                store: e.store.as_str().into(),
                traits: ValueTraits::of(&e.value),
                labels: labels.labels(&e.labels, value_labels),
            });
        }
        ix
    }

    /// Adds one value. A reference seen before keeps its first position for lookups by
    /// reference.
    pub fn push(&mut self, info: ValueInfo) {
        let i = self.items.len();
        self.by_ref.entry(info.reference.clone()).or_insert(i);
        self.by_slug.entry(info.slug.clone()).or_default().push(i);
        self.items.push(info);
    }

    /// Number of values.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The value at `i`.
    pub fn by_position(&self, i: usize) -> Option<&ValueInfo> {
        self.items.get(i)
    }

    /// The value with reference `r`, or failing that the only value whose slug is `r` (so a
    /// caller that names values by slug works too).
    pub fn lookup(&self, r: &str) -> Option<&ValueInfo> {
        if let Some(&i) = self.by_ref.get(r) {
            return self.items.get(i);
        }
        match self.by_slug.get(r).map(Vec::as_slice) {
            Some([i]) => self.items.get(*i),
            _ => None,
        }
    }

    /// Every value with slug `s`.
    pub fn with_slug<'a>(&'a self, s: &str) -> impl Iterator<Item = &'a ValueInfo> + 'a {
        self.by_slug
            .get(s)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.items.get(i))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    #[test]
    fn index_lookups() {
        let e = |r: &str, slug: &str, class: pb::ValueClass| {
            let mut e = pb::ValueEntry::default();
            e.r#ref = r.into();
            e.slug = slug.into();
            e.value = b"value-bytes".to_vec();
            e.class = class as i32;
            e
        };
        let ix = ValueIndex::from_entries(
            &[
                e("bao://kv/a#x", "a", pb::ValueClass::Display),
                e("bao://kv/b#x", "b", pb::ValueClass::Unspecified),
                e("bao://kv/b2#x", "b", pb::ValueClass::Credential),
            ],
            true,
        );
        assert_eq!(ix.len(), 3);
        assert!(!ix.is_empty());
        assert_eq!(
            ix.lookup("bao://kv/a#x").unwrap().class,
            ValueClass::Display
        );
        assert_eq!(ix.lookup("a").unwrap().reference.as_ref(), "bao://kv/a#x");
        assert!(ix.lookup("b").is_none(), "ambiguous slug");
        assert_eq!(
            ix.lookup("bao://kv/b#x").unwrap().class,
            ValueClass::Credential
        );
        assert_eq!(ix.with_slug("b").count(), 2);
        assert_eq!(
            ix.by_position(2).unwrap().reference.as_ref(),
            "bao://kv/b2#x"
        );
        assert_eq!(ValueClass::from_proto(77), ValueClass::Credential);
        assert_eq!(ValueClass::Display.as_str(), "display");
        // The value never shows up in Debug output.
        assert!(!format!("{ix:?}").contains("value-bytes"));
    }

    #[test]
    fn labels_are_shared_and_unknown_without_the_snapshot_flag() {
        let e = |r: &str, labels: &[(&str, &str)]| {
            let mut e = pb::ValueEntry::default();
            e.r#ref = r.into();
            e.slug = r.into();
            e.value = b"value-bytes".to_vec();
            e.labels = labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            e
        };
        let entries = [
            e("a", &[("tier", "prod")]),
            e("b", &[("tier", "prod")]),
            e("c", &[]),
            e("d", &[]),
        ];
        let ix = ValueIndex::from_entries(&entries, true);
        let l = |i: usize| ix.by_position(i).unwrap().labels.clone().unwrap();
        assert_eq!(l(0).get("tier").map(String::as_str), Some("prod"));
        assert!(Arc::ptr_eq(&l(0), &l(1)));
        assert!(l(2).is_empty() && Arc::ptr_eq(&l(2), &l(3)));
        let old = ValueIndex::from_entries(&entries, false);
        assert!(old.by_position(0).unwrap().labels.is_none());
    }
}
