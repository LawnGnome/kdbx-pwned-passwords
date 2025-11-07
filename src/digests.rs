use std::collections::{BTreeMap, BTreeSet};

use fstr::FStr;
use sha1_smol::Digest;

#[derive(Default, Debug)]
pub struct Digests(BTreeMap<FStr<5>, BTreeMap<FStr<40>, BTreeSet<String>>>);

impl Digests {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn upsert(&mut self, digest: Digest, name: String) {
        let digest = FStr::try_from(digest.to_string()).unwrap();
        let prefix = FStr::from_str_lossy(digest.split_at(5).0, b'\0');

        self.0
            .entry(prefix)
            .or_default()
            .entry(digest)
            .or_default()
            .insert(name);
    }
}

impl IntoIterator for Digests {
    type Item = (FStr<5>, BTreeMap<FStr<40>, BTreeSet<String>>);

    type IntoIter =
        std::collections::btree_map::IntoIter<FStr<5>, BTreeMap<FStr<40>, BTreeSet<String>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
