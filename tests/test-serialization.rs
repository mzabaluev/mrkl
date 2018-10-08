#![cfg(test)]
#![cfg(all(feature = "serialization", feature = "digest"))]

extern crate mrkl;
extern crate serde_json;
extern crate sha2;

use mrkl::digest::ByteDigestHasher;
use mrkl::leaf;
use mrkl::tree::Builder;
use sha2::Sha256;

type Hasher = ByteDigestHasher<Sha256>;

const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn serialize() {
    let hasher = Hasher::new();
    let leaf_extractor = leaf::extract_with(|input: &[u8]| {
        String::from_utf8(input.to_vec()).unwrap()
    });
    let builder = Builder::from_hasher_leaf_data(hasher, leaf_extractor);
    let tree = builder.complete_tree_from(TEST_DATA.chunks(10)).unwrap();
    let json = serde_json::to_string_pretty(&tree).unwrap();
    println!("{}", json);
}
