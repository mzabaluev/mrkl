// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A generic, minimalist Merkle tree.
//!
//! An implementation of Merkle tree that is generic over the hashed input
//! data, the hash function, and what gets into leaf data.
//!
//! Optional support is provided for the cryptographic hash functions
//! that conform to the API defined in crate `digest`.

#[cfg(feature = "serialization")]
#[macro_use] extern crate serde_derive;

pub mod hash;
pub mod leaf;
pub mod tree;

#[cfg(feature = "digest")]
pub mod digest;

pub use tree::MerkleTree;
