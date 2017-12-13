// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for cryptographic hash functions.
//!
//! This module provides an implementation of the trait `hash::Hasher`
//! that is backed by cryptographic hash functions conformant
//! to the traits defined in crate `digest`, optionally augmented with
//! generic, byte order aware hashing provided by crate `digest-hash`.
//!
//! This module is only available if the crate has been compiled with
//! the `digest-hash` feature, which is enabled by default.

use hash::{Hasher, NodeHasher};
use tree::{Nodes, Node};

pub extern crate digest_hash;

use self::digest_hash::{Hash, Endian, EndianInput};
use self::digest_hash::digest::{Input, FixedOutput};
use self::digest_hash::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;


#[derive(Clone)]
struct NodeDigestHasher<D> {
    phantom: PhantomData<D>
}

impl<D> NodeDigestHasher<D> {
    fn new() -> Self { NodeDigestHasher { phantom: PhantomData } }
}

impl<D> NodeHasher for NodeDigestHasher<D>
    where D: Default,
          D: Input,
          D: FixedOutput
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_nodes<'a, L>(&'a self,
                         iter: Nodes<'a, Self::HashOutput, L>)
                         -> Self::HashOutput
    {
        let mut digest = D::default();
        for node in iter {
            match *node {
                Node::Leaf(ref ln) => {
                    digest.process(&[0u8]);
                    digest.process(ln.hash_bytes());
                }
                Node::Hash(ref hn) => {
                    digest.process(&[1u8]);
                    digest.process(hn.hash_bytes());
                }
            }
        }
        digest.fixed_result()
    }
}

/// Provides a cryptographic hash function implementation
/// for hashing Merkle trees with byte order sensitive input.
///
/// The hash function implementation is defined by the type parameter.
/// As the byte order may be important for generic input values, that type
/// has to implement `digest_hash::EndianInput`.
///
#[derive(Clone)]
pub struct DigestHasher<D> {
    node_hasher: NodeDigestHasher<D>
}

impl<D: EndianInput> DigestHasher<D> {
    /// Constructs a new instance of the hash extractor.
    pub fn new() -> Self {
        DigestHasher {
            node_hasher: NodeDigestHasher::new()
        }
    }
}

impl<D> Default for DigestHasher<D>
    where D: EndianInput
{
    fn default() -> Self { Self::new() }
}

impl<D> Debug for DigestHasher<D>
    where D: EndianInput
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_tuple("DigestHasher")
         .field(&Endian::<D, D::ByteOrder>::byte_order_str())
         .finish()
    }
}

impl<D, In: ?Sized> Hasher<In> for DigestHasher<D>
    where In: Hash,
          D: Default,
          D: EndianInput,
          D: FixedOutput
{
    fn hash_input(&self, input: &In) -> Self::HashOutput {
        let mut digest = D::default();
        input.hash(&mut digest);
        digest.fixed_result()
    }
}

impl<D> NodeHasher for DigestHasher<D>
where D: Default,
      D: EndianInput,
      D: FixedOutput
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_nodes<'a, L>(
        &'a self,
        iter: Nodes<'a, Self::HashOutput, L>
    ) -> Self::HashOutput {
        self.node_hasher.hash_nodes(iter)
    }
}

/// Provides a cryptographic hash function implementation
/// for hashing Merkle trees with byte slice convertible input.
///
/// The hash function implementation is defined by the type parameter.
/// In contrast to the more generic `DigestHasher`, the parameter type is
/// bound by byte-oriented `digest::Input`, so any cryptographic digest
/// function implementations implementing this trait, plus
/// `digest::FixedOutput` and `Default`, are directly usable.
///
#[derive(Clone)]
pub struct ByteDigestHasher<D> {
    node_hasher: NodeDigestHasher<D>
}

impl<D: Input> ByteDigestHasher<D> {
    /// Constructs a new instance of the hash extractor.
    pub fn new() -> Self {
        ByteDigestHasher {
            node_hasher: NodeDigestHasher::new()
        }
    }
}

impl<D: Input> Default for ByteDigestHasher<D> {
    fn default() -> Self { Self::new() }
}

impl<D> Debug for ByteDigestHasher<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("ByteDigestHasher")
    }
}

impl<D, In: ?Sized> Hasher<In> for ByteDigestHasher<D>
    where In: AsRef<[u8]>,
          D: Default,
          D: Input,
          D: FixedOutput
{
    fn hash_input(&self, input: &In) -> Self::HashOutput {
        let mut digest = D::default();
        digest.process(input.as_ref());
        digest.fixed_result()
    }
}

impl<D> NodeHasher for ByteDigestHasher<D>
where D: Default,
      D: Input,
      D: FixedOutput
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_nodes<'a, L>(
        &'a self,
        iter: Nodes<'a, Self::HashOutput, L>
    ) -> Self::HashOutput {
        self.node_hasher.hash_nodes(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestHasher, ByteDigestHasher};
    use hash::Hasher;

    extern crate sha2;

    use self::sha2::{Sha256, Digest};
    use super::digest_hash::{BigEndian, EndianInput, Hash};

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    struct Hashable {
        a: u32
    }

    impl Hash for Hashable {
        fn hash<H: EndianInput>(&self, digest: &mut H) {
            self.a.hash(digest)
        }
    }

    #[test]
    fn hash_byte_input() {
        let hasher = ByteDigestHasher::<Sha256>::new();
        let hash = hasher.hash_input(&TEST_DATA);
        assert_eq!(hash, Sha256::digest(TEST_DATA));
    }

    #[test]
    fn hash_endian_input() {
        let hasher = DigestHasher::<BigEndian<Sha256>>::new();
        let hash = hasher.hash_input(&Hashable { a: 42 });
        assert_eq!(hash, Sha256::digest(&[0, 0, 0, 42][..]));
    }
}
