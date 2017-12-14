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
//! the `digest` feature, which is enabled by default.

use hash::{Hasher, NodeHasher};
use tree::{Nodes, Node};

pub extern crate digest_hash;

use self::digest_hash::{Hash, Endian, EndianInput};
use self::digest_hash::digest::{Input, FixedOutput};
use self::digest_hash::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;


/// The `NodeHasher` implementation used by default in this module.
///
/// This implementation provides protection against potential
/// second-preimage attacks by prepending the hash of each child node
/// with a byte value indicating the node's type: 0 is prepended for
/// leaf nodes, 1 for hash nodes.
pub struct DefaultNodeHasher<D> {
    phantom: PhantomData<D>
}

impl<D> DefaultNodeHasher<D>
where D: Default,
      D: Input + FixedOutput
{
    /// Constructs an instance of the node hasher.
    pub fn new() -> Self { DefaultNodeHasher { phantom: PhantomData } }
}

impl<D> Default for DefaultNodeHasher<D>
where D: Default,
      D: Input + FixedOutput
{
    fn default() -> Self { DefaultNodeHasher::new() }
}

impl<D> Clone for DefaultNodeHasher<D> {
    fn clone(&self) -> Self {
        DefaultNodeHasher { phantom: PhantomData }
    }
}

impl<D> Debug for DefaultNodeHasher<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("DefaultNodeHasher")
    }
}

impl<D> NodeHasher for DefaultNodeHasher<D>
where D: Default,
      D: Input + FixedOutput
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
/// The hash function implementation is defined by the first type parameter.
/// As the byte order may be important for generic input values, that type
/// has to implement `digest_hash::EndianInput`.
///
/// The implementation of a concatenated hash over node's children is
/// defined by the second type parameter. The default choice should be good
/// enough unless a specific way to derive concatenated hashes is required.
///
pub struct DigestHasher<D, Nh = DefaultNodeHasher<D>>
where D: FixedOutput,
      Nh: NodeHasher
{
    node_hasher: Nh,
    phantom: PhantomData<D>
}

impl<D, Nh> DigestHasher<D, Nh>
where D: Default,
      D: EndianInput + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    /// Constructs a new instance of the hash extractor.
    pub fn new() -> Self {
        Self::with_node_hasher(Nh::default())
    }
}

impl<D, Nh> DigestHasher<D, Nh>
where D: Default,
      D: EndianInput + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    /// Constructs a new instance of the hash extractor taking an
    /// instance of the node hasher.
    pub fn with_node_hasher(node_hasher: Nh) -> Self {
        DigestHasher {
            node_hasher,
            phantom: PhantomData
        }
    }
}

impl<D, Nh> Default for DigestHasher<D, Nh>
where D: Default,
      D: EndianInput + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    fn default() -> Self { DigestHasher::new() }
}

impl<D, Nh> Clone for DigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher,
      Nh: Clone
{
    fn clone(&self) -> Self {
        DigestHasher {
            node_hasher: self.node_hasher.clone(),
            phantom: PhantomData
        }
    }
}

impl<D, Nh> Debug for DigestHasher<D, Nh>
where D: EndianInput + FixedOutput,
      Nh: NodeHasher,
      Nh: Debug
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_tuple("DigestHasher")
         .field(&self.node_hasher)
         .field(&Endian::<D, D::ByteOrder>::byte_order_str())
         .finish()
    }
}

impl<D, Nh, In: ?Sized> Hasher<In> for DigestHasher<D, Nh>
where In: Hash,
      D: Default,
      D: EndianInput + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    fn hash_input(&self, input: &In) -> Self::HashOutput {
        let mut digest = D::default();
        input.hash(&mut digest);
        digest.fixed_result()
    }
}

impl<D, Nh> NodeHasher for DigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
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
/// The hash function implementation is defined by the first type parameter.
/// In contrast to the more generic `DigestHasher`, the parameter type is
/// bound by byte-oriented `digest::Input`, so any cryptographic digest
/// function implementations implementing this trait, plus
/// `digest::FixedOutput` and `Default`, are directly usable.
///
/// The implementation of a concatenated hash over node's children is
/// defined by the second type parameter. The default choice should be good
/// enough unless a specific way to derive concatenated hashes is required.
///
pub struct ByteDigestHasher<D, Nh = DefaultNodeHasher<D>>
where D: FixedOutput,
      Nh: NodeHasher
{
    node_hasher: Nh,
    phantom: PhantomData<D>
}

impl<D, Nh> ByteDigestHasher<D, Nh>
where D: Default,
      D: Input + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    /// Constructs a new instance of the hash extractor.
    pub fn new() -> Self {
        Self::with_node_hasher(Nh::default())
    }
}

impl<D, Nh> ByteDigestHasher<D, Nh>
where D: Default,
      D: Input + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    /// Constructs a new instance of the hash extractor taking an
    /// instance of the node hasher.
    pub fn with_node_hasher(node_hasher: Nh) -> Self {
        ByteDigestHasher {
            node_hasher,
            phantom: PhantomData
        }
    }
}

impl<D, Nh> Default for ByteDigestHasher<D, Nh>
where D: Default,
      D: Input + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    fn default() -> Self { ByteDigestHasher::new() }
}

impl<D, Nh> Clone for ByteDigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher,
      Nh: Clone
{
    fn clone(&self) -> Self {
        ByteDigestHasher {
            node_hasher: self.node_hasher.clone(),
            phantom: PhantomData
        }
    }
}

impl<D, Nh> Debug for ByteDigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher,
      Nh: Debug
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_tuple("DigestHasher")
         .field(&self.node_hasher)
         .finish()
    }
}

impl<D, Nh, In: ?Sized> Hasher<In> for ByteDigestHasher<D, Nh>
where In: AsRef<[u8]>,
      D: Default,
      D: Input + FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    fn hash_input(&self, input: &In) -> Self::HashOutput {
        let mut digest = D::default();
        digest.process(input.as_ref());
        digest.fixed_result()
    }
}

impl<D, Nh> NodeHasher for ByteDigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
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
    use hash::{Hasher, NodeHasher};

    use tree::{Builder, Node, Nodes};
    use leaf;

    extern crate sha2;

    use self::sha2::{Sha256, Digest};
    use super::digest_hash::BigEndian;
    use super::digest_hash::digest::{Input, FixedOutput};
    use super::digest_hash::digest::generic_array::GenericArray;
    use std::fmt;
    use std::fmt::Debug;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn hash_byte_input() {
        let hasher = ByteDigestHasher::<Sha256>::new();
        let hash = hasher.hash_input(&TEST_DATA);
        assert_eq!(hash, Sha256::digest(TEST_DATA));
    }

    #[test]
    fn hash_endian_input() {
        let hasher = DigestHasher::<BigEndian<Sha256>>::new();
        let hash = hasher.hash_input(&42u16);
        assert_eq!(hash, Sha256::digest(&[0, 42][..]));
    }

    #[derive(Default)]
    struct CustomNodeHasher;

    impl Debug for CustomNodeHasher {
        fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
            f.write_str("CustomNodeHasher")
        }
    }

    impl NodeHasher for CustomNodeHasher {
        type HashOutput = GenericArray<u8, <Sha256 as FixedOutput>::OutputSize>;

        fn hash_nodes<'a, L>(&'a self,
                             iter: Nodes<'a, Self::HashOutput, L>)
                             -> Self::HashOutput
        {
            let mut digest = Sha256::default();
            for node in iter {
                match *node {
                    Node::Leaf(ref ln) => {
                        digest.process(ln.hash_bytes());
                    }
                    Node::Hash(ref hn) => {
                        digest.process(hn.hash_bytes());
                    }
                }
            }
            digest.fixed_result()
        }
    }

    #[test]
    fn byte_digest_with_custom_node_hasher() {
        const CHUNK_SIZE: usize = 15;
        let hasher = ByteDigestHasher::<Sha256, _>::with_node_hasher(
                        CustomNodeHasher);
        let mut builder = Builder::from_hasher_leaf_data(hasher, leaf::NoData);
        builder.extend_leaves(TEST_DATA.chunks(CHUNK_SIZE));
        let tree = builder.complete().unwrap();
        let mut root_digest = Sha256::new();
        TEST_DATA.chunks(CHUNK_SIZE).map(|chunk| {
            Sha256::digest(chunk)
        }).for_each(|leaf_hash| {
            root_digest.process(leaf_hash.as_slice());
        });
        assert_eq!(*tree.root().hash(), root_digest.fixed_result());
    }

    #[test]
    fn endian_digest_with_custom_node_hasher() {
        let test_input = [42u16, 43u16];
        let hasher = DigestHasher::<BigEndian<Sha256>, _>::with_node_hasher(
                        CustomNodeHasher);
        let mut builder = Builder::from_hasher_leaf_data(hasher, leaf::NoData);
        builder.extend_leaves(test_input.iter());
        let tree = builder.complete().unwrap();
        let mut root_digest = Sha256::new();
        test_input.iter().map(|v| {
            Sha256::digest(&[0, *v as u8])
        }).for_each(|leaf_hash| {
            root_digest.process(leaf_hash.as_slice());
        });
        assert_eq!(*tree.root().hash(), root_digest.fixed_result());
    }
}
