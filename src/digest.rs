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
//! This implementation follows the Merkle tree hash definition given in
//! [IETF RFC 6962][rfc6962] and provides protection against potential
//! second-preimage attacks: a 0 byte is prepended to the hash input of each
//! leaf node, and a 1 byte is prepended to the concatenation of children's
//! hash values when calculating the hash of an internal node. Note
//! that while RFC 6962 only uses unbalanced full binary trees, the
//! implementation of the Merkle tree provided by this crate permits
//! single-child nodes to achieve uniform leaf depth. Such nodes are not
//! treated equivalent to their child by `DefaultNodeHasher`, to avoid
//! potentially surprising behavior when any trees that are single-node
//! chains over a subtree with the same hash value are considered equivalent.
//!
//! [rfc6962]: https://tools.ietf.org/html/rfc6962#section-2.1
//!
//! This module is only available if the crate has been compiled with
//! the `digest` feature, which is enabled by default.

use hash::{Hasher, NodeHasher};
use tree::Children;

pub extern crate digest_hash;

use self::digest_hash::{Hash, Endian, EndianInput};
use self::digest_hash::digest::{Input, FixedOutput};
use self::digest_hash::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;


/// The `NodeHasher` implementation used by default in this module.
///
/// This implementation concatenates the hash values of the child nodes,
/// prepended with a 1 byte, as input for the digest function.
pub struct DefaultNodeHasher<D> {
    phantom: PhantomData<D>
}

impl<D> DefaultNodeHasher<D> {
    /// Constructs an instance of the node hasher.
    pub fn new() -> Self { DefaultNodeHasher { phantom: PhantomData } }
}

impl<D> Default for DefaultNodeHasher<D> {
    fn default() -> Self { DefaultNodeHasher::new() }
}

impl<D> Clone for DefaultNodeHasher<D> {
    fn clone(&self) -> Self { DefaultNodeHasher::new() }
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

    fn hash_children<'a, L>(
        &'a self,
        mut iter: Children<'a, Self::HashOutput, L>
    ) -> Self::HashOutput {
        let mut digest = D::default();
        digest.process(&[1u8]);
        for node in iter {
            digest.process(node.hash_bytes());
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
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>
{
    node_hasher: Nh,
    phantom: PhantomData<D>
}

impl<D, Nh> DigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    /// Constructs a new instance of the hash extractor.
    pub fn new() -> Self {
        Self::with_node_hasher(Nh::default())
    }
}

impl<D, Nh> DigestHasher<D, Nh>
where D: FixedOutput,
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
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    fn default() -> Self { DigestHasher::new() }
}

impl<D, Nh> Clone for DigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
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
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
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
        digest.process(&[0u8]);
        input.hash(&mut digest);
        digest.fixed_result()
    }
}

impl<D, Nh> NodeHasher for DigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_children<'a, L>(
        &'a self,
        iter: Children<'a, Self::HashOutput, L>
    ) -> Self::HashOutput {
        self.node_hasher.hash_children(iter)
    }
}

/// Provides a cryptographic hash function implementation
/// for hashing Merkle trees with byte slice convertible input.
///
/// The hash function implementation is defined by the first type parameter.
/// In contrast to the more generic `DigestHasher`, the parameter type is
/// bound by bytestream-oriented `digest::Input`, so any cryptographic
/// digest function implementations conformant to this trait, plus
/// `digest::FixedOutput` and `Default`, are directly usable.
///
/// The implementation of a concatenated hash over node's children is
/// defined by the second type parameter. The default choice should be good
/// enough unless a specific way to derive concatenated hashes is required.
///
pub struct ByteDigestHasher<D, Nh = DefaultNodeHasher<D>>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    node_hasher: Nh,
    phantom: PhantomData<D>
}

impl<D, Nh> ByteDigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    /// Constructs a new instance of the hash extractor.
    pub fn new() -> Self {
        Self::with_node_hasher(Nh::default())
    }
}

impl<D, Nh> ByteDigestHasher<D, Nh>
where D: FixedOutput,
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
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
      Nh: Default
{
    fn default() -> Self { ByteDigestHasher::new() }
}

impl<D, Nh> Clone for ByteDigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
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
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
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
        digest.process(&[0u8]);
        digest.process(input.as_ref());
        digest.fixed_result()
    }
}

impl<D, Nh> NodeHasher for ByteDigestHasher<D, Nh>
where D: FixedOutput,
      Nh: NodeHasher<HashOutput = GenericArray<u8, D::OutputSize>>,
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_children<'a, L>(
        &'a self,
        iter: Children<'a, Self::HashOutput, L>
    ) -> Self::HashOutput {
        self.node_hasher.hash_children(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestHasher, ByteDigestHasher};
    use hash::{Hasher, NodeHasher};

    use tree::{Builder, Children};
    use leaf;

    extern crate sha2;

    use self::sha2::{Sha256, Digest};
    use super::digest_hash::BigEndian;
    use super::digest_hash::digest::{Input, FixedOutput};
    use super::digest_hash::digest::generic_array::GenericArray;
    use std::fmt;
    use std::fmt::Debug;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    fn leaf_digest(
        input: &[u8]
    ) -> GenericArray<u8, <Sha256 as FixedOutput>::OutputSize> {
        let mut digest = Sha256::new();
        digest.input(&[0u8]);
        digest.input(input);
        digest.result()
    }

    #[test]
    fn hash_byte_input() {
        let hasher = ByteDigestHasher::<Sha256>::new();
        let hash = hasher.hash_input(&TEST_DATA);
        assert_eq!(hash, leaf_digest(TEST_DATA));
    }

    #[test]
    fn hash_endian_input() {
        let hasher = DigestHasher::<BigEndian<Sha256>>::new();
        let hash = hasher.hash_input(&42u16);
        assert_eq!(hash, leaf_digest(&[0, 42][..]));
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

        fn hash_children<'a, L>(
            &'a self,
            iter: Children<'a, Self::HashOutput, L>
        ) -> Self::HashOutput {
            let mut digest = Sha256::default();
            for node in iter {
                digest.process(node.hash_bytes())
            }
            digest.fixed_result()
        }
    }

    #[test]
    fn byte_digest_with_custom_node_hasher() {
        const CHUNK_SIZE: usize = 15;
        let hasher = ByteDigestHasher::<Sha256, _>::with_node_hasher(
                        CustomNodeHasher);
        let builder = Builder::from_hasher_leaf_data(
                            hasher, leaf::no_data());
        let leaves =
            TEST_DATA.chunks(CHUNK_SIZE).map(|chunk| {
                builder.make_leaf(chunk)
            });
        let tree = builder.collect_children_from(leaves).unwrap();
        let mut root_digest = Sha256::new();
        TEST_DATA.chunks(CHUNK_SIZE).map(|chunk| {
            leaf_digest(chunk)
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
        let builder = Builder::from_hasher_leaf_data(
                        hasher, leaf::no_data());
        let leaves =
            test_input.iter().map(|input| {
                builder.make_leaf(input)
            });
        let tree = builder.collect_children_from(leaves).unwrap();
        let mut root_digest = Sha256::new();
        test_input.iter().map(|v| {
            leaf_digest(&[0, *v as u8])
        }).for_each(|leaf_hash| {
            root_digest.process(leaf_hash.as_slice());
        });
        assert_eq!(*tree.root().hash(), root_digest.fixed_result());
    }
}
