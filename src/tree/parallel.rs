// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Building Merkle trees in parallel.
//!
//! The `Builder` facility provided by this module uses [Rayon][rayon],
//! a data parallelism framework, to distribute building of a Merkle tree
//! across a pool of threads, in order to fully utilize capabilities for
//! parallelism found in modern multi-core CPUs.
//!
//! [rayon]: https://crates.io/crates/rayon
//!
//! This module is only available if the crate has been compiled with
//! the `parallel` feature, which is enabled by default.
//!
//! # Examples
//!
//! ```
//! # extern crate mrkl;
//! # extern crate rayon;
//! # #[cfg(feature = "digest")]
//! # extern crate sha2;
//! #
//! use rayon::prelude::*;
//! use mrkl::leaf;
//! use mrkl::tree::parallel::Builder;
//! # #[cfg(feature = "digest")]
//! use mrkl::digest::ByteDigestHasher;
//! # #[cfg(feature = "digest")]
//! use sha2::Sha256;
//!
//! # #[cfg(feature = "digest")]
//! # fn main() {
//! type Hasher = ByteDigestHasher<Sha256>;
//!
//! let builder = Builder::from_hasher_leaf_data(
//!                 Hasher::new(),
//!                 leaf::extract_with(|s: &[u8]| { s[0] }));
//! let data: &'static [u8] = b"The quick brown fox \
//!                             jumps over the lazy dog";
//! let input: Vec<_> = data.chunks(10).collect();
//! let iter = input.into_par_iter();
//! let tree = builder.complete_tree_from(iter).unwrap();
//! #     let _ = tree;
//! # }
//! # #[cfg(not(feature = "digest"))]
//! # fn main() { }
//! ```

pub extern crate rayon;

use self::rayon::prelude::*;
use self::rayon::iter::Either;

use hash::Hasher;
use leaf;
use tree;
use tree::{MerkleTree, EmptyTree};
use super::plumbing::BuilderNodes;


/// A parallel Merkle tree builder utilizing a work-stealing thread pool.
///
/// This is a data-parallel workalike of the sequential `tree::Builder`.
/// One difference with the sequential `Builder` is lack of any incremental
/// `&mut self` methods to populate nodes: all methods but the most trivial
/// `into_leaf()` require the child nodes to be constructed in a potentially
/// parallelized way. The `self` instance is consumed together with
/// the results of those computations to produce the final Merkle tree,
/// which, if happening in a Rayon-controlled job,
/// can then be passed on to build another level.
#[derive(Clone, Debug, Default)]
pub struct Builder<D, L> {
    hasher: D,
    leaf_data_extractor: L
}

impl<D, In> Builder<D, leaf::NoData<In>>
where D: Hasher<In> + Default
{
    /// Constructs a `Builder` with a default instance of the hash extractor,
    /// and `NoData` in place of the leaf data extractor.
    /// The constructed tree will contain only hash values in its leaf nodes.
    pub fn new() -> Self {
        Builder {
            hasher: D::default(),
            leaf_data_extractor: leaf::no_data()
        }
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData
{
    /// Constructs a `Builder` from the given instances of the hasher
    /// and the leaf data extractor.
    pub fn from_hasher_leaf_data(hasher: D, leaf_data_extractor: L) -> Self {
        Builder { hasher, leaf_data_extractor }
    }

    fn into_serial_builder(self) -> tree::Builder<D, L> {
        tree::Builder::from_hasher_leaf_data(
            self.hasher,
            self.leaf_data_extractor)
    }

    fn into_n_ary_serial_builder(self, n: usize) -> tree::Builder<D, L> {
        tree::Builder::n_ary_from_hasher_leaf_data(
            n,
            self.hasher,
            self.leaf_data_extractor)
    }

    /// Consumes this instance and an input value to create a Merkle tree
    /// consisting of a single leaf node with the hash of the input.
    /// This method is not parallelized internally, but it is provided to
    /// start the building from leaves up; _calls_ to this method
    /// are normally distributed across tasks for the work-stealing
    /// thread pool.
    pub fn into_leaf(
        self,
        input: L::Input
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let mut builder = self.into_n_ary_serial_builder(1);
        builder.push_leaf(input);
        builder.finish().unwrap()
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input> + Clone + Send,
      L: leaf::ExtractData + Clone + Send,
      D::HashOutput: Send,
      L::Input: Send,
      L::LeafData: Send
{
    /// Constructs a [complete binary][nist] Merkle tree from a parallel
    /// iterator with a known length, or anything that can be converted
    /// into such an iterator, e.g. any `Vec` with `Send` members.
    /// The nodes' hashes are calculated by the hash extractor, and
    /// the leaf data values are extracted from input data with the
    /// leaf data exractor.
    ///
    /// [nist]: https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html
    ///
    /// The work to construct subtrees gets recursively subdivided and
    /// distributed across a thread pool managed by Rayon.
    ///
    /// This method is only available when the hash extractor and the leaf
    /// data extractor implement `Clone`. To use a closure expression for
    /// the leaf data extractor, ensure that it does not capture any
    /// variables from the closure environment by passing it through the
    /// helper function `leaf::extract_with()`.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when the input is empty.
    pub fn complete_tree_from<I>(
        self,
        iterable: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IntoParallelIterator<Item = L::Input>,
          I::Iter: IndexedParallelIterator,
    {
        self.complete_tree_from_iter(iterable.into_par_iter())
    }

    fn complete_tree_from_iter<I>(
        self,
        mut iter: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IndexedParallelIterator<Item = L::Input> {
        if iter.len() == 0 {
            return Err(EmptyTree);
        }
        let leaves =
            iter.map_with(self.clone(), |master, input| {
                master.clone().into_leaf(input)
            });
        Ok(self.reduce(leaves))
    }

    fn reduce<I>(
        self,
        mut iter: I
    ) -> MerkleTree<D::HashOutput, L::LeafData>
    where I: IndexedParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>> {
        let len = iter.len();
        debug_assert!(len != 0);
        if len == 1 {
            return iter.reduce_with(|_, _| {
                    unreachable!("more than one item left in a parallel \
                                  iterator that reported length 1")
                })
                .expect("a parallel iterator that reported length 1 \
                         has come up empty");
        }
        let left_len = (len.saturating_add(1) / 2).next_power_of_two();
        let (left, right) = iter.enumerate()
            .partition_map::<Vec<_>, Vec<_>, _, _, _>(|(i, node)| {
                if i < left_len {
                    Either::Left(node)
                } else {
                    Either::Right(node)
                }
            });
        // The left and right parts cannot be empty for len >= 2
        self.reduce_and_join_parts(left, right)
    }

    fn reduce_and_join_parts(
        self,
        left:  Vec<MerkleTree<D::HashOutput, L::LeafData>>,
        right: Vec<MerkleTree<D::HashOutput, L::LeafData>>
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let left_builder = self.clone();
        let right_builder = self.clone();
        self.join(
            move || { left_builder.reduce(left.into_par_iter()) },
            move || { right_builder.reduce(right.into_par_iter()) }
        )
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
      D::HashOutput: Send,
      L::LeafData: Send
{
    /// Joins the Merkle trees produced by two closures, potentially ran in
    /// parallel by `rayon::join()`, to produce a tree with a new root node,
    /// with the trees returned by the closures converted to the new root's
    /// child nodes.
    pub fn join<LF, RF>(
        self,
        left: LF,
        right: RF
    ) -> MerkleTree<D::HashOutput, L::LeafData>
    where LF: FnOnce() -> MerkleTree<D::HashOutput, L::LeafData> + Send,
          RF: FnOnce() -> MerkleTree<D::HashOutput, L::LeafData> + Send
    {
        let (left_tree, right_tree) = rayon::join(left, right);
        let mut builder = self.into_serial_builder();
        builder.push_tree(left_tree);
        builder.push_tree(right_tree);
        builder.finish().unwrap()
    }

    /// Collects Merkle trees produced by a potentially parallelized
    /// iterative computation as nodes for constructing the top
    /// of the returned tree. If the iterator returns one tree (which can
    /// be a single-leaf tree), it is returned as the result.
    /// Multiple trees are made immediate children of the new root node of the
    /// returned tree.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when the input is empty.
    ///
    pub fn collect_nodes_from<I>(
        self,
        iterable: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IntoParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>>
    {
        self.collect_nodes_from_iter(iterable.into_par_iter())
    }

    fn collect_nodes_from_iter<I>(
        self,
        iter: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: ParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>>
    {
        // TODO: once specialization is stabilized, utilize
        // .collect_into() with indexed iterators.
        let mut nodes: Vec<_> =
            iter.map(|tree| {
                tree.root
            })
            .collect();
        let mut builder = self.into_n_ary_serial_builder(nodes.len());
        builder.append_nodes(&mut nodes);
        builder.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Builder;

    use super::rayon::prelude::*;
    use super::rayon::iter;

    use leaf;
    use tree::Node;
    use super::super::testmocks::MockHasher;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn complete_tree_from_empty() {
        let builder = Builder::<MockHasher, _>::new();
        builder.complete_tree_from(iter::empty::<[u8; 1]>()).unwrap_err();
    }

    #[test]
    fn complete_leaf() {
        let builder = Builder::<MockHasher, _>::new();
        let iter = iter::repeatn(TEST_DATA, 1);
        let tree = builder.complete_tree_from(iter).unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), TEST_DATA);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn complete_tree() {
        let builder = Builder::<MockHasher, _>::new();
        let data: Vec<_> = TEST_DATA.chunks(15).collect();
        let tree = builder.complete_tree_from(data).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    > the lazy dog";
            assert_eq!(hn.hash_bytes(), expected);
        } else {
            unreachable!()
        }
    }

    const TEST_STRS: [&'static str; 3] = [
        "Panda eats,",
        "shoots,",
        "and leaves."];

    #[test]
    fn collect_nodes_for_arbitrary_arity_tree() {
        let iter =
            TEST_STRS.into_par_iter().map(|input| {
                let builder = Builder::<MockHasher, _>::new();
                builder.into_leaf(input)
            });
        let builder = Builder::<MockHasher, leaf::NoData<&'static str>>::new();
        let tree = builder.collect_nodes_from(iter).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b">Panda eats,>shoots,>and leaves.");
            let mut peek_iter = hn.children().peekable();
            assert!(peek_iter.peek().is_some());
            for (i, child) in peek_iter.enumerate() {
                if let Node::Leaf(ref ln) = *child {
                    assert_eq!(ln.hash_bytes(), TEST_STRS[i].as_bytes());
                } else {
                    unreachable!()
                }
            }
        } else {
            unreachable!()
        }
    }
}
