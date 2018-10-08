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
//! across a pool of work-stealing threads, in order to fully utilize
//! capabilities for parallelism found in modern multi-core CPUs.
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

use super::plumbing::FromNodes;
use hash::Hasher;
use leaf;
use tree;
use tree::{BuildResult, EmptyTree, MerkleTree};

/// A parallel Merkle tree builder utilizing a work-stealing thread pool.
///
/// This is a data-parallel workalike of the sequential `tree::Builder`.
/// Where the sequential `Builder` works with tree instances and sequential
/// iterators, this API uses thread-safe closures and Rayon's parallel
/// iterators to obtain children for new tree's root in a potentially
/// parallelized way.
#[derive(Clone, Debug, Default)]
pub struct Builder<D, L>
where
    D: Hasher<L::Input>,
    L: leaf::ExtractData,
{
    inner: tree::Builder<D, L>,
}

impl<D, In> Builder<D, leaf::NoData<In>>
where
    D: Hasher<In> + Default,
{
    /// Constructs a `Builder` with a default instance of the hash extractor,
    /// and `NoData` in place of the leaf data extractor.
    /// The constructed tree will contain only hash values in its leaf nodes.
    pub fn new() -> Self {
        Builder {
            inner: tree::Builder::new(),
        }
    }
}

impl<D, L> Builder<D, L>
where
    D: Hasher<L::Input>,
    L: leaf::ExtractData,
{
    /// Constructs a `Builder` from the given instances of the hasher
    /// and the leaf data extractor.
    pub fn from_hasher_leaf_data(hasher: D, leaf_data_extractor: L) -> Self {
        let inner =
            tree::Builder::from_hasher_leaf_data(hasher, leaf_data_extractor);
        Builder { inner }
    }

    /// Transforms input data into a tree consisting of a single leaf node.
    ///
    /// This method is not parallelized internally, but it is provided to
    /// start the building from leaves up; _calls_ to this method
    /// are normally distributed across tasks for the work-stealing
    /// thread pool.
    /// The hash value for the root leaf node is calculated by the hash
    /// extractor, and the leaf data value is obtained by the leaf data
    /// extractor used by this `Builder`.
    pub fn make_leaf(
        &self,
        input: L::Input,
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        self.inner.make_leaf(input)
    }

    /// Constructs a Merkle tree with the passed subtree as the single
    /// child of the root node, usually considered to be the leftmost child
    /// in an _n_-ary tree.
    ///
    /// This method can be used to deal with the unpaired
    /// rightmost node in a level of the tree under construction, when
    /// equal path height to all leaf nodes needs to be maintained.
    /// The `hash_children()` method of the hash extractor receives the child
    /// as the single element in the `Children` iterator.
    pub fn chain_lone_child(
        &self,
        child: MerkleTree<D::HashOutput, L::LeafData>,
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        self.inner.chain_lone_child(child)
    }
}

impl<D, L> Builder<D, L>
where
    D: Hasher<L::Input> + Clone + Send,
    L: leaf::ExtractData + Clone + Send,
    D::HashOutput: Send,
    L::Input: Send,
    L::LeafData: Send,
{
    /// Constructs a left-filled, same-leaf-depth binary Merkle tree from a
    /// parallel iterator over input values with a known length, or anything
    /// that can be converted into such an iterator, e.g. any `Vec` with
    /// `Send` members.
    /// The nodes' hashes are calculated by the hash extractor, and
    /// the leaf data values are extracted from input data with the
    /// leaf data exractor.
    ///
    /// The constructed tree has the following properties: the left subtree
    /// of the root node is a perfect binary tree, all leaf nodes are on the
    /// same level (i.e. have the same depth), and nodes on every tree level
    /// are packed to the left. This means that the rightmost internal node
    /// on any level under root may have only a single child that is considered
    /// to be the left child. This layout is a subgraph to the
    /// [complete binary tree][nist-complete] with the same leaf nodes at the
    /// deepest level; higher-level leaf nodes of the complete tree do not
    /// carry a practical meaning in this representation of the Merkle tree
    /// and are not present in the data model, nor any internal nodes that
    /// would have only such leaf nodes as descendants.
    ///
    /// [nist-complete]: https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html
    ///
    /// The work to construct subtrees gets recursively subdivided and
    /// distributed across a thread pool managed by Rayon. Construction
    /// of the leaf nodes is also parallelized across the input sequence.
    /// The implementation temporarily allocates an amount of memory that
    /// can be approximated as **s ⋅ n ⋅ (1 + (⌈log₂(n)⌉ - 1) / 2)**, where
    /// **n** is the length of the input sequence, and **s** is the size of
    /// a tree node which is somewhat larger than the sum of sizes of a
    /// hash value and a leaf data value. Part of the allocated memory gets
    /// recycled in the created tree, which takes approximately **s ⋅ n ⋅ 2**.
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
    ///
    pub fn complete_tree_from<I>(
        &self,
        iterable: I,
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where
        I: IntoParallelIterator<Item = L::Input>,
        I::Iter: IndexedParallelIterator,
    {
        self.complete_tree_from_iter(iterable.into_par_iter())
    }

    fn complete_tree_from_iter<I>(
        &self,
        mut iter: I,
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where
        I: IndexedParallelIterator<Item = L::Input>,
    {
        if iter.len() == 0 {
            return Err(EmptyTree);
        }
        let leaves: Vec<_> = iter
            .map_with(self.clone(), |master, input| master.make_leaf(input))
            .collect();
        assert!(
            leaves.len() != 0,
            "the parallel iterator that reported nonzero length \
             has come up empty"
        );
        let perfect_len = leaves.len().checked_next_power_of_two().unwrap();
        Ok(self.reduce_complete(leaves, perfect_len))
    }

    fn reduce_complete(
        &self,
        mut level_nodes: Vec<MerkleTree<D::HashOutput, L::LeafData>>,
        perfect_len: usize,
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let len = level_nodes.len();
        debug_assert!(len != 0);
        let left_len = perfect_len / 2;
        if len <= left_len {
            // We're going to have no right subtree on this node.
            // And it's still an internal node because this is never true
            // when perfect_len == 1.
            let subtree = self.reduce_complete(level_nodes, left_len);
            self.chain_lone_child(subtree)
        } else if len == 1 {
            level_nodes.pop().unwrap()
        } else {
            let right = level_nodes.split_off(left_len);
            let left = level_nodes;
            let left_builder = self.clone();
            let right_builder = self.clone();
            self.join(
                move || left_builder.reduce_complete(left, left_len),
                move || right_builder.reduce_complete(right, left_len),
            )
        }
    }

    /// Constructs a [full][nist-full] binary Merkle tree from a parallel
    /// iterator with a known length, or anything that can be converted
    /// into such an iterator, e.g. any `Vec` with `Send` members.
    /// The nodes' hashes are calculated by the hash extractor, and
    /// the leaf data values are extracted from input data with the
    /// leaf data exractor.
    ///
    /// The constructed tree has the following properties: the left subtree
    /// of any internal node, including root, is a perfect binary tree,
    /// nodes on every tree level are packed to the left, but the tree is
    /// not necessarily balanced, i.e. the leaf nodes are not generally all
    /// on the same level.
    ///
    /// [nist-full]: https://xlinux.nist.gov/dads/HTML/fullBinaryTree.html
    ///
    /// The work to construct subtrees gets recursively subdivided and
    /// distributed across a thread pool managed by Rayon. Construction
    /// of the leaf nodes is also parallelized across the input sequence.
    /// The implementation temporarily allocates an amount of memory that
    /// can be approximated as **s ⋅ n ⋅ (1 + (⌈log₂(n)⌉ - 1) / 2)**, where
    /// **n** is the length of the input sequence, and **s** is the size of
    /// a tree node which is somewhat larger than the sum of sizes of a
    /// hash value and a leaf data value. Part of the allocated memory gets
    /// recycled in the created tree, which takes approximately **s ⋅ n ⋅ 2**.
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
    ///
    pub fn full_tree_from<I>(
        &self,
        iterable: I,
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where
        I: IntoParallelIterator<Item = L::Input>,
        I::Iter: IndexedParallelIterator,
    {
        self.full_tree_from_iter(iterable.into_par_iter())
    }

    fn full_tree_from_iter<I>(
        &self,
        mut iter: I,
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where
        I: IndexedParallelIterator<Item = L::Input>,
    {
        if iter.len() == 0 {
            return Err(EmptyTree);
        }
        let leaves: Vec<_> = iter
            .map_with(self.clone(), |master, input| master.make_leaf(input))
            .collect();
        assert!(
            leaves.len() != 0,
            "the parallel iterator that reported nonzero length \
             has come up empty"
        );
        Ok(self.reduce_full(leaves))
    }

    fn reduce_full(
        &self,
        mut level_nodes: Vec<MerkleTree<D::HashOutput, L::LeafData>>,
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let len = level_nodes.len();
        debug_assert!(len != 0);
        let left_len = (len.saturating_add(1) / 2).next_power_of_two();
        if len == 1 {
            level_nodes.pop().unwrap()
        } else {
            let right = level_nodes.split_off(left_len);
            let left = level_nodes;
            let left_builder = self.clone();
            let right_builder = self.clone();
            self.join(
                move || left_builder.reduce_full(left),
                move || right_builder.reduce_full(right),
            )
        }
    }
}

impl<D, L> Builder<D, L>
where
    D: Hasher<L::Input>,
    L: leaf::ExtractData,
    D::HashOutput: Send,
    L::LeafData: Send,
{
    /// Joins the Merkle trees produced by two closures, potentially ran in
    /// parallel by `rayon::join()`, to produce a tree with a new root node,
    /// with the trees returned by the closures converted to the new root's
    /// child nodes.
    ///
    /// The `hash_children()` method of the hash extractor is used to obtain
    /// the root hash.
    pub fn join<LF, RF>(
        &self,
        left: LF,
        right: RF,
    ) -> MerkleTree<D::HashOutput, L::LeafData>
    where
        LF: FnOnce() -> MerkleTree<D::HashOutput, L::LeafData> + Send,
        RF: FnOnce() -> MerkleTree<D::HashOutput, L::LeafData> + Send,
    {
        let (left_tree, right_tree) = rayon::join(left, right);
        self.inner.join(left_tree, right_tree)
    }

    /// Collects Merkle trees produced by a potentially parallelized
    /// iterative computation as child nodes for the root of the
    /// returned tree.
    ///
    /// The `hash_children()` method of the hash extractor is used to obtain
    /// the root hash.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when the iteration turns out empty.
    ///
    pub fn collect_children_from<I>(
        &self,
        iterable: I,
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where
        I: IntoParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>>,
    {
        self.collect_children_from_iter(iterable.into_par_iter())
    }

    fn collect_children_from_iter<I>(
        &self,
        iter: I,
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where
        I: ParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>>,
    {
        let nodes: Vec<_> = iter.map(|tree| tree.root).collect();
        self.inner.tree_from_nodes(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::Builder;

    use super::rayon::iter;
    use super::rayon::prelude::*;

    use super::super::testmocks::MockHasher;
    use leaf;
    use tree::Node;

    const TEST_DATA: &'static [u8] =
        b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn complete_tree_from_empty() {
        let builder = Builder::<MockHasher, _>::new();
        builder
            .complete_tree_from(iter::empty::<[u8; 1]>())
            .unwrap_err();
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
                                    #(> the lazy dog)";
            assert_eq!(hn.hash_bytes(), expected);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn complete_tree_is_subgraph_of_its_math_definition() {
        let builder = Builder::<MockHasher, _>::new();
        let data: Vec<_> = TEST_DATA.chunks(10).collect();
        let tree = builder.complete_tree_from(data).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] =
                b"#(#(>The quick >brown fox )#(>jumps over> the lazy ))\
                      #(#(>dog))";
            assert_eq!(hn.hash_bytes(), expected);
            assert_eq!(hn.children.len(), 2);
            if let Node::Hash(ref hn) = *hn.child_at(1) {
                assert_eq!(hn.hash_bytes(), b"#(>dog)");
                assert_eq!(hn.children.len(), 1);
                if let Node::Hash(ref hn) = *hn.child_at(0) {
                    assert_eq!(hn.hash_bytes(), b">dog");
                    assert_eq!(hn.children.len(), 1);
                    if let Node::Leaf(ref ln) = *hn.child_at(0) {
                        assert_eq!(ln.hash_bytes(), b"dog");
                    } else {
                        unreachable!()
                    }
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn cant_make_full_from_empty() {
        use super::rayon::iter::empty;
        let builder = Builder::<MockHasher, _>::new();
        let err = builder.full_tree_from(empty::<[u8; 1]>()).unwrap_err();
        println!("error {:?}: {}", err, err);
    }

    #[test]
    fn full_tree_is_full() {
        let builder = Builder::<MockHasher, _>::new();
        let data: Vec<_> = TEST_DATA.chunks(7).collect();
        let tree = builder.full_tree_from(data).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(#(>The qui>ck brow)#(>n fox j>umps ov))\
                      #(#(>er the >lazy do)>g)";
            assert_eq!(hn.hash_bytes(), expected);
        } else {
            unreachable!()
        }
    }

    const TEST_STRS: [&'static str; 3] =
        ["Panda eats,", "shoots,", "and leaves."];

    #[test]
    fn collect_nodes_for_arbitrary_arity_tree() {
        let builder = Builder::<MockHasher, leaf::NoData<&'static str>>::new();
        let iter = TEST_STRS
            .into_par_iter()
            .map_with(builder.clone(), |builder, input| {
                builder.make_leaf(input)
            });
        let tree = builder.collect_children_from(iter).unwrap();
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
