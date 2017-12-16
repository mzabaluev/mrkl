// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{MerkleTree, Node, HashNode, LeafNode, Nodes};
use super::plumbing;
use hash::Hasher;
use leaf;

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::iter::IntoIterator;


/// The facility for constructing of Merkle trees.
///
/// Mutable `Builder` instances can be used to construct a Merkle
/// tree. There are two ways of construction: incremental by using `Builder`
/// instances to construct and compose trees, or by using the convenience
/// method `complete_tree_from()` to create a complete binary tree out of a
/// sequence of input values.
///
/// When used in the incremental fashion, a `Builder` contains a
/// sequence of nodes which can be populated in order, to become one level
/// – either the single root node, or the children of the
/// newly calculated root node – of the Merkle tree created with
/// the method `finish()`. Either input data values or subtrees already
/// constructed from input data can be consumed to append leaf or hash
/// nodes, respectively.
///
/// `Builder` has two type parameters: the hash exractor implementing trait
/// `hash::Hasher`, and the leaf data extractor implementing trait
/// `leaf::ExtractData`. Depending on the construction method and the
/// context for type inference, one or both of these types can be inferred
/// at the construction site.
///
#[derive(Debug)]
pub struct Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
{
    hasher: D,
    leaf_data_extractor: L,
    nodes: Vec<Node<D::HashOutput, L::LeafData>>
}

impl<D, L> plumbing::BuilderNodes for Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
{
    type HashOutput = D::HashOutput;
    type LeafData = L::LeafData;

    fn append_nodes(
        &mut self,
        take_from: &mut Vec<Node<Self::HashOutput, Self::LeafData>>
    ) {
        self.nodes.append(take_from);
    }
}

impl<D, In> Builder<D, leaf::NoData<In>>
where D: Hasher<In>,
      D: Default
{
    /// Constructs a `Builder` with a default instance of the hash extractor,
    /// and `NoData` in place of the leaf data extractor.
    /// The constructed tree will contain only hash values in its leaf nodes.
    ///
    /// # Examples
    ///
    /// Unless otherwise constrained, the type of the `Hasher` implementation
    /// has to be explicitly specified when using this method:
    ///
    /// ```
    /// # extern crate mrkl;
    /// # #[cfg(feature = "digest")]
    /// # extern crate sha2;
    /// #
    /// use mrkl::tree::Builder;
    /// # #[cfg(feature = "digest")]
    /// use mrkl::digest::ByteDigestHasher;
    /// # #[cfg(feature = "digest")]
    /// use sha2::Sha256;
    ///
    /// # #[cfg(feature = "digest")]
    /// # fn main() {
    /// type Hasher = ByteDigestHasher<Sha256>;
    /// let mut builder = Builder::<Hasher, _>::new();
    /// let data: &[u8] = b"the quick brown fox jumped over the lazy dog";
    /// builder.push_leaf(data);
    /// # }
    /// # #[cfg(not(feature = "digest"))]
    /// # fn main() { }
    /// ```
    pub fn new() -> Self {
        Self::from_hasher_leaf_data(D::default(), leaf::no_data())
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
{
    /// Constructs a `Builder` from the given instances of the hasher
    /// and the leaf data extractor.
    pub fn from_hasher_leaf_data(hasher: D, leaf_data_extractor: L) -> Self {
        Self::n_ary_from_hasher_leaf_data(2, hasher, leaf_data_extractor)
    }

    /// Constructs a `Builder` with capacity reserved for the given number
    /// of child nodes,
    /// from the given instances of the hasher and the leaf data extractor.
    pub fn n_ary_from_hasher_leaf_data(
        n: usize,
        hasher: D,
        leaf_data_extractor: L
    ) -> Self {
        Builder {
            hasher,
            leaf_data_extractor,
            nodes: Vec::with_capacity(n)
        }
    }

    /// Appends a leaf node to the sequence of nodes.
    ///
    /// The hash value for the leaf node is calculated by the hash extractor,
    /// and the leaf data value is obtained by the leaf data extractor
    /// used by this `Builder`.
    pub fn push_leaf(&mut self, input: L::Input) {
        let hash = self.hasher.hash_input(&input);
        let data = self.leaf_data_extractor.extract_data(input);
        self.nodes.push(Node::Leaf(LeafNode { hash, data }));
    }

    /// Appends a Merkle subtree as a hash node to the sequence of nodes.
    pub fn push_tree(&mut self,
                     tree: MerkleTree<D::HashOutput, L::LeafData>)
    {
        self.nodes.push(tree.root);
    }

    /// Appends leaf nodes with input data retrieved from an iterable.
    pub fn extend_leaves<I>(&mut self, iter: I)
    where I: IntoIterator<Item = L::Input> {
        self.extend_leaves_impl(iter.into_iter())
    }

    fn extend_leaves_impl<I>(&mut self, iter: I)
    where I: Iterator<Item = L::Input> {
        let (size_low, _) = iter.size_hint();
        self.nodes.reserve(size_low);
        for input in iter {
            self.push_leaf(input);
        }
    }

    fn nodes<'a>(&'a self) -> Nodes<'a, D::HashOutput, L::LeafData> {
        Nodes(self.nodes.iter())
    }

    /// Constructs the final `MerkleTree` from the populated `Builder`
    /// instance.
    ///
    /// The tree constructed will depend on the number of nodes this
    /// instance has been populated with. From a single leaf node, a
    /// single-level tree is constructed containing the leaf node as
    /// the root. If a single tree has been added as a hash node,
    /// an equivalent tree is returned.
    /// From multiple nodes, a tree is constructed by creating a
    /// root hash node as the parent of the sequence of the populated nodes,
    /// hashed with the `hash_nodes()` method of the hash extractor to
    /// obtain the root hash.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when called on an unpopulated
    /// `Builder`.
    ///
    pub fn finish(
        mut self
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    {
        match self.nodes.len() {
            0 => Err(EmptyTree),
            1 => {
                let root = self.nodes.pop().unwrap();
                Ok(MerkleTree { root })
            }
            _ => {
                let hash = self.hasher.hash_nodes(self.nodes());
                let node = HashNode { hash, children: self.nodes.into() };
                Ok(MerkleTree { root: Node::Hash(node) })
            }
        }
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input> + Clone,
      L: leaf::ExtractData + Clone,
{
    /// Constructs a [complete binary][nist] Merkle tree from a sequence of
    /// input values with a known length. The nodes' hashes are calculated
    /// by the hash extractor, and the leaf data values are extracted from
    /// input data with the leaf data exractor.
    ///
    /// [nist]: https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html
    ///
    /// This method is only available when the hash extractor and the leaf
    /// data extractor implement `Clone`. To use a closure expression for
    /// the leaf data extractor, ensure that it does not capture any
    /// variables from the closure environment by passing it through the
    /// helper function `leaf::extract_with()`.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when the input sequence is empty.
    ///
    /// # Panics
    ///
    /// Panics when called on a `Builder` that has been populated with any
    /// nodes.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate mrkl;
    /// # #[cfg(feature = "digest")]
    /// # extern crate sha2;
    /// #
    /// use mrkl::leaf;
    /// use mrkl::tree::Builder;
    /// # #[cfg(feature = "digest")]
    /// use mrkl::digest::ByteDigestHasher;
    /// # #[cfg(feature = "digest")]
    /// use sha2::Sha256;
    ///
    /// # #[cfg(feature = "digest")]
    /// # fn main() {
    /// type Hasher = ByteDigestHasher<Sha256>;
    ///
    /// let builder = Builder::from_hasher_leaf_data(
    ///                 Hasher::new(),
    ///                 leaf::extract_with(|s: &[u8]| { s[0] }));
    /// let input: &'static [u8] = b"The quick brown fox \
    ///                              jumps over the lazy dog";
    /// let tree = builder.complete_tree_from(input.chunks(10)).unwrap();
    /// #     let _ = tree;
    /// # }
    /// # #[cfg(not(feature = "digest"))]
    /// # fn main() { }
    /// ```
    pub fn complete_tree_from<I>(
        mut self,
        iterable: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IntoIterator<Item = L::Input>,
          I::IntoIter: ExactSizeIterator
    {
        assert!(self.nodes.is_empty(),
                "complete_tree_from() called on a populated Builder");
        let mut iter = iterable.into_iter();
        let len = iter.len();
        if len == 0 {
            return Err(EmptyTree);
        }
        self.populate_complete_from_iter(&mut iter, len);
        debug_assert!(iter.next().is_none(),
                      "iterator has not been exhausted after reported length");
        self.finish()
    }

    fn populate_complete_from_iter<I>(&mut self, iter: &mut I, len: usize)
    where I: Iterator<Item = L::Input>
    {
        debug_assert!(len != 0);
        if len == 1 {
            let item = iter.next()
                       .expect("iterator returned None \
                                before its reported length was reached");
            self.push_leaf(item);
        } else {
            let left_len = (len.saturating_add(1) / 2).next_power_of_two();
            {
                let mut builder = Builder::from_hasher_leaf_data(
                            self.hasher.clone(),
                            self.leaf_data_extractor.clone());
                builder.populate_complete_from_iter(iter, left_len);
                let left_tree = builder.finish().unwrap();
                self.push_tree(left_tree);
            }
            // This never overflows or comes to 0 because
            // left_len < len for len >= 2
            let right_len = len - left_len;
            {
                let mut builder = Builder::from_hasher_leaf_data(
                            self.hasher.clone(),
                            self.leaf_data_extractor.clone());
                builder.populate_complete_from_iter(iter, right_len);
                let right_tree = builder.finish().unwrap();
                self.push_tree(right_tree);
            }
        }
    }
}

/// The error value returned when a tree was attempted to be constructed
/// from empty input.
///
/// An empty tree is not considered to be a valid Merkle tree
/// by the API of this crate.
#[derive(Debug)]
pub struct EmptyTree;

impl Display for EmptyTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("attempted to create an empty Merkle tree")
    }
}

impl Error for EmptyTree {
    fn description(&self) -> &str { "empty Merkle tree" }
}

#[cfg(test)]
mod tests {
    use super::Builder;

    use leaf;
    use tree::{MerkleTree, EmptyTree, Node};

    use super::super::testmocks::MockHasher;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn empty_tree() {
        use std::error::Error;

        fn daft() -> Result<MerkleTree<Vec<u8>, ()>, EmptyTree> {
            let builder = Builder::<MockHasher, leaf::NoData<String>>::new();
            let _ = builder.finish()?;
            unreachable!()
        }

        let err = daft().unwrap_err();
        assert_eq!(err.description(), "empty Merkle tree");
        println!("{}", err);
        println!("{:?}", err);
    }

    #[test]
    fn builder_no_data_fixed_size_array() {
        let mut builder = Builder::<MockHasher, _>::new();
        builder.push_leaf([1u8, 2u8, 3u8, 4u8]);
        let tree = builder.finish().unwrap();
        assert_eq!(tree.root().hash_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn builder_with_owned_leaves() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::owned());
        builder.push_leaf([1u8, 2u8, 3u8, 4u8]);
        let tree = builder.finish().unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), &[1, 2, 3, 4]);
            assert_eq!(ln.data(), &[1, 2, 3, 4]);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn builder_leaf_extract_with_plain_fn() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: [u8; 4]| { s.len() }));
        builder.push_leaf([0u8, 1u8, 2u8, 3u8]);
        let tree = builder.finish().unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), &[0, 1, 2, 3]);
            assert_eq!(*ln.data(), 4);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn builder_leaf_extract_with_closure() {
        let hasher = MockHasher::default();
        let off = 42;
        let mut builder = Builder::from_hasher_leaf_data(
                hasher,
                leaf::ExtractFn::with(|s: [u8; 4]| { s.len() + off }));
        builder.push_leaf([0u8, 1u8, 2u8, 3u8]);
        let tree = builder.finish().unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), &[0, 1, 2, 3]);
            assert_eq!(*ln.data(), 46);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn builder_over_nonstatic_slice() {
        let v = Vec::from(TEST_DATA);
        let mut builder = Builder::<MockHasher, leaf::NoData<&[u8]>>::new();
        builder.push_leaf(&v[..]);
        let tree = builder.finish().unwrap();
        assert_eq!(tree.root().hash_bytes(), TEST_DATA);
    }

    #[test]
    fn two_leaves_make_a_tree() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: &str| { s.to_string() }));
        builder.push_leaf("eats shoots");
        builder.push_leaf("and leaves");
        let tree = builder.finish().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b">eats shoots>and leaves");
            let child = hn.child_at(0);
            if let Node::Leaf(ref ln) = *child {
                assert_eq!(ln.hash_bytes(), b"eats shoots");
                assert_eq!(ln.data(), "eats shoots");
            } else {
                unreachable!()
            }
            let child = hn.child_at(1);
            if let Node::Leaf(ref ln) = *child {
                assert_eq!(ln.hash_bytes(), b"and leaves");
                assert_eq!(ln.data(), "and leaves");
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    #[should_panic]
    fn child_out_of_range() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::no_data());
        builder.push_leaf("eats shoots");
        builder.push_leaf("and leaves");
        let tree = builder.finish().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let _child = hn.child_at(2);
        } else {
            unreachable!()
        }
    }

    const TEST_STRS: [&'static str; 3] = [
        "Panda eats,",
        "shoots,",
        "and leaves."];

    #[test]
    fn three_leaves_make_a_ternary_tree() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: &str| { s.to_string() }));
        for s in TEST_STRS.iter() {
            builder.push_leaf(s);
        }
        let tree = builder.finish().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b">Panda eats,>shoots,>and leaves.");
            for (i, child) in hn.children().enumerate() {
                if let Node::Leaf(ref ln) = *child {
                    assert_eq!(ln.hash_bytes(), TEST_STRS[i].as_bytes());
                    assert_eq!(ln.data(), TEST_STRS[i]);
                } else {
                    unreachable!()
                }
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn extend_leaves_for_arbitrary_arity_tree() {
        let mut builder = Builder::<MockHasher, _>::new();
        builder.extend_leaves(TEST_STRS.iter());
        let tree = builder.finish().unwrap();
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

    #[test]
    fn stack_builders_for_multilevel_tree() {
        fn leaf_extractor(s: &str) -> String { s.to_string() }

        let mut builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(leaf_extractor));
        builder.push_leaf("shoots,");
        builder.push_leaf("and leaves.");
        let subtree = builder.finish().unwrap();
        let mut builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(leaf_extractor));
        builder.push_leaf("Panda eats,");
        builder.push_tree(subtree);
        let tree = builder.finish().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b">Panda eats,#(>shoots,>and leaves.)";
            assert_eq!(hn.hash_bytes(), expected);
            let child = hn.child_at(0);
            if let Node::Leaf(ref ln) = *child {
                assert_eq!(ln.hash_bytes(), b"Panda eats,");
                assert_eq!(ln.data(), "Panda eats,");
            } else {
                unreachable!()
            }
            let child = hn.child_at(1);
            if let Node::Hash(ref hn) = *child {
                assert_eq!(hn.hash_bytes(), b">shoots,>and leaves.");
                let child = hn.child_at(0);
                if let Node::Leaf(ref ln) = *child {
                    assert_eq!(ln.hash_bytes(), b"shoots,");
                    assert_eq!(ln.data(), "shoots,");
                } else {
                    unreachable!()
                }
                let child = hn.child_at(1);
                if let Node::Leaf(ref ln) = *child {
                    assert_eq!(ln.hash_bytes(), b"and leaves.");
                    assert_eq!(ln.data(), "and leaves.");
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
    fn complete_tree_from_empty() {
        use std::iter::empty;
        let builder = Builder::<MockHasher, _>::new();
        builder.complete_tree_from(empty::<[u8; 1]>()).unwrap_err();
    }

    #[test]
    #[should_panic]
    fn complete_tree_from_panics_on_populated_builder() {
        let mut builder = Builder::<MockHasher, _>::new();
        builder.push_leaf(&[0u8][..]);
        let _ = builder.complete_tree_from(TEST_DATA.chunks(1));
    }

    #[test]
    fn complete_tree_with_no_leaf_data() {
        let builder = Builder::<MockHasher, _>::new();
        let tree = builder.complete_tree_from(TEST_DATA.chunks(15)).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    > the lazy dog";
            assert_eq!(hn.hash_bytes(), expected);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn complete_tree_with_owned_leaf_data() {
        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::owned::<Vec<u8>>());
        let iter = TEST_DATA.chunks(15).map(|s| { s.to_vec() });
        let tree = builder.complete_tree_from(iter).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    > the lazy dog";
            assert_eq!(hn.hash_bytes(), expected);
            if let Node::Leaf(ref ln) = *hn.child_at(1) {
                assert_eq!(ln.hash_bytes(), b" the lazy dog");
                assert_eq!(ln.data(), b" the lazy dog");
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn complete_tree_using_leaf_extract_with() {
        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(|s: &[u8]| { s[1] }));
        let tree = builder.complete_tree_from(TEST_DATA.chunks(15)).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    > the lazy dog";
            assert_eq!(hn.hash_bytes(), expected);
            if let Node::Leaf(ref ln) = *hn.child_at(1) {
                assert_eq!(ln.hash_bytes(), b" the lazy dog");
                assert_eq!(*ln.data(), b't');
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }
}
