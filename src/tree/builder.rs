// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{MerkleTree, Node, HashNode, LeafNode, Nodes};
use hash::Hasher;
use leaf;

use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::iter::IntoIterator;


/// The facility to construct Merkle trees with.
///
/// Mutable `Builder` instances can be used to construct a complete Merkle
/// tree. There are two ways of construction: incremental by using `Builder`
/// instances to construct and compose trees, or by using the convenience
/// method `build_balanced_from()` to create a balanced binary tree out of a
/// sequence of input values.
///
/// When used in the incremental fashion, a `Builder` contains a
/// sequence of nodes which can be populated in order, to become one layer
/// – either a single leaf node, or the nodes immediately under the
/// newly calculated root node – of a complete Merkle tree created with
/// the method `complete()`. Either input data values or complete subtrees
/// can be consumed to append leaf or hash nodes, respectively.
///
/// `Builder` has three type parameters: the hash exractor implementing trait
/// `hash::Hasher`, the leaf data extractor implementing trait
/// `leaf::ExractData`, and the input value type. Depending on the
/// construction method and the context for type inference, some or all
/// of these types can be inferred at the construction site.
///
pub struct Builder<D, L, In>
    where D: Hasher<In>,
          L: leaf::ExtractData<In>
{
    hasher: D,
    leaf_data_extractor: L,
    nodes: Vec<Node<D::HashOutput, L::LeafData>>
}

impl<D, L, In> Debug for Builder<D, L, In>
where D: Debug,
      D: Hasher<In>,
      D::HashOutput: Debug,
      L: Debug,
      L: leaf::ExtractData<In>,
      L::LeafData: Debug
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Builder")
         .field("hasher", &self.hasher)
         .field("leaf_data_extractor", &self.leaf_data_extractor)
         .field("nodes", &self.nodes)
         .finish()
    }
}

impl<D, In> Builder<D, leaf::NoData, In>
    where D: Hasher<In>,
          D: Default
{
    /// Constructs a `Builder` with a default instance of the hash extractor,
    /// and `NoData` in place of the list data extractor.
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
    /// let mut builder = Builder::<Hasher, _, _>::new();
    /// let data: &[u8] = b"the quick brown fox jumped over the lazy dog";
    /// builder.push_leaf(data);
    /// # }
    /// # #[cfg(not(feature = "digest"))]
    /// # fn main() { }
    /// ```
    pub fn new() -> Self {
        Self::from_hasher_leaf_data(D::default(), leaf::NoData)
    }
}

impl<D, L, In> Builder<D, L, In>
    where D: Hasher<In>,
          L: leaf::ExtractData<In>
{
    /// Constructs a `Builder` from the given instances of the hasher
    /// and the leaf data extractor.
    pub fn from_hasher_leaf_data(hasher: D, leaf_data_extractor: L) -> Self {
        Builder {
            hasher,
            leaf_data_extractor,
            // expecting two children per node
            nodes: Vec::with_capacity(2)
        }
    }

    /// Appends a leaf node to the sequence of nodes.
    ///
    /// The hash value for the leaf node is calculated by the hash extractor,
    /// and the leaf data value is obtained by the leaf data extractor
    /// used by this `Builder`.
    pub fn push_leaf(&mut self, input: In) {
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
    where I: IntoIterator<Item = In> {
        self.extend_leaves_impl(iter.into_iter())
    }

    fn extend_leaves_impl<I>(&mut self, iter: I)
    where I: Iterator<Item = In> {
        let (size_low, _) = iter.size_hint();
        self.nodes.reserve(size_low);
        for input in iter {
            self.push_leaf(input);
        }
    }

    fn nodes<'a>(&'a self) -> Nodes<'a, D::HashOutput, L::LeafData> {
        Nodes(self.nodes.iter())
    }

    /// Constructs a complete MerkleTree from the populated `Builder`,
    /// consuming it in the process.
    ///
    /// The tree constructed will depend on the number of nodes this
    /// instance has been populated with. From a single leaf node, a
    /// single-level tree is constructed containing the leaf node as
    /// root. From multiple nodes, a tree is constructed by creating a
    /// root hash node as the parent of the sequence of the populated nodes,
    /// hashed with the hash extractor's `hash_nodes()` method to
    /// obtain the root hash.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when called on an unpopulated
    /// `Builder`.
    ///
    pub fn complete(mut self)
                -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
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

impl<D, L, In> Builder<D, L, In>
    where D: Hasher<In> + Clone,
          L: leaf::ExtractData<In> + Clone
{
    /// Constructs a balanced binary Merkle tree from a sequence of
    /// input values with a known length. The nodes' hashes are calculated
    /// by the hash extractor, and the leaf data values are extracted from
    /// input data with the leaf data exractor.
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
    /// let tree = builder.build_balanced_from(input.chunks(10)).unwrap();
    /// #     let _ = tree;
    /// # }
    /// # #[cfg(not(feature = "digest"))]
    /// # fn main() { }
    /// ```
    pub fn build_balanced_from<I>(mut self, iterable: I)
                -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
        where I: IntoIterator<Item = In>,
              I::IntoIter: ExactSizeIterator
    {
        assert!(self.nodes.is_empty(),
                "build_balanced_from() called on a populated Builder");
        let mut iter = iterable.into_iter();
        let len = iter.len();
        if len == 0 {
            return Err(EmptyTree);
        }
        self.populate_balanced_from_iter(&mut iter, len);
        debug_assert!(iter.next().is_none(),
                      "iterator has not been exhausted after reported length");
        self.complete()
    }

    fn populate_balanced_from_iter<I>(&mut self, iter: &mut I, len: usize)
        where I: Iterator<Item = In>
    {
        debug_assert!(len != 0);
        if len == 1 {
            let item = iter.next()
                       .expect("iterator returned None \
                                before its reported length was reached");
            self.push_leaf(item);
        } else {
            let left_len = len.saturating_add(1) / 2;
            {
                let mut builder = Builder::from_hasher_leaf_data(
                            self.hasher.clone(),
                            self.leaf_data_extractor.clone());
                builder.populate_balanced_from_iter(iter, left_len);
                let left_tree = builder.complete().unwrap();
                self.push_tree(left_tree);
            }
            let right_len = len - left_len;
            {
                let mut builder = Builder::from_hasher_leaf_data(
                            self.hasher.clone(),
                            self.leaf_data_extractor.clone());
                builder.populate_balanced_from_iter(iter, right_len);
                let right_tree = builder.complete().unwrap();
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

    use hash::{Hasher, NodeHasher};
    use leaf;
    use tree::{MerkleTree, EmptyTree, Nodes, Node};

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[derive(Clone, Debug, Default)]
    struct MockHasher;

    impl<In: AsRef<[u8]>> Hasher<In> for MockHasher {
        fn hash_input(&self, input: &In) -> Vec<u8> {
            input.as_ref().to_vec()
        }
    }

    impl NodeHasher for MockHasher {

        type HashOutput = Vec<u8>;

        fn hash_nodes<'a, L>(&'a self,
                             iter: Nodes<'a, Vec<u8>, L>)
                             -> Vec<u8>
        {
            let mut dump = Vec::new();
            for node in iter {
                match *node {
                    Node::Leaf(ref ln) => {
                        dump.push(b'>');
                        dump.extend(ln.hash_bytes());
                    }
                    Node::Hash(ref hn) => {
                        dump.extend(b"#(");
                        dump.extend(hn.hash_bytes());
                        dump.extend(b")");
                    }
                }
            }
            dump
        }
    }

    #[test]
    fn empty_tree() {
        use std::error::Error;

        fn daft() -> Result<MerkleTree<Vec<u8>, ()>, EmptyTree> {
            let builder = Builder::<MockHasher, _, String>::new();
            let _ = builder.complete()?;
            unreachable!()
        }

        let err = daft().unwrap_err();
        assert_eq!(err.description(), "empty Merkle tree");
        println!("{}", err);
        println!("{:?}", err);
    }

    #[test]
    fn builder_no_data_fixed_size_array() {
        let mut builder = Builder::<MockHasher, leaf::NoData, _>::new();
        builder.push_leaf([1u8, 2u8, 3u8, 4u8]);
        let tree = builder.complete().unwrap();
        assert_eq!(tree.root().hash_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn builder_with_owned_leaves() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::owned());
        builder.push_leaf([1u8, 2u8, 3u8, 4u8]);
        let tree = builder.complete().unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), &[1, 2, 3, 4]);
            assert_eq!(ln.data(), &[1, 2, 3, 4]);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn builder_leaf_data_extract_with_plain_fn() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: [u8; 4]| { s.len() }));
        builder.push_leaf([0u8, 1u8, 2u8, 3u8]);
        let tree = builder.complete().unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), &[0, 1, 2, 3]);
            assert_eq!(*ln.data(), 4);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn builder_leaf_data_extract_with_closure() {
        let hasher = MockHasher::default();
        let off = 42;
        let mut builder = Builder::from_hasher_leaf_data(
                hasher,
                leaf::ExtractFn::with(|s: [u8; 4]| { s.len() + off }));
        builder.push_leaf([0u8, 1u8, 2u8, 3u8]);
        let tree = builder.complete().unwrap();
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
        let mut builder = Builder::<MockHasher, _, &[u8]>::new();
        builder.push_leaf(&v[..]);
        let tree = builder.complete().unwrap();
        assert_eq!(tree.root().hash_bytes(), TEST_DATA);
    }

    #[test]
    fn two_leaves_make_a_tree() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: &str| { s.to_string() }));
        builder.push_leaf("eats shoots");
        builder.push_leaf("and leaves");
        let tree = builder.complete().unwrap();
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
                hasher, leaf::NoData);
        builder.push_leaf("eats shoots");
        builder.push_leaf("and leaves");
        let tree = builder.complete().unwrap();
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
        let tree = builder.complete().unwrap();
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
        let mut builder = Builder::<MockHasher, _, _>::new();
        builder.extend_leaves(TEST_STRS.iter());
        let tree = builder.complete().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b">Panda eats,>shoots,>and leaves.");
            for (i, child) in hn.children().enumerate() {
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
        let subtree = builder.complete().unwrap();
        let mut builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(leaf_extractor));
        builder.push_leaf("Panda eats,");
        builder.push_tree(subtree);
        let tree = builder.complete().unwrap();
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
    fn build_balanced_from_empty() {
        use std::iter::empty;
        let builder = Builder::<MockHasher, _, _>::new();
        builder.build_balanced_from(empty::<[u8; 1]>()).unwrap_err();
    }

    #[test]
    #[should_panic]
    fn build_balanced_on_populated_builder() {
        let mut builder = Builder::<MockHasher, leaf::NoData, &[u8]>::new();
        builder.push_leaf(&[0u8]);
        let _ = builder.build_balanced_from(TEST_DATA.chunks(1));
    }

    #[test]
    fn build_balanced_no_leaf_data() {
        let builder = Builder::<MockHasher, leaf::NoData, _>::new();
        let tree = builder.build_balanced_from(TEST_DATA.chunks(15)).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    > the lazy dog";
            assert_eq!(hn.hash_bytes(), expected);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn build_balanced_owned_leaf_data() {
        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::owned::<Vec<u8>>());
        let iter = TEST_DATA.chunks(15).map(|s| { s.to_vec() });
        let tree = builder.build_balanced_from(iter).unwrap();
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
    fn build_balanced_leaf_data_extract_with() {
        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(|s: &[u8]| { s[1] }));
        let tree = builder.build_balanced_from(TEST_DATA.chunks(15)).unwrap();
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
