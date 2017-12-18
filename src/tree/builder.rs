// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{MerkleTree, Node, HashNode, LeafNode, Children};
use super::plumbing;
use hash::Hasher;
use leaf;

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::iter::IntoIterator;


/// A convenience type alias for the result type used by this crate.
pub type BuildResult<H, T> = Result<MerkleTree<H, T>, EmptyTree>;

/// The facility for constructing Merkle trees.
///
/// A `Builder` instance can be used to construct a Merkle
/// tree. There are two ways of construction: incremental by using a
/// `Builder` to construct and compose a tree from leaves or previously
/// constructed subtrees up to root, or by using the convenience method
/// `complete_tree_from()` to create a left-filled, same-leaf-depth binary
/// tree out of a sequence of input values.
///
/// `Builder` has two type parameters: the hash exractor implementing trait
/// `hash::Hasher`, and the leaf data extractor implementing trait
/// `leaf::ExtractData`. Depending on the construction method and the
/// context for type inference, one or both of these types can be inferred
/// at the construction site.
///
#[derive(Default, Debug)]
pub struct Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
{
    hasher: D,
    leaf_data_extractor: L
}

impl<D, L> plumbing::FromNodes for Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
{
    type HashOutput = D::HashOutput;
    type LeafData = L::LeafData;

    fn tree_from_nodes(
        &self,
        nodes: Vec<Node<D::HashOutput, L::LeafData>>
    ) -> BuildResult<D::HashOutput, L::LeafData> {
        self.make_tree(nodes.into())
    }
}

impl<D, L> Clone for Builder<D, L>
where D: Hasher<L::Input> + Clone,
      L: leaf::ExtractData + Clone,
{
    fn clone(&self) -> Self {
        Builder::from_hasher_leaf_data(
            self.hasher.clone(), self.leaf_data_extractor.clone())
    }
}

impl<D, In> Builder<D, leaf::NoData<In>>
where D: Hasher<In> + Default
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
    /// let builder = Builder::<Hasher, _>::new();
    /// let data: &[u8] = b"the quick brown fox jumped over the lazy dog";
    /// let tree = builder.make_leaf(data);
    /// # let _ = tree;
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
        Builder {
            hasher,
            leaf_data_extractor
        }
    }

    /// Transforms input data into a tree consisting of a single leaf node.
    ///
    /// The hash value for the root leaf node is calculated by the hash
    /// extractor, and the leaf data value is obtained by the leaf data
    /// extractor used by this `Builder`.
    pub fn make_leaf(
        &self,
        input: L::Input
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let hash = self.hasher.hash_input(&input);
        let data = self.leaf_data_extractor.extract_data(input);
        MerkleTree { root: Node::Leaf(LeafNode { hash, data }) }
    }

    fn make_tree(
        &self,
        children: Box<[Node<D::HashOutput, L::LeafData>]>
    ) -> BuildResult<D::HashOutput, L::LeafData> {
        if children.is_empty() {
            return Err(EmptyTree);
        }
        Ok(self.make_tree_unchecked(children))
    }

    fn make_tree_unchecked(
        &self,
        children: Box<[Node<D::HashOutput, L::LeafData>]>
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        debug_assert!(!children.is_empty());
        let hash = self.hasher.hash_children(Children(children.iter()));
        MerkleTree { root: Node::Hash(HashNode { hash, children }) }
    }

    /// Joins the two given subtrees to produce a tree with a new root node,
    /// with the passed trees converted to the new root's child nodes.
    ///
    /// The `hash_children()` method of the hash extractor is used to obtain
    /// the root hash.
    pub fn join(
        &self,
        left:  MerkleTree<D::HashOutput, L::LeafData>,
        right: MerkleTree<D::HashOutput, L::LeafData>
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let children = Box::new([left.root, right.root]);
        self.make_tree_unchecked(children)
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
        child: MerkleTree<D::HashOutput, L::LeafData>
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let children = Box::new([child.root]);
        self.make_tree_unchecked(children)
    }

    /// Collects Merkle trees from the given iterable as child nodes for the
    /// root of the returned tree.
    ///
    /// The `hash_children()` method of the hash extractor is used to obtain
    /// the root hash.
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when the sequence of nodes is empty.
    ///
    pub fn collect_children_from<I>(
        &self,
        iterable: I
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where I: IntoIterator<Item = MerkleTree<D::HashOutput, L::LeafData>> {
        self.collect_children_from_iter(iterable.into_iter())
    }

    fn collect_children_from_iter<I>(
        &self,
        iter: I
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where I: Iterator<Item = MerkleTree<D::HashOutput, L::LeafData>> {
        let children: Vec<_> = iter.map(|tree| tree.root).collect();
        self.make_tree(children.into())
    }

    /// Constructs a left-filled binary Merkle tree from a sequence
    /// of input values with a known length. The nodes' hashes are calculated
    /// by the hash extractor, and the leaf data values are extracted from
    /// input data with the leaf data exractor.
    ///
    /// The constructed tree has the following properties: the left subtree
    /// of the root node is a perfect binary tree, all leaf nodes are on the
    /// same level (i.e. have the same depth), and nodes on every tree level
    /// are packed to the left. This means that the rightmost internal node
    /// on any level under root may have only a single child that is considered
    /// to be the left child. This layout is a subgraph to the
    /// [complete binary tree][nist] with the same leaf nodes at the deepest
    /// level; higher-level leaf nodes of the complete tree do not carry
    /// a practical meaning in this representation of the Merkle tree
    /// and are not present in the data model, nor any internal nodes that
    /// would have only such leaf nodes as descendants.
    ///
    /// [nist]: https://xlinux.nist.gov/dads/HTML/completeBinaryTree.html
    ///
    /// # Errors
    ///
    /// Returns the `EmptyTree` error when the input sequence is empty.
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
        &self,
        iterable: I
    ) -> BuildResult<D::HashOutput, L::LeafData>
    where I: IntoIterator<Item = L::Input>,
          I::IntoIter: ExactSizeIterator
    {
        let mut iter = iterable.into_iter();
        let len = iter.len();
        if len == 0 {
            return Err(EmptyTree);
        }
        let perfect_len = len.checked_next_power_of_two().unwrap();
        let tree = self.extract_complete_tree(&mut iter, len, perfect_len);
        debug_assert!(iter.next().is_none(),
                      "iterator has not been exhausted after reported length");
        Ok(tree)
    }

    fn extract_complete_tree<I>(
        &self,
        iter: &mut I,
        len: usize,
        perfect_len: usize
    ) -> MerkleTree<D::HashOutput, L::LeafData>
    where I: Iterator<Item = L::Input> {
        debug_assert!(len != 0);
        let left_len = perfect_len / 2;
        if len <= left_len {
            // We're going to have no right subtree on this node.
            // And it's still an internal node because this is never true
            // when perfect_len == 1.
            let left_tree = self.extract_complete_tree(
                    iter, len, left_len);
            self.chain_lone_child(left_tree)
        } else if len == 1 {
            let input = iter.next()
                        .expect("iterator returned None \
                                 before its reported length was reached");
            self.make_leaf(input)
        } else {
            let left_tree = self.extract_complete_tree(
                    iter, left_len, left_len);
            // This never overflows or comes to 0 because
            // left_len < len for len >= 2
            let right_len = len - left_len;
            let right_tree = self.extract_complete_tree(
                    iter, right_len, left_len);
            self.join(left_tree, right_tree)
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
    use tree::{Node};

    use super::super::testmocks::MockHasher;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn builder_no_data_fixed_size_array() {
        let builder = Builder::<MockHasher, _>::new();
        let tree = builder.make_leaf([1u8, 2u8, 3u8, 4u8]);
        assert_eq!(tree.root().hash_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn builder_with_owned_leaves() {
        let hasher = MockHasher::default();
        let builder = Builder::from_hasher_leaf_data(
                hasher, leaf::owned());
        let tree = builder.make_leaf([1u8, 2u8, 3u8, 4u8]);
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
        let builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: [u8; 4]| { s.len() }));
        let tree = builder.make_leaf([0u8, 1u8, 2u8, 3u8]);
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
        let builder = Builder::from_hasher_leaf_data(
                hasher,
                leaf::ExtractFn::with(|s: [u8; 4]| { s.len() + off }));
        let tree = builder.make_leaf([0u8, 1u8, 2u8, 3u8]);
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
        let builder = Builder::<MockHasher, leaf::NoData<&[u8]>>::new();
        let tree = builder.make_leaf(&v[..]);
        assert_eq!(tree.root().hash_bytes(), TEST_DATA);
    }

    #[test]
    fn two_leaves_make_a_tree() {
        let hasher = MockHasher::default();
        let builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: &str| { s.to_string() }));
        let left_leaf = builder.make_leaf("eats shoots");
        let right_leaf = builder.make_leaf("and leaves");
        let tree = builder.join(left_leaf, right_leaf);
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
        let builder = Builder::from_hasher_leaf_data(
                hasher, leaf::no_data());
        let child = builder.make_leaf("eats shoots");
        let tree = builder.chain_lone_child(child);
        if let Node::Hash(ref hn) = *tree.root() {
            let _child = hn.child_at(1);
        } else {
            unreachable!()
        }
    }

    const TEST_STRS: [&'static str; 3] = [
        "Panda eats,",
        "shoots,",
        "and leaves."];

    #[test]
    fn collect_children_for_arbitrary_arity_tree() {
        let hasher = MockHasher::default();
        let builder = Builder::from_hasher_leaf_data(
                hasher, leaf::extract_with(|s: &str| { s.to_string() }));
        let leaves =
            TEST_STRS.iter().map(|s| {
                builder.make_leaf(s)
            });
        let tree = builder.collect_children_from(leaves).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b">Panda eats,>shoots,>and leaves.");
            let mut peek_iter = hn.children().peekable();
            assert!(peek_iter.peek().is_some());
            for (i, child) in peek_iter.enumerate() {
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
    fn stack_trees() {
        fn leaf_extractor(s: &str) -> String { s.to_string() }

        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(leaf_extractor));
        let left = builder.make_leaf("shoots,");
        let right = builder.make_leaf("and leaves.");
        let subtree = builder.join(left, right);
        let left = builder.make_leaf("Panda eats,");
        let tree = builder.join(left, subtree);
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
    fn complete_tree_with_no_leaf_data() {
        let builder = Builder::<MockHasher, _>::new();
        let tree = builder.complete_tree_from(TEST_DATA.chunks(15)).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    #(> the lazy dog)";
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
                                    #(> the lazy dog)";
            assert_eq!(hn.hash_bytes(), expected);
            assert_eq!(hn.children().len(), 2);
            if let Node::Hash(ref hn) = *hn.child_at(1) {
                assert_eq!(hn.children().len(), 1);
                if let Node::Leaf(ref ln) = *hn.child_at(0) {
                    assert_eq!(ln.hash_bytes(), b" the lazy dog");
                    assert_eq!(ln.data(), b" the lazy dog");
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
    fn complete_tree_using_leaf_extract_with() {
        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::extract_with(|s: &[u8]| { s[1] }));
        let tree = builder.complete_tree_from(TEST_DATA.chunks(15)).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    #(> the lazy dog)";
            assert_eq!(hn.hash_bytes(), expected);
            if let Node::Hash(ref hn) = *hn.child_at(0) {
                if let Node::Leaf(ref ln) = *hn.child_at(1) {
                    assert_eq!(ln.hash_bytes(), b" fox jumps over");
                    assert_eq!(*ln.data(), b'f');
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
    fn complete_tree_using_leaf_extract_closure() {
        let off = 1;
        let builder = Builder::from_hasher_leaf_data(
                MockHasher::default(),
                leaf::ExtractFn::with(|s: &[u8]| { s[1] + off }));
        let tree = builder.complete_tree_from(TEST_DATA.chunks(15)).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    #(> the lazy dog)";
            assert_eq!(hn.hash_bytes(), expected);
            if let Node::Hash(ref hn) = *hn.child_at(0) {
                if let Node::Leaf(ref ln) = *hn.child_at(1) {
                    assert_eq!(ln.hash_bytes(), b" fox jumps over");
                    assert_eq!(*ln.data(), b'g');
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
    fn complete_tree_is_subgraph_of_its_math_definition() {
        let builder = Builder::<MockHasher, _>::new();
        let tree = builder.complete_tree_from(TEST_DATA.chunks(10)).unwrap();
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
}
