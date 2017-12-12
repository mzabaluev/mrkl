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
use std::fmt::Display;


#[derive(Debug)]
pub struct Builder<D, L, In>
    where D: Hasher<In>,
          L: leaf::ExtractData<In>
{
    hasher: D,
    leaf_data_extractor: L,
    nodes: Vec<Node<D::HashOutput, L::LeafData>>
}

impl<D, In> Builder<D, leaf::NoData, In>
    where D: Hasher<In>,
          D: Default
{
    pub fn new() -> Self {
        Self::from_hasher_leaf_data(D::default(), leaf::NoData)
    }
}

impl<D, L, In> Builder<D, L, In>
    where D: Hasher<In>,
          L: leaf::ExtractData<In>
{
    pub fn from_hasher_leaf_data(hasher: D, leaf_data_extractor: L) -> Self {
        Builder {
            hasher,
            leaf_data_extractor,
            // expecting two children per node
            nodes: Vec::with_capacity(2)
        }
    }

    pub fn push_leaf(&mut self, input: In) {
        let hash = self.hasher.hash_input(&input);
        let data = self.leaf_data_extractor.extract_data(input);
        self.nodes.push(Node::Leaf(LeafNode { hash, data }));
    }

    pub fn push_tree(&mut self,
                     tree: MerkleTree<D::HashOutput, L::LeafData>)
    {
        self.nodes.push(tree.root);
    }

    fn nodes<'a>(&'a self) -> Nodes<'a, D::HashOutput, L::LeafData> {
        Nodes(self.nodes.iter())
    }

    pub fn complete(mut self)
                    -> Result<MerkleTree<D::HashOutput, L::LeafData>,
                              EmptyTree>
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

    use hash::Hasher;
    use leaf;
    use tree::{MerkleTree, EmptyTree, Nodes, Node};

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[derive(Debug)]
    struct MockHasher {
        bytes: Vec<u8>
    }

    impl Default for MockHasher {
        fn default() -> Self {
            MockHasher { bytes: Vec::new() }
        }
    }

    impl<In: AsRef<[u8]>> Hasher<In> for MockHasher {
        type HashOutput = Vec<u8>;

        fn hash_input(&self, input: &In) -> Vec<u8> {
            input.as_ref().to_vec()
        }

        fn hash_nodes<'a, L>(&'a self,
                             iter: Nodes<'a, Vec<u8>, L>)
                             -> Vec<u8>
        {
            let mut dump = Vec::new();
            for node in iter {
                match *node {
                    Node::Leaf(ref ln) => {
                        dump.push(b'L');
                        dump.extend(ln.hash_bytes());
                    }
                    Node::Hash(ref hn) => {
                        dump.push(b'H');
                        dump.extend(hn.hash_bytes());
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
    fn builder_leaf_data_extract_with_closure() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, |s: [u8; 4]| { s.len() });
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
                hasher, |s: &str| { s.to_string() });
        builder.push_leaf("eats shoots");
        builder.push_leaf("and leaves");
        let tree = builder.complete().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b"Leats shootsLand leaves");
            assert_eq!(hn.child_count(), 2);
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
    fn three_leaves_make_a_ternary_tree() {
        const TEST_STRS: [&'static str; 3] = [
            "Panda eats,",
            "shoots,",
            "and leaves"];
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, |s: &str| { s.to_string() });
        for s in TEST_STRS.iter() {
            builder.push_leaf(s);
        }
        let tree = builder.complete().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b"LPanda eats,Lshoots,Land leaves");
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
    fn stack_builders_for_multilevel_tree() {
        fn leaf_extractor(s: &str) -> String { s.to_string() }

        let mut builder = Builder::from_hasher_leaf_data(
                MockHasher::default(), leaf_extractor);
        builder.push_leaf("shoots,");
        builder.push_leaf("and leaves");
        let subtree = builder.complete().unwrap();
        let mut builder = Builder::from_hasher_leaf_data(
                MockHasher::default(), leaf_extractor);
        builder.push_leaf("Panda eats,");
        builder.push_tree(subtree);
        let tree = builder.complete().unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b"LPanda eats,HLshoots,Land leaves");
            let child = hn.child_at(0);
            if let Node::Leaf(ref ln) = *child {
                assert_eq!(ln.hash_bytes(), b"Panda eats,");
                assert_eq!(ln.data(), "Panda eats,");
            } else {
                unreachable!()
            }
            let child = hn.child_at(1);
            if let Node::Hash(ref hn) = *child {
                assert_eq!(hn.hash_bytes(), b"Lshoots,Land leaves");
                let child = hn.child_at(0);
                if let Node::Leaf(ref ln) = *child {
                    assert_eq!(ln.hash_bytes(), b"shoots,");
                    assert_eq!(ln.data(), "shoots,");
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
        } else {
            unreachable!()
        }
    }
}
