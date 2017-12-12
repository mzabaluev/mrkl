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
    use tree::{Nodes, Node};

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

    const CHUNK_SIZE: usize = 4;

    impl Hasher<[u8; CHUNK_SIZE]> for MockHasher {
        type HashOutput = Vec<u8>;

        fn hash_input(&self, input: &[u8; CHUNK_SIZE]) -> Vec<u8> {
            input.to_vec()
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
    fn builder_no_data_fixed_chunks() {
        let mut builder = Builder::<MockHasher, _, _>::new();
        builder.push_leaf([0u8; CHUNK_SIZE]);
    }

    #[test]
    fn builder_with_owned_leaves() {
        let hasher = MockHasher::default();
        let mut builder = Builder::from_hasher_leaf_data(
                hasher, leaf::owned());
        builder.push_leaf([0u8; CHUNK_SIZE]);
    }
}
