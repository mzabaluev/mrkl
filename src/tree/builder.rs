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
pub struct Builder<In, D, L>
    where D: Hasher<In>,
          L: leaf::ExtractData<In>
{
    hasher: D,
    leaf_data_extractor: L,
    nodes: Vec<Node<D::HashOutput, L::LeafData>>
}

impl<In, D> Builder<In, D, leaf::NoData>
    where D: Hasher<In>,
          D: Default
{
    pub fn new() -> Self {
        Self::from_hasher_leaf_data(D::default(), leaf::NoData)
    }
}

impl<In, D, L> Builder<In, D, L>
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
