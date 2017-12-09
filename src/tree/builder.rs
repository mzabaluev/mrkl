// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{MerkleTree, Node, HashNode, LeafNode, Nodes};
use hash::Hasher;

use std::error::Error;
use std::fmt;
use std::fmt::Display;


#[derive(Debug)]
pub struct Builder<H>
    where H: Hasher
{
    hasher: H,
    nodes: Vec<Node<H::HashOutput, H::LeafData>>
}

impl<H> Builder<H>
    where H: Hasher
{
    pub fn new(hasher: H) -> Self {
        Builder {
            hasher,
            // expecting two children per node
            nodes: Vec::with_capacity(2)
        }
    }

    pub fn push_leaf(&mut self, input: H::Input) {
        let (hash, data) = self.hasher.hash_data(input);
        self.nodes.push(Node::Leaf(LeafNode { hash, data }));
    }

    pub fn push_tree(&mut self,
                     tree: MerkleTree<H::HashOutput, H::LeafData>)
    {
        self.nodes.push(tree.root);
    }

    fn nodes<'a>(&'a self) -> Nodes<'a, H::HashOutput, H::LeafData> {
        Nodes(self.nodes.iter())
    }

    pub fn complete(mut self)
                    -> Result<MerkleTree<H::HashOutput, H::LeafData>,
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
