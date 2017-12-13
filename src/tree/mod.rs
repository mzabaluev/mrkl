// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Data types for representation and construction of Merkle trees.

mod builder;
pub use self::builder::{Builder, EmptyTree};

use std::iter::{Iterator, DoubleEndedIterator, ExactSizeIterator};
use std::slice;
use std::hash as std_hash;

/// A complete Merkle tree.
///
/// Values of this type represent complete Merkle trees.
/// A valid tree either has a single leaf node as the root node,
/// or has a hierarchy of nodes terminating with leaf nodes and
/// with hash-only nodes at levels above leaves.
///
/// `MerkleTree` hierarchies are immutable: it's not possible to e.g.
/// swap out nodes in safe code because doing so would violate
/// the hash integrity.
#[derive(Debug)]
pub struct MerkleTree<H, T> {
    root: Node<H, T>
}

/// A Merkle tree node, which can be either a leaf node or a hash node.
///
/// `Node` values can be borrowed from under a `MerkleTree`.
#[derive(Debug)]
pub enum Node<H, T> {
    /// A leaf node value.
    Leaf(LeafNode<H, T>),
    /// A hash node value with child nodes.
    Hash(HashNode<H, T>)
}

/// A value representing a leaf node.
///
/// `LeafNode` values can be obtained by destructuring `Node`.
#[derive(Debug)]
pub struct LeafNode<H, T> {
    hash: H,
    data: T
}

/// A value representing a node containing the hash of its child nodes.
///
/// `HashNode` values can be obtained by destructuring `Node`.
#[derive(Debug)]
pub struct HashNode<H, T> {
    hash: H,
    children: Box<[Node<H, T>]>
}

impl<H, T> MerkleTree<H, T> {
    /// Returns the root node of the tree as a borrowed reference.
    pub fn root(&self) -> &Node<H, T> { &self.root }
}

impl<H, T> Node<H, T> {
    /// Returns a reference to the hash value of the tree node.
    pub fn hash(&self) -> &H {
        match *self {
            Node::Leaf(ref ln) => &ln.hash,
            Node::Hash(ref hn) => &hn.hash
        }
    }
}

impl<H: AsRef<[u8]>, T> Node<H, T> {
    /// Returns the hash value of the node as a byte slice.
    pub fn hash_bytes(&self) -> &[u8] {
        self.hash().as_ref()
    }
}

impl<H: AsRef<[u8]>, T> LeafNode<H, T> {
    /// Returns the hash value of the leaf node as a byte slice.
    pub fn hash_bytes(&self) -> &[u8] { self.hash.as_ref() }
}

impl<H, T> LeafNode<H, T> {

    /// Returns a reference to the hash value of the leaf node.
    pub fn hash(&self) -> &H { &self.hash }

    /// Returns a reference to the leaf data value of the node.
    pub fn data(&self) -> &T { &self.data }
}

impl<H: AsRef<[u8]>, T> HashNode<H, T> {
    /// Returns the hash value of the hash node as a byte slice.
    pub fn hash_bytes(&self) -> &[u8] { self.hash.as_ref() }
}

impl<H, T> HashNode<H, T> {

    /// Returns a reference to the hash value of the hash node.
    pub fn hash(&self) -> &H { &self.hash }

    /// Borrows a child node value at the specified index.
    pub fn child_at(&self, index: usize) -> &Node<H, T> {
        &self.children[index]
    }

    /// Returns an iterator over the child nodes.
    pub fn children<'a>(&'a self) -> Nodes<'a, H, T> {
        Nodes(self.children.iter())
    }
}

// NOTE: The PartialEq, Eq, and Hash implementations assume that the hashing
// is cryptographically strong.

macro_rules! impl_eq_for {
    ($($Name:ident),+) => {
        $(impl<H: Eq, T> Eq for $Name<H, T> {})+
    }
}

macro_rules! impl_partial_eq {
    {
        $(
            <$Rhs:ident> for $This:ident (&$self:ident, &$other:ident) {
                $logic:expr
            }
        )+
    } => {
        $(
            impl<H: PartialEq, T> PartialEq<$Rhs<H, T>> for $This<H, T> {
                fn eq(&$self, $other: &$Rhs<H, T>) -> bool {
                    $logic
                }
            }
        )+
    }
}

macro_rules! impl_partial_eq_and_hash_for {
    {
        $(
            $This:ident (&$self:ident) {
                $get_hash:expr
            }
        )+
    } => {
        $(
            impl_partial_eq! {
                <MerkleTree> for $This (&$self, &other) {
                    $get_hash == other.root().hash()
                }
                <Node> for $This (&$self, &other) {
                    $get_hash == other.hash()
                }
                <LeafNode> for $This (&$self, &other) {
                    $get_hash == other.hash()
                }
                <HashNode> for $This (&$self, &other) {
                    $get_hash == other.hash()
                }
            }

            impl<H: std_hash::Hash, T> std_hash::Hash for $This<H, T> {
                fn hash<S: std_hash::Hasher>(&$self, state: &mut S) {
                    $get_hash.hash(state)
                }
            }
        )+
    }
}

impl_eq_for!(MerkleTree, Node, LeafNode, HashNode);

impl_partial_eq_and_hash_for! {
    MerkleTree (&self) {
        self.root().hash()
    }
    Node (&self) {
        self.hash()
    }
    LeafNode (&self) {
        self.hash()
    }
    HashNode (&self) {
        self.hash()
    }
}

/// An iterator over borrowed values of tree nodes, usually being the
/// child nodes of a single hash node.
#[derive(Clone, Debug)]
pub struct Nodes<'a, H: 'a, T: 'a>(slice::Iter<'a, Node<H, T>>);

impl<'a, H, T> Iterator for Nodes<'a, H, T> {
    type Item = &'a Node<H, T>;
    fn next(&mut self) -> Option<Self::Item> { self.0.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.0.size_hint() }
    fn count(self) -> usize { self.0.count() }
    fn nth(&mut self, n: usize) -> Option<Self::Item> { self.0.nth(n) }
    fn last(self) -> Option<Self::Item> { self.0.last() }
}

impl<'a, H, T> ExactSizeIterator for Nodes<'a, H, T> {
    fn len(&self) -> usize { self.0.len() }
}

impl<'a, H, T> DoubleEndedIterator for Nodes<'a, H, T> {
    fn next_back(&mut self) -> Option<Self::Item> { self.0.next_back() }
}
