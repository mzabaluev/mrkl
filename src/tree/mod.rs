// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The data model and construction facilities for Merkle trees.
//!
//! The data of constructed, immutable Merkle trees are represented
//! by types `MerkleTree`, `Node`, `LeafNode`, and `HashNode`. All of these
//! types are comparable for equality with other of these types where it
//! makes sense, except that `LeafNode` and `HashNode` are not directly
//! comparable and never compare against the other type as equal when found
//! gisguised by `MerkleTree` or `Node`.
//! Each of the types also implements `Eq` and `std::hash::Hash`.
//! Practical uniqueness of the hash values in a Merkle tree is used to
//! provide fast implementations for the standard equality comparison and
//! hashing traits. However, if the hashing algorithm has been chosen
//! poorly, incorrect results may occur. Also note that leaf data never
//! figure in hashing or equality comparisons.

mod builder;
pub use self::builder::{Builder, BuildResult, EmptyTree};

#[cfg(feature = "parallel")]
pub mod parallel;

mod plumbing;

#[cfg(test)]
mod testmocks;

use std::iter::{Iterator, DoubleEndedIterator, ExactSizeIterator};
use std::slice;
use std::fmt;
use std::fmt::Debug;
use std::hash as std_hash;

/// A Merkle tree.
///
/// Values of this type represent fully constructed Merkle trees.
/// A valid tree either has a single leaf node as the root node,
/// or has a hierarchy of nodes terminating with leaf nodes and
/// with hash-only nodes at levels above leaves.
///
/// `MerkleTree` hierarchies are immutable: it's not possible to e.g.
/// swap out nodes in safe code because doing so would violate
/// the hash integrity.
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize))]
pub struct MerkleTree<H, T> {
    root: Node<H, T>
}

/// A Merkle tree node, which can be either a leaf node or a hash node.
///
/// `Node` values can be borrowed from under a `MerkleTree`.
#[cfg_attr(feature = "serialization", derive(Serialize))]
pub enum Node<H, T> {
    /// A leaf node value.
    Leaf(LeafNode<H, T>),
    /// An internal node value.
    Hash(HashNode<H, T>)
}

/// A value representing a leaf node in a Merkle tree.
///
/// `LeafNode` values can be obtained by destructuring `Node`.
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize))]
pub struct LeafNode<H, T> {
    hash: H,
    data: T
}

/// A value representing an internal node in Merkle tree.
///
/// `HashNode` values can be obtained by destructuring `Node`.
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize))]
pub struct HashNode<H, T> {
    hash: H,
    children: Box<[Node<H, T>]>
}

impl<H, T> MerkleTree<H, T> {
    /// Returns the root node of the tree as a borrowed reference.
    pub fn root(&self) -> &Node<H, T> { &self.root }
}

impl<H: Debug, T: Debug> Debug for Node<H, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Node::Leaf(ref ln) => ln.fmt(f),
            Node::Hash(ref hn) => hn.fmt(f)
        }
    }
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
    /// Returns the hash value of the node as a byte slice.
    pub fn hash_bytes(&self) -> &[u8] { self.hash.as_ref() }
}

impl<H, T> LeafNode<H, T> {

    /// Returns a reference to the hash value of the node.
    pub fn hash(&self) -> &H { &self.hash }

    /// Returns a reference to the leaf data value of the node.
    pub fn data(&self) -> &T { &self.data }
}

impl<H: AsRef<[u8]>, T> HashNode<H, T> {
    /// Returns the hash value of the node as a byte slice.
    pub fn hash_bytes(&self) -> &[u8] { self.hash.as_ref() }
}

impl<H, T> HashNode<H, T> {

    /// Returns a reference to the hash value of the node.
    pub fn hash(&self) -> &H { &self.hash }

    /// Borrows a child node value at the specified index.
    pub fn child_at(&self, index: usize) -> &Node<H, T> {
        &self.children[index]
    }

    /// Returns an iterator over the child nodes.
    pub fn children<'a>(&'a self) -> Children<'a, H, T> {
        Children(self.children.iter())
    }

    pub fn child_hashes<'a>(&'a self) -> NodeHashes<'a, H> {
        NodeHashes {
            nodes: &self.children[..],
            pos: 0,
            len: self.children.len()
        }
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
            <$Rhs:ident> for $This:ident: (&$self:ident, &$other:ident) {
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

macro_rules! impl_hash_for {
    {
        $(
            $This:ident: (&$self:ident) {
                $get_hash:expr
            }
        )+
    } => {
        $(
            impl<H: std_hash::Hash, T> std_hash::Hash for $This<H, T> {
                fn hash<S: std_hash::Hasher>(&$self, state: &mut S) {
                    $get_hash.hash(state)
                }
            }
        )+
    }
}

impl_eq_for!(MerkleTree, Node, LeafNode, HashNode);

impl_partial_eq! {
    <MerkleTree> for MerkleTree: (&self, &other) {
        self.root() == other.root()
    }

    <Node> for MerkleTree: (&self, &other) {
        self.root() == other
    }

    <LeafNode> for MerkleTree: (&self, &other) {
        self.root() == other
    }

    <HashNode> for MerkleTree: (&self, &other) {
        self.root() == other
    }

    <MerkleTree> for Node: (&self, &other) {
        self == other.root()
    }

    <Node> for Node: (&self, &other) {
        match (self, other) {
            (&Node::Leaf(ref lhs), &Node::Leaf(ref rhs)) => lhs == rhs,
            (&Node::Hash(ref lhs), &Node::Hash(ref rhs)) => lhs == rhs,
            _ => false
        }
    }

    <LeafNode> for Node: (&self, &other) {
        match *self {
            Node::Leaf(ref lhs) => lhs == other,
            _ => false
        }
    }

    <HashNode> for Node: (&self, &other) {
        match *self {
            Node::Hash(ref lhs) => lhs == other,
            _ => false
        }
    }

    <MerkleTree> for LeafNode: (&self, &other) {
        self == other.root()
    }

    <Node> for LeafNode: (&self, &other) {
        match *other {
            Node::Leaf(ref rhs) => self == rhs,
            _ => false
        }
    }

    <LeafNode> for LeafNode: (&self, &other) {
        self.hash() == other.hash()
    }

    <MerkleTree> for HashNode: (&self, &other) {
        self == other.root()
    }

    <Node> for HashNode: (&self, &other) {
        match *other {
            Node::Hash(ref rhs) => self == rhs,
            _ => false
        }
    }

    <HashNode> for HashNode: (&self, &other) {
        self.hash() == other.hash()
    }
}

impl_hash_for! {
    MerkleTree: (&self) {
        self.root().hash()
    }
    Node: (&self) {
        self.hash()
    }
    LeafNode: (&self) {
        self.hash()
    }
    HashNode: (&self) {
        self.hash()
    }
}

/// An iterator over borrowed values of tree nodes, usually being the
/// child nodes of a single hash node.
#[derive(Debug)]
pub struct Children<'a, H: 'a, T: 'a>(slice::Iter<'a, Node<H, T>>);

impl<'a, H, T> Clone for Children<'a, H, T> {
    fn clone(&self) -> Self {
        Children(self.0.clone())
    }
}

impl<'a, H, T> Iterator for Children<'a, H, T> {
    type Item = &'a Node<H, T>;
    fn next(&mut self) -> Option<Self::Item> { self.0.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.0.size_hint() }
    fn count(self) -> usize { self.0.count() }
    fn nth(&mut self, n: usize) -> Option<Self::Item> { self.0.nth(n) }
    fn last(self) -> Option<Self::Item> { self.0.last() }
}

impl<'a, H, T> ExactSizeIterator for Children<'a, H, T> {
    fn len(&self) -> usize { self.0.len() }
}

impl<'a, H, T> DoubleEndedIterator for Children<'a, H, T> {
    fn next_back(&mut self) -> Option<Self::Item> { self.0.next_back() }
}

// An internal helper trait that provides dynamic dispatch to iterate
// over nodes' hashes while not encoding leaf data as the object type's
// parameter.
trait DynHashSlice<H> {
    fn len(&self) -> usize;
    fn hash_at(&self, index: usize) -> &H;
}

impl<'a, H, T> DynHashSlice<H> for [Node<H, T>] {
    fn len(&self) -> usize { (*self).len() }

    fn hash_at(&self, index: usize) -> &H {
        self[index].hash()
    }
}

#[derive(Clone)]
pub struct NodeHashes<'a, H: 'a> {
    nodes: &'a DynHashSlice<H>,
    pos: usize,
    len: usize
}

impl<'a, H> Debug for NodeHashes<'a, H> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("NodeHashes")
         .field("pos", &self.pos)
         .field("len", &self.len)
         .finish()
    }
}

impl<'a, H> Iterator for NodeHashes<'a, H> {
    type Item = &'a H;

    fn next(&mut self) -> Option<&'a H> {
        if self.pos == self.len {
            None
        } else {
            debug_assert!(self.pos <= self.len);
            let i = self.pos;
            self.pos += 1;
            Some(self.nodes.hash_at(i))
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining_len = self.len - self.pos;
        (remaining_len, Some(remaining_len))
    }

    fn count(self) -> usize { self.len - self.pos }

    fn nth(&mut self, n: usize) -> Option<&'a H> {
        if n >= self.len - self.pos {
            None
        } else {
            // self.pos can't overflow because it's not greater
            // than a memory sized container length
            let i = self.pos + n;
            self.pos = i + 1;
            Some(self.nodes.hash_at(i))
        }
    }

    fn last(self) -> Option<&'a H> {
        debug_assert!(self.pos <= self.len);
        if self.pos == self.len {
            // This includes check for self.len == 0
            None
        } else {
            Some(self.nodes.hash_at(self.len - 1))
        }
    }
}

impl<'a, H> ExactSizeIterator for NodeHashes<'a, H> {
    fn len(&self) -> usize { self.len }
}

impl<'a, H> DoubleEndedIterator for NodeHashes<'a, H> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.pos == 0 {
            None
        } else {
            self.pos -= 1;
            Some(self.nodes.hash_at(self.pos))
        }
    }
}
