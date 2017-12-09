// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod builder;
pub use self::builder::{Builder, EmptyTree};

use std::iter::{Iterator, DoubleEndedIterator, ExactSizeIterator};
use std::slice;

#[derive(Debug)]
pub struct MerkleTree<H, T> {
    root: Node<H, T>
}

#[derive(Debug)]
pub enum Node<H, T> {
    Leaf(LeafNode<H, T>),
    Hash(HashNode<H, T>)
}

#[derive(Debug)]
pub struct LeafNode<H, T> {
    hash: H,
    data: T
}

#[derive(Debug)]
pub struct HashNode<H, T> {
    hash: H,
    children: Box<[Node<H, T>]>
}

impl<H, T> MerkleTree<H, T> {
    pub fn root(&self) -> &Node<H, T> { &self.root }
}

impl<H: AsRef<[u8]>, T> Node<H, T> {

    pub fn hash_bytes(&self) -> &[u8] {
        match *self {
            Node::Leaf(ref ln) => ln.hash_bytes(),
            Node::Hash(ref hn) => hn.hash_bytes()
        }
    }
}

impl<H: AsRef<[u8]>, T> LeafNode<H, T> {
    pub fn hash_bytes(&self) -> &[u8] { self.hash.as_ref() }
}

impl<H, T> LeafNode<H, T> {
    pub fn data(&self) -> &T {
        &self.data
    }
}

impl<H: AsRef<[u8]>, T> HashNode<H, T> {
    pub fn hash_bytes(&self) -> &[u8] { self.hash.as_ref() }
}

impl<H, T> HashNode<H, T> {

    pub fn child_count(&self) -> usize { self.children.len() }

    pub fn child_at(&self, index: usize) -> &Node<H, T> {
        &self.children[index]
    }

    pub fn children<'a>(&'a self) -> Nodes<'a, H, T> {
        Nodes(self.children.iter())
    }
}

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
