// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use digest;
use digest::generic_array::GenericArray;

//mod builder;
//pub use self::builder::*;

struct HashValue<H: digest::FixedOutput>(GenericArray<u8, H::OutputSize>);

pub struct MerkleTree<H, T=()>
    where H: digest::FixedOutput
{
    root: HashNode<H, T>
}

pub enum Node<H, T>
    where H: digest::FixedOutput
{
    Leaf(LeafNode<H, T>),
    Hash(HashNode<H, T>)
}

pub struct LeafNode<H, T>
    where H: digest::FixedOutput
{
    hash: HashValue<H>,
    data: T
}

pub struct HashNode<H, T>
    where H: digest::FixedOutput
{
    hash: HashValue<H>,
    children: Box<[Node<H, T>]>
}

impl<H, T> MerkleTree<H, T>
    where H: Default,
          H: digest::FixedOutput
{
    pub fn new() -> Self {
        let hasher: H = Default::default();
        let root = HashNode {
            hash: HashValue(hasher.fixed_result()),
            children: Box::new([])
        };
        MerkleTree { root }
    }
}

impl<H, T> MerkleTree<H, T>
    where H: digest::FixedOutput
{
    pub fn root(&self) -> &HashNode<H, T> { &self.root }
}

impl<H, T> LeafNode<H, T>
    where H: digest::FixedOutput
{
    pub fn hash_bytes(&self) -> &[u8] { self.hash.0.as_slice() }

    pub fn data(&self) -> &T {
        &self.data
    }
}

impl<H, T> HashNode<H, T>
    where H: digest::FixedOutput
{
    pub fn hash_bytes(&self) -> &[u8] { self.hash.0.as_slice() }

    pub fn child_at(&self, index: usize) -> &Node<H, T> {
        &self.children[index]
    }
}
