// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use hash::Hasher;
use leaf::LeafData;
use tree::{Nodes, Node};

extern crate digest;

use self::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;


#[derive(Clone)]
pub struct DigestHasher<D, F> {
    leaf_data_extractor: F,
    phantom: PhantomData<D>
}

impl<D, F> Debug for DigestHasher<D, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("DigestHasher { .. }")
    }
}

struct HashAdapter<D> {
    inner: D
}

impl<D: Default> HashAdapter<D> {
    fn new() -> Self {
        HashAdapter { inner: D::default() }
    }
}

impl<D> HashAdapter<D> {
    fn into_inner(self) -> D { self.inner }
}

impl<D: digest::Input> StdHasher for HashAdapter<D> {

    // This is not needed for our purposes, but it's a required method
    fn finish(&self) -> u64 { unimplemented!() }

    fn write(&mut self, bytes: &[u8]) {
        self.inner.process(bytes);
    }
}

impl<D, F> DigestHasher<D, F> {
    pub fn new(leaf_data_extractor: F) -> DigestHasher<D, F> {
        DigestHasher { leaf_data_extractor, phantom: PhantomData }
    }
}

impl<D, F> Hasher for DigestHasher<D, F>
    where D: digest::Input,
          D: digest::FixedOutput,
          D: Default,
          F: LeafData,
          F::Input: StdHash
{
    type Input = F::Input;
    type HashOutput = GenericArray<u8, D::OutputSize>;
    type LeafData = F::Output;

    fn hash_data(&self, input: Self::Input)
                 -> (Self::HashOutput, Self::LeafData)
    {
        let mut hasher = HashAdapter::<D>::new();
        input.hash(&mut hasher);
        let hash = hasher.into_inner().fixed_result();
        let data = self.leaf_data_extractor.leaf_data(input);
        (hash, data)
    }

    fn hash_nodes<'a>(&'a self,
                      iter: Nodes<'a, Self::HashOutput, Self::LeafData>)
                      -> Self::HashOutput
    {
        let mut digest = D::default();
        for node in iter {
            match *node {
                Node::Leaf(ref ln) => {
                    digest.process(&[0u8]);
                    digest.process(ln.hash_bytes());
                }
                Node::Hash(ref hn) => {
                    digest.process(&[1u8]);
                    digest.process(hn.hash_bytes());
                }
            }
        }
        digest.fixed_result()
    }
}
