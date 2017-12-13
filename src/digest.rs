// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use hash::Hasher;
use tree::{Nodes, Node};

pub extern crate digest_hash;

use self::digest_hash::{Hash, Endian, EndianInput};
use self::digest_hash::digest::FixedOutput;
use self::digest_hash::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;


#[derive(Clone)]
pub struct DigestHasher<D> {
    phantom: PhantomData<D>
}

impl<D> DigestHasher<D>
    where D: EndianInput
{
    pub fn new() -> Self {
        DigestHasher { phantom: PhantomData }
    }
}

impl<D> Default for DigestHasher<D>
    where D: EndianInput
{
    fn default() -> Self { Self::new() }
}

impl<D> Debug for DigestHasher<D>
    where D: EndianInput
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_tuple("DigestHasher")
         .field(&Endian::<D, D::ByteOrder>::byte_order_str())
         .finish()
    }
}

impl<D, In: ?Sized> Hasher<In> for DigestHasher<D>
    where In: Hash,
          D: Default,
          D: EndianInput,
          D: FixedOutput
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_input(&self, input: &In) -> Self::HashOutput {
        let mut digest = D::default();
        input.hash(&mut digest);
        digest.fixed_result()
    }

    fn hash_nodes<'a, L>(&'a self,
                         iter: Nodes<'a, Self::HashOutput, L>)
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

#[cfg(test)]
mod tests {
    use super::DigestHasher;
    use hash::Hasher;

    extern crate sha2;

    use self::sha2::{Sha256, Digest};
    use super::digest_hash::BigEndian;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn hash_input() {
        let hasher = DigestHasher::<BigEndian<Sha256>>::new();
        let hash = hasher.hash_input(&TEST_DATA);
        assert_eq!(hash, Sha256::digest(TEST_DATA));
    }
}
