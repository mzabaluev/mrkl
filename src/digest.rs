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
use self::digest_hash::byteorder::ByteOrder;
use self::digest_hash::digest::{Input, FixedOutput};
use self::digest_hash::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;


#[derive(Clone)]
pub struct DigestHasher<In: ?Sized, D, Bo> {
    phantom: PhantomData<(*const In, Endian<D, Bo>)>
}

impl<In: ?Sized, D, Bo> Default for DigestHasher<In, D, Bo>
    where D: EndianInput,
          Bo: ByteOrder
{
    fn default() -> Self {
        DigestHasher { phantom: PhantomData }
    }
}

impl<In: ?Sized, D, Bo> Debug for DigestHasher<In, D, Bo>
    where Bo: ByteOrder
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_tuple("DigestHasher")
         .field(&Endian::<D, Bo>::byte_order_str())
         .finish()
    }
}

impl<In: ?Sized, D, Bo> Hasher<In> for DigestHasher<In, D, Bo>
    where In: Hash,
          D: Default,
          D: Input,
          D: FixedOutput,
          Bo: ByteOrder
{
    type HashOutput = GenericArray<u8, D::OutputSize>;

    fn hash_input(&self, input: &In) -> Self::HashOutput {
        let mut digest = Endian::<D, Bo>::default();
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
    use super::digest_hash::byteorder;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn hasher_hash_input() {
        let hasher = DigestHasher::<&'static [u8], BigEndian<Sha256>, byteorder::BigEndian>::default();
        let hash = hasher.hash_input(&TEST_DATA);
        assert_eq!(hash, Sha256::digest(TEST_DATA));
    }
}
