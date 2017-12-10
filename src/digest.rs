// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use hash::{/* Hash, */ Hasher};
use leaf;
use tree::{Nodes, Node};

extern crate digest;
extern crate byteorder;

use self::byteorder::{ByteOrder, BigEndian, LittleEndian, NetworkEndian};
use self::digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem;


macro_rules! for_all_mi_primitives {
    (T, method, bo_func : $macro:ident!(T, method, bo_func)) => {
        $macro!(u16, process_u16, write_u16);
        $macro!(i16, process_i16, write_i16);
        $macro!(u32, process_u32, write_u32);
        $macro!(i32, process_i32, write_i32);
        $macro!(u64, process_u64, write_u64);
        $macro!(i64, process_i64, write_i64);
        $macro!(f32, process_f32, write_f32);
        $macro!(f64, process_f64, write_f64);
    }
}

macro_rules! endian_method {
    ($t:ty, $name:ident, $bo_func:ident) => {
        fn $name(&mut self, n: $t) {
            let mut buf: [u8; mem::size_of::<$t>()]
                         = unsafe { mem::uninitialized() };
            Bo::$bo_func(&mut buf, n);
            self.process(&buf);
        }
    }
}

pub trait EndianInput<Bo> : digest::Input
    where Bo: ByteOrder
{

    fn process_u8(&mut self, n: u8) {
        self.process(&[n]);
    }

    fn process_i8(&mut self, n: i8) {
        self.process(&[n as u8]);
    }

    for_all_mi_primitives!(T, method, bo_func:
                           endian_method!(T, method, bo_func));
}

// Insta-impl for all digest functions
impl<T> EndianInput<LittleEndian> for T where T: digest::Input {}
impl<T> EndianInput<BigEndian> for T where T: digest::Input {}

pub trait Hash {
    fn hash<H, Bo>(&self, digest: &mut H)
        where H: EndianInput<Bo>,
              Bo: ByteOrder;
}

macro_rules! impl_hash_for {
    {
        ($self:ident: &$t:ty, $digest:ident) $body:block
    } => {
        impl Hash for $t {
            fn hash<H, Bo>(&$self, $digest: &mut H)
                where H: EndianInput<Bo>,
                      Bo: ByteOrder
            $body
        }
    }
}

macro_rules! impl_hash_for_primitive {
    ($t:ty, $method:ident, $_bo_func:ident) => {
        impl_hash_for! {
            (self: &$t, digest) {
                digest.$method(*self);
            }
        }
    }
}

for_all_mi_primitives!(T, method, bo_func:
                       impl_hash_for_primitive!(T, method, bo_func));

impl<'a, T: ?Sized> Hash for &'a T
    where T: Hash
{
    fn hash<H, Bo>(&self, digest: &mut H)
        where H: EndianInput<Bo>,
              Bo: ByteOrder
    {
        (*self).hash::<H, Bo>(digest);
    }
}

impl_hash_for! {
    (self: &[u8], digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &Box<[u8]>, digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &Vec<u8>, digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &str, digest) {
        digest.process(self.as_bytes());
    }
}

impl_hash_for! {
    (self: &Box<str>, digest) {
        digest.process(self.as_bytes());
    }
}

impl_hash_for! {
    (self: &String, digest) {
        digest.process(self.as_bytes());
    }
}

#[derive(Copy, Clone)]
pub struct DigestHasher<D, F, Bo: ByteOrder = NetworkEndian> {
    leaf_data_extractor: F,
    phantom: PhantomData<(D, Bo)>
}

impl<D, F, Bo> Debug for DigestHasher<D, F, Bo>
    where F: Debug,
          Bo: ByteOrder
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        // Do a bit of runtime testing.
        let mut buf = [0u8; 2];
        Bo::write_u16(&mut buf, 0x0100);
        let endianness = match buf[1] {
            0x01 => "BigEndian",
            0x00 => "LittleEndian",
            _ => unreachable!()
        };

        f.debug_struct("DigestHasher")
         .field("leaf_data_extractor", &self.leaf_data_extractor)
         .field("byte_order", &endianness)
         .finish()
    }
}

impl<D, F, Bo> DigestHasher<D, F, Bo>
    where F: leaf::ExtractData,
          F: Default,
          Bo: ByteOrder
{
    pub fn new() -> DigestHasher<D, F, Bo> {
        DigestHasher {
            leaf_data_extractor: F::default(),
            phantom: PhantomData
        }
    }
}

impl<D, F, Bo> DigestHasher<D, F, Bo>
    where F: leaf::ExtractData,
          Bo: ByteOrder
{
    pub fn with_leaf_data(extractor: F) -> DigestHasher<D, F, Bo> {
        DigestHasher {
            leaf_data_extractor: extractor,
            phantom: PhantomData
        }
    }
}

impl<D, F, Bo> Hasher for DigestHasher<D, F, Bo>
    where Bo: ByteOrder,
          D: EndianInput<Bo>,
          D: digest::FixedOutput,
          D: Default,
          F: leaf::ExtractData,
          F::Input: Hash
{
    type Input = F::Input;
    type HashOutput = GenericArray<u8, D::OutputSize>;
    type LeafData = F::Output;

    fn hash_data(&self, input: Self::Input)
                 -> (Self::HashOutput, Self::LeafData)
    {
        let mut hasher = D::default();
        input.hash(&mut hasher);
        let hash = hasher.fixed_result();
        let data = self.leaf_data_extractor.extract_data(input);
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
