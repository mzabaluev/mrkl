// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

pub trait ExtractData<In> {
    type LeafData;
    fn extract_data(&self, input: In) -> Self::LeafData;
}

#[derive(Copy, Clone)]
pub struct NoData<In> {
    phantom: PhantomData<In>
}

impl<In> Debug for NoData<In> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("NoData")
    }
}

impl<In> Default for NoData<In> {
    fn default() -> Self { NoData { phantom: PhantomData } }
}

impl<In> ExtractData<In> for NoData<In> {
    type LeafData = ();
    fn extract_data(&self, _: In) -> () { () }
}

#[derive(Copy, Clone)]
pub struct Owned<T> {
    phantom: PhantomData<T>
}

impl<T> Debug for Owned<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("Owned")
    }
}

impl<T> Default for Owned<T> {
    fn default() -> Self { Owned { phantom: PhantomData } }
}

impl<T> ExtractData<T> for Owned<T> {
    type LeafData = T;
    fn extract_data(&self, input: T) -> T { input }
}

pub struct ExtractFn<In, F> {
    extractor: F,
    phantom: PhantomData<In>
}

impl<In, F> Debug for ExtractFn<In, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("ExtractFn")
    }
}

impl<In, F, Out> ExtractData<In> for ExtractFn<In, F>
    where F: Fn(In) -> Out
{
    type LeafData = Out;
    fn extract_data(&self, input: In) -> Out {
        (self.extractor)(input)
    }
}

pub fn no_data<In>() -> NoData<In> {
    NoData::default()
}

pub fn owned<In>() -> Owned<In> {
    Owned::default()
}

pub fn extract_with<In, F, Out>(extractor: F) -> ExtractFn<In, F>
    where F: Fn(In) -> Out
{
    ExtractFn { extractor, phantom: PhantomData }
}
