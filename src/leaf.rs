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

pub trait ExtractData {
    type Input;
    type Output;
    fn extract_data(&self, input: Self::Input) -> Self::Output;
}

#[derive(Copy, Clone, Default)]
pub struct NoData<In> {
    phantom: PhantomData<In>
}

impl<In> Debug for NoData<In> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("NoData")
    }
}

impl<In> ExtractData for NoData<In> {
    type Input = In;
    type Output = ();
    fn extract_data(&self, _: In) -> () { () }
}

#[derive(Copy, Clone, Default)]
pub struct Owned<T> {
    phantom: PhantomData<T>
}

impl<T> Debug for Owned<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("Owned")
    }
}

impl<T> ExtractData for Owned<T> {
    type Input = T;
    type Output = T;
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

impl<In, F, Out> ExtractData for ExtractFn<In, F>
    where F: Fn(In) -> Out
{
    type Input = In;
    type Output = Out;
    fn extract_data(&self, input: In) -> Out {
        (self.extractor)(input)
    }
}

pub fn extract_with<In, F, Out>(extractor: F) -> ExtractFn<In, F>
    where F: Fn(In) -> Out
{
    ExtractFn { extractor, phantom: PhantomData }
}
