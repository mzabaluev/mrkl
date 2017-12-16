// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Facilities for extracting leaf data.
//!
//! Merkle trees are not generally used to own the data they provide
//! hashing for, but information derived from input may need to be
//! associated with leaf nodes. The trait `ExtractData` and its
//! implementations provide versatile ways of retrieving leaf node data.

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;

/// A way to extract data for leaf nodes of a Merkle tree.
pub trait ExtractData {

    /// The type of input data.
    type Input;

    /// The type of data stored in the leaf nodes.
    type LeafData;

    /// The extraction method for leaf data.
    fn extract_data(&self, input: Self::Input) -> Self::LeafData;
}

/// Used to build a no-data Merkle tree.
///
/// Trees built with this extractor contain only hashes in their leaf
/// nodes; the `data()` method of their `LeafNode` values returns the
/// empty unit value.
pub struct NoData<In> {
    marker: PhantomData<In>
}

impl<In> Default for NoData<In> {
    fn default() -> Self {
        NoData { marker: PhantomData }
    }
}

impl<In> Clone for NoData<In> {
    fn clone(&self) -> Self {
        NoData::default()
    }
}

impl<In> Debug for NoData<In> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("NoData")
    }
}

impl<In> ExtractData for NoData<In> {
    type Input = In;
    type LeafData = ();
    fn extract_data(&self, _: In) -> () { () }
}

/// Used to build a Merkle tree owning its input data.
///
/// Trees built with this extractor own the values passed as leaf
/// input. The `data()` method of their `LeafNode` values returns
/// a reference to the owned value.
pub struct Owned<T> {
    marker: PhantomData<T>
}

impl<T> Default for Owned<T> {
    fn default() -> Self { Owned { marker: PhantomData } }
}

impl<T> Clone for Owned<T> {
    fn clone(&self) -> Self {
        Owned::default()
    }
}

impl<T> Debug for Owned<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("Owned")
    }
}

impl<T> ExtractData for Owned<T> {
    type Input = T;
    type LeafData = T;
    fn extract_data(&self, input: T) -> T { input }
}

/// An adapter structure used to fit closures to extract leaf node data.
///
/// This is a type system fix for using arbitrary `Fn` closures to extract
/// leaf node data from input values.
///
/// This extractor cannot be used for building trees with the
/// `complete_tree_from()` method of both sequential and parallel
/// `Builder` types, since these impose a `Clone` bound on the extractor.
/// Use the `extract_with()` helper function provided by this module
/// to extract leaf data with plain functions, including closure expressions
/// without variable captures that can be converted to an `fn` type.
pub struct ExtractFn<In, F> {
    extractor: F,
    phantom: PhantomData<In>
}

impl<In, F> Debug for ExtractFn<In, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.write_str("ExtractFn")
    }
}

impl<In, F, Out> ExtractFn<In, F>
    where F: Fn(In) -> Out
{
    /// Create an instance of the extractor wrapping the closure
    /// passed as the parameter.
    pub fn with(extractor: F) -> Self {
        ExtractFn { extractor, phantom: PhantomData }
    }
}

impl<In, F, Out> ExtractData for ExtractFn<In, F>
    where F: Fn(In) -> Out
{
    type Input = In;
    type LeafData = Out;
    fn extract_data(&self, input: In) -> Out {
        (self.extractor)(input)
    }
}

impl<In, Out> ExtractData for fn(In) -> Out {
    type Input = In;
    type LeafData = Out;
    fn extract_data(&self, input: In) -> Out {
        self(input)
    }
}

/// A helper function to create instances of `NoData`
/// with a more concise syntax.
pub fn no_data<In>() -> NoData<In> {
    NoData::default()
}

/// A helper function to create instances of `Owned`
/// with a more concise syntax.
pub fn owned<In>() -> Owned<In> {
    Owned::default()
}

/// A helper function to create function-based leaf data extractors.
///
/// Usage of this function ensures that the return value can be used
/// to build trees with `Builder::build_balanced_with()`. A closure
/// expression passed as the parameter is converted to an unnamed
/// plain function.
///
/// For incrementally built trees, the `ExtractFn` extractor type is
/// available that wraps arbitrary `Fn` closures.
pub fn extract_with<In, Out>(extractor: fn(In) -> Out)
                             -> fn(In) -> Out {
    extractor
}

#[cfg(test)]
mod tests {
    use super::{no_data, owned, extract_with};

    #[derive(Debug)]
    struct NonCloneable;

    #[test]
    fn no_data_is_cloneable() {
        let extractor = no_data::<NonCloneable>();
        let _ = extractor.clone();
    }

    #[test]
    fn owned_is_always_cloneable() {
        let extractor = owned::<NonCloneable>();
        let _ = extractor.clone();
    }

    #[test]
    fn result_of_extract_with_is_cloneable() {
        let _capture = NonCloneable;
        let extractor = extract_with(
            |s: &'static [u8]| {
                // This breaks the test:
                //let _ = format!("{:?}", _capture);
                s.len()
            });
        let _ = extractor.clone();
    }
}
