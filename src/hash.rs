// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The abstraction of the hash algorithm for Merkle trees.

use tree::Nodes;

/// A hash algorithm implementation for a Merkle tree.
///
/// The abstraction provided by `Hasher` is generic over the input data type,
/// agnostic to the implementation of the hash function, and allows different
/// ways of calculating the hash of child nodes for their parent node.
pub trait Hasher<In: ?Sized> {

    /// The output of the hash function.
    type HashOutput;

    /// Hash an element of the input data.
    ///
    /// This method is used to calculate hash values of the leaf nodes
    /// in the Merkle tree under construction.
    fn hash_input(&self, input: &In) -> Self::HashOutput;

    /// Hash a sequence of child nodes to produce the parent hash value.
    ///
    /// This method is used to calculate hash values of the non-leaf nodes
    /// in the Merkle tree under construction.
    fn hash_nodes<'a, L>(&'a self,
                         iter: Nodes<'a, Self::HashOutput, L>)
                         -> Self::HashOutput;
}
