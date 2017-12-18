# Generic Merkle Tree

This crate provides a generic, composable, and parallelizable way to
construct Merkle trees, also known as hash trees, from input data.
The basic design is agnostic to the choice of the hashing algorithm,
the type of input data, and what information derived from the input
gets stored inside leaf nodes.

## Design assumptions

* Merkle trees are normally built once when the hashed content is
  "sealed". Appending to a previously calculated tree is only done by adding
  new levels on top of the sealed tree root. An application design that needs
  to repeatedly recalculate a Merkle tree over variable content has
  questionable usefulness and efficiency. Therefore, the data structures
  representing fully constructed trees can be made immutable.

* Merkle trees are not generally used to contain the hashed input data.
  However, some information about the input may need to be stored in the
  leaf nodes. Therefore, the design should provide flexible choices for
  leaf data extraction, including trees without leaf data and
  trees taking ownership of the input as leaf data.

* The application should have a choice in the hashing algorithm that is
  not restricted to a particular digest API. The Rust Crypto project's API,
  however, should be supported out of the box.

* The application should have flexibility in how the hash over child nodes
  is calculated for their parent node. The popular way of prepending a byte
  value distinguishing a leaf node from a non-leaf node, to protect against
  second-preimage attacks, can be provided by default.

* Building both left-filled, uniform-leaf-depth binary trees permitting
  single-child rightmost internal nodes (as in Bitcoin), and full, but not
  necessarily balanced binary trees (as in Certificate Transparency),
  should be supported as primary use cases.

* Calculation of Merkle trees is eminently parallelizable, so an
  implementation using a work-stealing thread pool should be provided
  as an optional feature.

## Design notes

The design uses the builder pattern to separate the Merkle tree data model,
which is immutable, from various construction facilities that are represented
by `tree::Builder`, `tree::parallel::Builder`, and related types.

## Future additions

Verification trees consisting only of hashes, used to verify integrity of
content retrieved separately, can be thought of as a special case of
`MerkleTree` with hash values for input. The API should provide the ability
to verify a tree built from content against its verification counterpart
obtained elsewhere, which may not have the same depth. This is not implemented
yet.

The input to make a leaf node cannot yet be provided incrementally. There is
an idea how to implement this in an elegant way.

An extension can be provided to build trees from iterated input where
data to hash is delivered multiplexed alongside the values to store as
leaf data (like in the item values of `std::iter::Enumerate`).

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
