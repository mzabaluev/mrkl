// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub extern crate rayon;

use self::rayon::prelude::*;
use self::rayon::iter::Either;

use hash::Hasher;
use leaf;
use tree;
use tree::{MerkleTree, EmptyTree};
use super::plumbing::BuilderNodes;


#[derive(Clone, Debug, Default)]
pub struct Builder<D, L> {
    hasher: D,
    leaf_data_extractor: L
}

impl<D, In> Builder<D, leaf::NoData<In>>
where D: Default,
      D: Hasher<In>
{
    pub fn new() -> Self {
        Builder {
            hasher: D::default(),
            leaf_data_extractor: leaf::no_data()
        }
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData
{
    pub fn from_hasher_leaf_data(hasher: D, leaf_data_extractor: L) -> Self {
        Builder { hasher, leaf_data_extractor }
    }

    fn into_serial_builder(self) -> tree::Builder<D, L> {
        tree::Builder::from_hasher_leaf_data(
            self.hasher,
            self.leaf_data_extractor)
    }

    fn into_n_ary_serial_builder(self, n: usize) -> tree::Builder<D, L> {
        tree::Builder::n_ary_from_hasher_leaf_data(
            n,
            self.hasher,
            self.leaf_data_extractor)
    }

    pub fn into_leaf(
        self,
        input: L::Input
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let mut builder = self.into_n_ary_serial_builder(1);
        builder.push_leaf(input);
        builder.complete().unwrap()
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input> + Clone + Send,
      L: leaf::ExtractData + Clone + Send,
      D::HashOutput: Send,
      L::Input: Send,
      L::LeafData: Send
{
    pub fn build_balanced_from<I>(
        self,
        iterable: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IntoParallelIterator<Item = L::Input>,
          I::Iter: IndexedParallelIterator,
    {
        self.build_balanced_from_iter(iterable.into_par_iter())
    }

    fn build_balanced_from_iter<I>(
        self,
        mut iter: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IndexedParallelIterator<Item = L::Input> {
        if iter.len() == 0 {
            return Err(EmptyTree);
        }
        let leaves =
            iter.map_with(self.clone(), |master, input| {
                master.clone().into_leaf(input)
            });
        Ok(self.reduce(leaves))
    }

    fn reduce<I>(
        self,
        mut iter: I
    ) -> MerkleTree<D::HashOutput, L::LeafData>
    where I: IndexedParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>> {
        let len = iter.len();
        debug_assert!(len != 0);
        if len == 1 {
            return iter.reduce_with(|_, _| {
                    unreachable!("more than one item left in a parallel \
                                  iterator that reported length 1")
                })
                .expect("a parallel iterator that reported length 1 \
                         has come up empty");
        }
        let left_len = len.saturating_add(1) / 2;
        let (left, right) = iter.enumerate()
            .partition_map::<Vec<_>, Vec<_>, _, _, _>(|(i, node)| {
                if i < left_len {
                    Either::Left(node)
                } else {
                    Either::Right(node)
                }
            });
        self.reduce_and_join_parts(left, right)
    }

    fn reduce_and_join_parts(
        self,
        left:  Vec<MerkleTree<D::HashOutput, L::LeafData>>,
        right: Vec<MerkleTree<D::HashOutput, L::LeafData>>
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let left_builder = self.clone();
        let right_builder = self.clone();
        self.join(
            move || { left_builder.reduce(left.into_par_iter()) },
            move || { right_builder.reduce(right.into_par_iter()) }
        )
    }
}

impl<D, L> Builder<D, L>
where D: Hasher<L::Input>,
      L: leaf::ExtractData,
      D::HashOutput: Send,
      L::LeafData: Send
{
    pub fn join<LF, RF>(
        self,
        left: LF,
        right: RF
    ) -> MerkleTree<D::HashOutput, L::LeafData>
    where LF: FnOnce() -> MerkleTree<D::HashOutput, L::LeafData> + Send,
          RF: FnOnce() -> MerkleTree<D::HashOutput, L::LeafData> + Send
    {
        let (left_tree, right_tree) = rayon::join(left, right);
        let mut builder = self.into_serial_builder();
        builder.push_tree(left_tree);
        builder.push_tree(right_tree);
        builder.complete().unwrap()
    }

    pub fn collect_nodes_from<I>(
        self,
        iterable: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: IntoParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>>
    {
        self.collect_nodes_from_iter(iterable.into_par_iter())
    }

    fn collect_nodes_from_iter<I>(
        self,
        iter: I
    ) -> Result<MerkleTree<D::HashOutput, L::LeafData>, EmptyTree>
    where I: ParallelIterator<Item = MerkleTree<D::HashOutput, L::LeafData>>
    {
        // TODO: once specialization is stabilized, utilize
        // .collect_into() with indexed iterators.
        let mut nodes: Vec<_> =
            iter.map(|tree| {
                tree.root
            })
            .collect();
        let mut builder = self.into_n_ary_serial_builder(nodes.len());
        builder.append_nodes(&mut nodes);
        builder.complete()
    }
}

#[cfg(test)]
mod tests {
    use super::Builder;

    use super::rayon::prelude::*;
    use super::rayon::iter;

    use leaf;
    use tree::Node;
    use super::super::testmocks::MockHasher;

    const TEST_DATA: &'static [u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn build_balanced_from_empty() {
        let builder = Builder::<MockHasher, _>::new();
        builder.build_balanced_from(iter::empty::<[u8; 1]>()).unwrap_err();
    }

    #[test]
    fn build_balanced_leaf() {
        let builder = Builder::<MockHasher, _>::new();
        let iter = iter::repeatn(TEST_DATA, 1);
        let tree = builder.build_balanced_from(iter).unwrap();
        if let Node::Leaf(ref ln) = *tree.root() {
            assert_eq!(ln.hash_bytes(), TEST_DATA);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn build_balanced_tree() {
        let builder = Builder::<MockHasher, _>::new();
        let data: Vec<_> = TEST_DATA.chunks(15).collect();
        let tree = builder.build_balanced_from(data).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            let expected: &[u8] = b"#(>The quick brown> fox jumps over)\
                                    > the lazy dog";
            assert_eq!(hn.hash_bytes(), expected);
        } else {
            unreachable!()
        }
    }

    const TEST_STRS: [&'static str; 3] = [
        "Panda eats,",
        "shoots,",
        "and leaves."];

    #[test]
    fn collect_nodes_for_arbitrary_arity_tree() {
        let iter =
            TEST_STRS.into_par_iter().map(|input| {
                let builder = Builder::<MockHasher, _>::new();
                builder.into_leaf(input)
            });
        let builder = Builder::<MockHasher, leaf::NoData<&'static str>>::new();
        let tree = builder.collect_nodes_from(iter).unwrap();
        if let Node::Hash(ref hn) = *tree.root() {
            assert_eq!(hn.hash_bytes(), b">Panda eats,>shoots,>and leaves.");
            let mut peek_iter = hn.children().peekable();
            assert!(peek_iter.peek().is_some());
            for (i, child) in peek_iter.enumerate() {
                if let Node::Leaf(ref ln) = *child {
                    assert_eq!(ln.hash_bytes(), TEST_STRS[i].as_bytes());
                } else {
                    unreachable!()
                }
            }
        } else {
            unreachable!()
        }
    }
}
