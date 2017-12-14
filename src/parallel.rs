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


#[derive(Clone, Debug, Default)]
pub struct Builder<D, L> {
    hasher: D,
    leaf_data_extractor: L
}

impl<D, In> Builder<D, leaf::NoData<In>>
where D: Default,
      D: Hasher<In> + Clone + Send,
      D::HashOutput: Send,
      In: Send
{
    pub fn new() -> Self {
        Builder {
            hasher: D::default(),
            leaf_data_extractor: leaf::no_data()
        }
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
                let mut builder = tree::Builder::from_hasher_leaf_data(
                            master.hasher.clone(),
                            master.leaf_data_extractor.clone());
                builder.push_leaf(input);
                builder.complete().unwrap()
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
        self.join(left, right)
    }

    fn join(
        self,
        left:  Vec<MerkleTree<D::HashOutput, L::LeafData>>,
        right: Vec<MerkleTree<D::HashOutput, L::LeafData>>
    ) -> MerkleTree<D::HashOutput, L::LeafData> {
        let left_builder = self.clone();
        let right_builder = self.clone();
        let (left_tree, right_tree) = rayon::join(
            move || { left_builder.reduce(left.into_par_iter()) },
            move || { right_builder.reduce(right.into_par_iter()) }
        );
        let mut builder = tree::Builder::from_hasher_leaf_data(
                    self.hasher,
                    self.leaf_data_extractor);
        builder.push_tree(left_tree);
        builder.push_tree(right_tree);
        builder.complete().unwrap()
    }
}
