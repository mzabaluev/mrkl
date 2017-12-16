// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use tree::Node;

use hash::NodeHasher;
use leaf;

pub trait FromNodes {
    type Hasher: NodeHasher;
    type LeafDataExtractor: leaf::ExtractData;

    fn from_nodes(
        hasher: Self::Hasher,
        leaf_data_extractor: Self::LeafDataExtractor,
        nodes: Vec<Node<<Self::Hasher as NodeHasher>::HashOutput,
                        <Self::LeafDataExtractor as leaf::ExtractData>::LeafData>>
    ) -> Self;
}
