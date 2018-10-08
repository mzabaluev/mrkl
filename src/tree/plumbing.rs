// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use tree::{BuildResult, Node};

pub trait FromNodes {
    type HashOutput;
    type LeafData;

    fn tree_from_nodes(
        &self,
        nodes: Vec<Node<Self::HashOutput, Self::LeafData>>,
    ) -> BuildResult<Self::HashOutput, Self::LeafData>;
}
