// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use tree::Nodes;


pub trait Hasher {
    type Input;
    type HashOutput;
    type LeafData;

    fn hash_data(&self, input: Self::Input)
                 -> (Self::HashOutput, Self::LeafData);

    fn hash_nodes<'a>(&'a self,
                      iter: Nodes<'a, Self::HashOutput, Self::LeafData>)
                      -> Self::HashOutput;
}
