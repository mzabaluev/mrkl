// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use hash::{Hasher, NodeHasher};
use tree::{Nodes, Node};

#[derive(Clone, Debug, Default)]
pub struct MockHasher;

impl<In: AsRef<[u8]>> Hasher<In> for MockHasher {
    fn hash_input(&self, input: &In) -> Vec<u8> {
        input.as_ref().to_vec()
    }
}

impl NodeHasher for MockHasher {

    type HashOutput = Vec<u8>;

    fn hash_nodes<'a, L>(&'a self,
                         iter: Nodes<'a, Vec<u8>, L>)
                         -> Vec<u8>
    {
        let mut dump = Vec::new();
        for node in iter {
            match *node {
                Node::Leaf(ref ln) => {
                    dump.push(b'>');
                    dump.extend(ln.hash_bytes());
                }
                Node::Hash(ref hn) => {
                    dump.extend(b"#(");
                    dump.extend(hn.hash_bytes());
                    dump.extend(b")");
                }
            }
        }
        dump
    }
}

