#![feature(test)]

extern crate test;

extern crate mrkl;

#[cfg(feature = "digest")]
mod digest {
    extern crate sha2;
    extern crate digest_hash;

    mod prelude {
        pub use test::Bencher;
        pub use test::black_box;

        pub use mrkl::digest::ByteDigestHasher;
        pub use super::sha2::Sha256;
        pub use super::sha2::Digest;
        pub use super::digest_hash::digest::generic_array::GenericArray;

        pub type Hasher = ByteDigestHasher<Sha256>;
    }

    mod sequential {
        use super::prelude::*;

        use mrkl::tree::Builder;

        use std::iter;

        #[bench]
        fn pure_digest_perf_100x4k(b: &mut Bencher) {
            let block: &[u8] = &[0u8; 4 * 1024];

            b.iter(|| {
                let mut hash = GenericArray::default();
                for _ in 0 .. 100 {
                    hash = Sha256::digest(block);
                    hash = black_box(hash);
                }
                for _ in 0 .. 100 - 1 {
                    let mut digest = Sha256::new();
                    digest.input(&[0u8][..]);
                    digest.input(&hash);
                    digest.input(&[0u8][..]);
                    digest.input(&hash);
                    hash = digest.result();
                    hash = black_box(hash);
                }
            })
        }

        #[bench]
        fn complete_tree_100x4k(b: &mut Bencher) {
            let block: &[u8] = &[0u8; 4 * 1024];
            let seq: Vec<_> = iter::repeat(block).take(100).collect();
            b.iter(|| {
                let builder = Builder::<Hasher, _>::new();
                let tree = builder.complete_tree_from(&seq).unwrap();
                black_box(tree);
            })
        }
    }

    #[cfg(feature = "parallel")]
    mod parallel {
        extern crate rayon;

        use super::prelude::*;

        use mrkl::tree::parallel::Builder;

        use self::rayon::iter;

        #[bench]
        fn complete_tree_100x4k(b: &mut Bencher) {
            let block: &[u8] = &[0u8; 4 * 1024];
            b.iter(|| {
                let iter = iter::repeatn(block, 100);
                let builder = Builder::<Hasher, _>::new();
                let tree = builder.complete_tree_from(iter).unwrap();
                black_box(tree);
            })
        }
    }
}
