#![feature(test)]

extern crate test;

extern crate mrkl;

#[cfg(feature = "digest-hash")]
mod digest {
    extern crate sha2;

    use test;
    use test::Bencher;

    use mrkl::tree::Builder;
    use mrkl::digest::ByteDigestHasher;
    use self::sha2::Sha256;

    use std::iter;

    type Hasher = ByteDigestHasher<Sha256>;

    #[bench]
    fn build_balanced_100x4k(b: &mut Bencher) {
        let block: &[u8] = &[0u8; 4 * 1024];
        let seq: Vec<_> = iter::repeat(block).take(100).collect();
        b.iter(|| {
            let builder = Builder::<Hasher, _, _>::new();
            let tree = builder.build_balanced_from(&seq).unwrap();
            test::black_box(tree);
        })
    }
}
