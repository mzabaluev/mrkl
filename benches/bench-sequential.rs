#![feature(test)]

extern crate test;

extern crate mrkl;

#[cfg(feature = "digest-hash")]
mod digest {
    extern crate sha2;
    extern crate digest_hash;

    use test;
    use test::Bencher;

    use mrkl::tree::Builder;
    use mrkl::digest::ByteDigestHasher;
    use self::sha2::Sha256;
    use self::sha2::Digest;
    use self::digest_hash::digest::generic_array::GenericArray;

    use std::iter;

    type Hasher = ByteDigestHasher<Sha256>;

    #[bench]
    fn pure_digest_perf_100x4k(b: &mut Bencher) {
        let block: &[u8] = &[0u8; 4 * 1024];

        b.iter(|| {
            let mut hash = GenericArray::default();
            for _ in 0 .. 100 {
                hash = Sha256::digest(block);
                hash = test::black_box(hash);
            }
            for _ in 0 .. 100 - 1 {
                let mut digest = Sha256::new();
                digest.input(&[0u8][..]);
                digest.input(&hash);
                digest.input(&[0u8][..]);
                digest.input(&hash);
                hash = digest.result();
                hash = test::black_box(hash);
            }
        })
    }

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
