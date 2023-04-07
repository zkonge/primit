use md5::{Digest, Md5};
use primit::{
    hash::md5::md5,
    rng::{FastRng, Rng},
};

#[test]
fn test_md5() {
    let mut input = [0u8; 512];
    let mut rng = FastRng::new_from_seed(&[0u8; 32]);

    for l in 0..input.len() {
        rng.fill_bytes(&mut input[..l]);

        let mut std_digest = Md5::new();
        std_digest.update(&input[..l]);
        let output = std_digest.finalize();

        assert_eq!(&md5(&input[..l]), output.as_slice());
    }
}
