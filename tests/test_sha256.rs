use md5::Digest;
use primit::{
    hash::sha256::sha256,
    rng::{cprng::FastRng, Rng},
};
use sha2::Sha256;

#[test]
fn test_sha256_fuzz() {
    let mut input = [0u8; 512];
    let mut rng = FastRng::new_from_seed(&[0u8; 32]);

    for l in 0..input.len() {
        rng.fill_bytes(&mut input[..l]);

        let mut std_digest = Sha256::new();
        std_digest.update(&input[..l]);
        let output = std_digest.finalize();

        assert_eq!(&sha256(&input[..l]), output.as_slice());
    }
}
