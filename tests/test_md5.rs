use primit::{
    hash::md5::{md5, MD5},
    hash::Digest,
    utils::hex::decode,
};
use rand::{rngs, SeedableRng, Rng};

#[test]
fn test_md5() {
    let inputs = [
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "0123456789012345678901234567890123456789012345678901234567890123",
        "1234567890123456789012345678901234567890123456789012345678901234",
        "12345678901234567890123456789012345678901234567890123456789012345",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    ];
    let outputs = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72",
        "f96b697d7cb7938d525a2f31aaf161d0",
        "c3fcd3d76192e4007dfb496cca67e13b",
        "d174ab98d277d9f5a5611c2c9f419d9f",
        "7f7bfd348709deeaace19e3f535f8c54",
        "eb6c4179c0a7c82cc2828c1e6338e165",
        "823cc889fc7318dd33dde0654a80b70a",
        "57edf4a22be3c955ac49da2e2107b67a",
    ];
    for (input, &output) in inputs.iter().zip(outputs.iter()) {
        let mut output_bytes = [0u8; MD5::LENGTH];
        decode(output.as_bytes(), &mut output_bytes).unwrap();

        let hash = md5(input.as_bytes());

        assert_eq!(hash, output_bytes);
    }
}

#[test]
fn test_md5_fuzz() {
    use md5::Digest;

    let mut rng = rngs::StdRng::seed_from_u64(0);
    let mut input = [0u8; 256];
    for l in 0..input.len() {
        for _ in 0..50 {
            rng.fill(&mut input[..l]);

            let mut h = md5::Md5::new();
            h.update(&input[..l]);

            let output = md5(&input[..l]);

            assert_eq!(h.finalize().as_slice(), &output);
        }
    }
}
