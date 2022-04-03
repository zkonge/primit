use primit::{hash::sha256::sha256, utils::hex::encode_fix};
use rand::{rngs, Rng, SeedableRng};

#[test]
fn test_sha256() {
    let input: [&[u8]; 6] = [
        b"",
        b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        &[0u8; 64],
        &[0u8; 1024],
        &[0u8; 65],
    ];
    let output = [
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        b"f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        b"5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
        b"98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7",
    ];

    for (i, o) in input.iter().zip(output) {
        let r = encode_fix(&sha256(i));
        assert_eq!(&r, o);
    }
}

#[test]
fn test_sha256_fuzz() {
    use sha2::Digest;

    let mut rng = rngs::StdRng::seed_from_u64(0);
    let mut input = [0u8; 256];
    for l in 0..input.len() {
        for _ in 0..50 {
            rng.fill(&mut input[..l]);

            let mut h = sha2::Sha256::new();
            h.update(&input[..l]);

            let output = sha256(&input[..l]);

            assert_eq!(h.finalize().as_slice(), &output);
        }
    }
}
