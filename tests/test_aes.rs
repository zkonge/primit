use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use primit::{
    rng::{cprng::FastRng, Rng},
    symmetry::aes::AES128,
};

#[test]
fn test_encrypt() {
    let mut rng = FastRng::new_from_seed(&[0u8; 32]);
    let mut input = [0u8; 16];
    let mut key = [0u8; 16];
    for _ in 0..1000 {
        rng.fill_bytes(&mut input);
        rng.fill_bytes(&mut key);
        let mut output = input;

        let cipher = AES128::new(&key);
        cipher.encrypt(&mut output);

        let std_cipher = Aes128::new_from_slice(&key).unwrap();
        std_cipher.decrypt_block((&mut output).into());

        assert_eq!(input, output);
    }
}

#[test]
fn test_decrypt() {
    let mut rng = FastRng::new_from_seed(&[0u8; 32]);
    let mut input = [0u8; 16];
    let mut key = [0u8; 16];
    for _ in 0..1000 {
        let mut output = input;

        let std_cipher = Aes128::new_from_slice(&key).unwrap();
        std_cipher.encrypt_block((&mut output).into());

        let cipher = AES128::new(&key);
        cipher.decrypt(&mut output);

        assert_eq!(input, output);

        rng.fill_bytes(&mut input);
        rng.fill_bytes(&mut key);
        dbg!(input);
    }
}
