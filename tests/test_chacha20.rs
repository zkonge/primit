use chacha20::cipher::{KeyIvInit, StreamCipher};
use primit::{
    rng::{FastRng, Rng},
    symmetry::chacha::ChaCha20,
};

#[test]
fn test_chacha20() {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut rng = FastRng::new_from_seed(&[0u8; 32]);

    for _ in 0..1000 {
        let mut d = [0u8; 1024];

        let mut std_cipher = chacha20::ChaCha20::new(&key.into(), &nonce.into());
        std_cipher.apply_keystream(&mut d[..233]);
        std_cipher.apply_keystream(&mut d[233..]);

        let mut cipher = ChaCha20::new(&key, &nonce);
        cipher.apply(&mut d[..233]);
        cipher.apply(&mut d[233..]);

        assert_eq!(d, [0u8; 1024]);

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
    }
}
