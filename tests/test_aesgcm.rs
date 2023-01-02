use aes_gcm::{aead::AeadInPlace, aes::cipher::generic_array::GenericArray, Aes128Gcm, KeyInit};
use primit::{
    aead::{aesgcm::AESGCM, Aead, Decryptor, Encryptor},
    rng::{cprng::FastRng, Rng},
    utils::hex::decode_fix,
};

#[test]
fn test_aesgcm() {
    // Test  Case  1
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let aad = [0u8; 0];
    // let plaintext = [0u8; 0];
    let mut text = [0u8; 0];

    let alg = AESGCM::new(&key);
    let encryptor = alg.encryptor(&iv, &aad);
    let tag = encryptor.finalize(&mut text);
    assert_eq!(
        tag,
        [88, 226, 252, 206, 250, 126, 48, 97, 54, 127, 29, 87, 164, 231, 69, 90]
    );

    // Test  Case  2
    let key = [0u8; 16];
    let iv = [0u8; 12];
    let aad = [0u8; 0];
    let mut text = [0u8; 16];

    let alg = AESGCM::new(&key);
    let encryptor = alg.encryptor(&iv, &aad);
    let tag = encryptor.finalize(&mut text);

    assert_eq!(
        &text,
        &decode_fix::<16>(b"0388dace60b6a392f328c2b971b2fe78").unwrap()
    );

    assert_eq!(
        tag,
        decode_fix::<16>(b"ab6e47d42cec13bdf53a67b21257bddf").unwrap()
    );
}

#[test]
fn test_aesgcm_fuzz() {
    fn tester(key: &[u8; 16], nonce: &[u8; 12], ad: &[u8], text: &[u8]) {
        let alg = AESGCM::new(key);
        let std_alg = Aes128Gcm::new(GenericArray::from_slice(key));

        // test encrypt
        let enc = alg.encryptor(nonce, ad);

        let mut data = text.to_vec();
        let tag = enc.finalize(&mut data);

        let mut std_data = text.to_vec();
        let std_tag = std_alg
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), ad, &mut std_data)
            .unwrap();

        assert_eq!(&data, &std_data);
        assert_eq!(tag.as_slice(), std_tag.as_slice());

        // test decrypt
        let dec = alg.decryptor(nonce, ad);

        dec.finalize(&mut data, &tag).unwrap();

        std_alg
            .decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                ad,
                &mut std_data,
                GenericArray::from_slice(tag.as_slice()),
            )
            .unwrap();

        assert_eq!(data, std_data);
    }

    let mut rng = FastRng::new_from_seed(&[0u8; 32]);

    for _ in 0..1000 {
        let mut key = [0u8; 16];
        let mut nonce = [0u8; 12];
        let mut ad = [0u8; 64];
        let mut text = [0u8; 64];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut ad);
        rng.fill_bytes(&mut text);

        // tester(&key, &nonce, &ad[..0], &text[..0]);
        // tester(&key, &nonce, &ad[..0], &text[..32]);
        tester(&key, &nonce, &ad[..0], &text[..47]);

        tester(&key, &nonce, &ad[..47], &text[..0]);
        tester(&key, &nonce, &ad[..47], &text[..32]);
        tester(&key, &nonce, &ad[..47], &text[..47]);

        tester(&key, &nonce, &ad, &text);
    }
}
