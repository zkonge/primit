use primit::aead::{chacha20poly1305::Chacha20Poly1305, Aead, Decryptor, Encryptor};

#[test]
fn test_chacha20poly1305() {
    let key = [
        78, 124, 134, 194, 178, 159, 186, 121, 39, 150, 125, 52, 41, 43, 133, 188, 16, 113, 83,
        255, 47, 98, 231, 194, 142, 108, 49, 193, 59, 172, 221, 210,
    ];
    let nonce = [63, 143, 158, 193, 12, 74, 32, 200, 246, 116, 243, 3];
    let aad = [0, 0, 0, 0, 0, 0, 0, 0, 22, 3, 3, 0, 16];

    let mut data = [
        20, 0, 0, 12, 82, 176, 48, 66, 102, 149, 142, 132, 230, 204, 153, 206,
    ];
    let origin_data = data;

    let alg = Chacha20Poly1305::new(&key);
    let enc = alg.encryptor(&nonce, &aad);
    let mac = enc.finalize(&mut data);

    assert_eq!(
        &data,
        &[117, 99, 17, 144, 9, 64, 124, 90, 213, 214, 44, 59, 54, 152, 33, 165,]
    );
    assert_eq!(
        &mac,
        &[154, 213, 114, 86, 225, 115, 178, 58, 128, 128, 233, 241, 148, 121, 248, 25]
    );

    let dec = alg.decryptor(&nonce, &aad);
    assert!(dec.finalize(&mut data,&mac).is_ok());

    assert_eq!(data, origin_data);
}
