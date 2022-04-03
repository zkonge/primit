use primit::utils::hex::decode;

#[test]
fn test_decode() {
    const I: [u8; 32] = *b"d41d8cd98f00b204e9800998ecf8427e";
    const O: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
    ];
    let mut r = [0u8; 16];
    decode(&I, &mut r).unwrap();
    assert_eq!(r, O);
}
