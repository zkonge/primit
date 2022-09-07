use primit::utils::hex::{decode, encode};

#[test]
fn test_encode() {
    let input: [u8; 28] = (0..28).collect::<Vec<_>>().try_into().unwrap();
    let output: [u8; 56] = *b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b";
    let mut d = [0u8; 56];
    encode(&mut d, &input).unwrap();
    assert_eq!(d, output);
}

#[test]
fn test_decode() {
    let input: [u8; 56] = *b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b";
    let output: [u8; 28] = (0..28).collect::<Vec<_>>().try_into().unwrap();
    let mut d = [0u8; 28];
    decode(&mut d, &input).unwrap();
    assert_eq!(d, output);
}
