use poly1305::{
    universal_hash::{KeyInit, UniversalHash},
    Poly1305,
};
use primit::mac::poly1305::poly1305;

fn std_poly1305(key: &[u8], data: &[u8]) -> [u8; poly1305::BLOCK_SIZE] {
    let mut p = Poly1305::new_from_slice(key).unwrap();
    p.update_padded(data);
    let mut r = [0u8; poly1305::BLOCK_SIZE];
    r.copy_from_slice(p.finalize().as_slice());
    r
}

#[test]
fn test_poly1305() {
    let msg = [
        0xab, 0x08, 0x12, 0x72, 0x4a, 0x7f, 0x1e, 0x34, 0x27, 0x42, 0xcb, 0xed, 0x37, 0x4d, 0x94,
        0xd1, 0x36, 0xc6, 0xb8, 0x79, 0x5d, 0x45, 0xb3, 0x81, 0x98, 0x30, 0xf2, 0xc0, 0x44, 0x91,
        0xfa, 0xf0, 0x99, 0x0c, 0x62, 0xe4, 0x8b, 0x80, 0x18, 0xb2, 0xc3, 0xe4, 0xa0, 0xfa, 0x31,
        0x34, 0xcb, 0x67, 0xfa, 0x83, 0xe1, 0x58, 0xc9, 0x94, 0xd9, 0x61, 0xc4, 0xcb, 0x21, 0x09,
        0x5c, 0x1b, 0xf9,
    ];
    let key = [
        0x12, 0x97, 0x6a, 0x08, 0xc4, 0x42, 0x6d, 0x0c, 0xe8, 0xa8, 0x24, 0x07, 0xc4, 0xf4, 0x82,
        0x07, 0x80, 0xf8, 0xc2, 0x0a, 0xa7, 0x12, 0x02, 0xd1, 0xe2, 0x91, 0x79, 0xcb, 0xcb, 0x55,
        0x5a, 0x57,
    ];
    let expected = [
        0xe7, 0x0b, 0x28, 0xa3, 0x0d, 0xbd, 0xe7, 0xee, 0x75, 0x34, 0xaa, 0x25, 0x8b, 0x97, 0x79,
        0x12,
    ];

    assert_eq!(poly1305(&key, &msg), expected);
    assert_eq!(poly1305(&key, &msg), std_poly1305(&key, &msg));

    let msg = [
        0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91, 0x00, 0x00, 0x00,
        0x00, 0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6,
        0x43, 0xbd, 0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 0xf1, 0x08, 0x67, 0x0a, 0xc7,
        0x6c, 0x8c, 0xb2, 0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 0xa0, 0x9e, 0xe9, 0x4e,
        0x38, 0x2d, 0x26, 0xb0, 0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 0xd4, 0xf0, 0x3b,
        0x7f, 0x35, 0x58, 0x94, 0xcf, 0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 0x98, 0xc8,
        0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81, 0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 0x60,
        0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55, 0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61,
        0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38, 0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02,
        0xb0, 0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4, 0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80,
        0x4d, 0x46, 0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9, 0x90, 0x40, 0xc5, 0xa4, 0x04,
        0x33, 0x22, 0x5e, 0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e, 0xaf, 0x45, 0x34, 0xd7,
        0xf8, 0x3f, 0xa1, 0x15, 0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a, 0x0d, 0x07, 0x2b,
        0x04, 0xb3, 0x56, 0x4e, 0xea, 0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a, 0x0b, 0xb2,
        0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e, 0xce,
        0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
        0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71,
        0x30, 0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f,
        0x2c, 0x29, 0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 0x9b, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let key = [
        0xbd, 0xf0, 0x4a, 0xa9, 0x5c, 0xe4, 0xde, 0x89, 0x95, 0xb1, 0x4b, 0xb6, 0xa1, 0x8f, 0xec,
        0xaf, 0x26, 0x47, 0x8f, 0x50, 0xc0, 0x54, 0xf5, 0x63, 0xdb, 0xc0, 0xa2, 0x1e, 0x26, 0x15,
        0x72, 0xaa,
    ];
    let expected = [
        0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f,
        0x38,
    ];
    assert_eq!(poly1305(&key, &msg), expected);
    assert_eq!(poly1305(&key, &msg), std_poly1305(&key, &msg));
}
