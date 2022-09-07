use crate::utils::{
    endian::{BigEndian, EndianConvertion},
    xor::xor,
};

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCONSTANT: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[inline(always)]
fn byte(i: u32, n: u32) -> u8 {
    (i >> ((3 - n) * 8)) as u8
}

#[inline(always)]
fn sub_byte(x: u32, subtle_box: &[u8; 256]) -> u32 {
    // endian is not matter
    let [a, b, c, d] = x.to_ne_bytes();
    u32::from_ne_bytes([
        subtle_box[a as usize],
        subtle_box[b as usize],
        subtle_box[c as usize],
        subtle_box[d as usize],
    ])
}

fn sub_bytes(data: &mut [u32; 4]) {
    data.iter_mut().for_each(|x| {
        *x = sub_byte(*x, &SBOX);
    });
}

fn inv_sub_bytes(data: &mut [u32; 4]) {
    data.iter_mut().for_each(|x| {
        *x = sub_byte(*x, &RSBOX);
    });
}

fn shift_rows(data: &mut [u32; 4]) {
    *data = [
        u32::from_be_bytes([
            byte(data[0], 0),
            byte(data[1], 1),
            byte(data[2], 2),
            byte(data[3], 3),
        ]),
        u32::from_be_bytes([
            byte(data[1], 0),
            byte(data[2], 1),
            byte(data[3], 2),
            byte(data[0], 3),
        ]),
        u32::from_be_bytes([
            byte(data[2], 0),
            byte(data[3], 1),
            byte(data[0], 2),
            byte(data[1], 3),
        ]),
        u32::from_be_bytes([
            byte(data[3], 0),
            byte(data[0], 1),
            byte(data[1], 2),
            byte(data[2], 3),
        ]),
    ];
}

fn inv_shift_rows(data: &mut [u32; 4]) {
    *data = [
        u32::from_be_bytes([
            byte(data[0], 0),
            byte(data[3], 1),
            byte(data[2], 2),
            byte(data[1], 3),
        ]),
        u32::from_be_bytes([
            byte(data[1], 0),
            byte(data[0], 1),
            byte(data[3], 2),
            byte(data[2], 3),
        ]),
        u32::from_be_bytes([
            byte(data[2], 0),
            byte(data[1], 1),
            byte(data[0], 2),
            byte(data[3], 3),
        ]),
        u32::from_be_bytes([
            byte(data[3], 0),
            byte(data[2], 1),
            byte(data[1], 2),
            byte(data[0], 3),
        ]),
    ];
}

fn gf_poly_mul2(x: u32) -> u32 {
    ((x & 0x7f7f7f7f) << 1) ^ (((x & 0x80808080) >> 7) * 0x1b)
}

fn mix_column(x: u32) -> u32 {
    let x2 = gf_poly_mul2(x);
    x2 ^ (x ^ x2).rotate_right(24) ^ x.rotate_right(16) ^ x.rotate_right(8)
}

fn inv_mix_column(x: u32) -> u32 {
    let x2 = gf_poly_mul2(x);
    let x4 = gf_poly_mul2(x2);
    let x9 = x ^ gf_poly_mul2(x4);
    let x11 = x2 ^ x9;
    let x13 = x4 ^ x9;

    x ^ x2 ^ x13 ^ x11.rotate_right(24) ^ x13.rotate_right(16) ^ x9.rotate_right(8)
}

fn mix_columns(data: &mut [u32; 4]) {
    for x in data.iter_mut() {
        *x = mix_column(*x);
    }
}

fn inv_mix_columns(data: &mut [u32; 4]) {
    for x in data.iter_mut() {
        *x = inv_mix_column(*x);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AES128 {
    round_key: [[u32; 4]; 11],
}

impl AES128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut round_key = [[0u32; 4]; 11];

        BigEndian::from_bytes(&mut round_key[0], key);

        for i in 0..round_key.len() - 1 {
            let (a, b) = (round_key[i], &mut round_key[i + 1]);

            // rot word, sub word
            let mut temp = sub_byte(a[3].rotate_left(8), &SBOX);

            // rconstant
            temp ^= (RCONSTANT[i] as u32) << 24;

            *b = a;

            for chunk in b {
                *chunk ^= temp;
                temp = *chunk;
            }
        }
        AES128 { round_key }
    }

    pub fn encrypt(&self, data: &mut [u8; 16]) {
        let keys = self.round_key;
        let (first_key, keys) = keys.split_first().unwrap();
        let (last_key, keys) = keys.split_last().unwrap();

        let blocks = &mut [0u32; 4];
        BigEndian::from_bytes(blocks, data);

        xor(blocks, first_key);

        for key in keys {
            sub_bytes(blocks);
            shift_rows(blocks);
            mix_columns(blocks);
            xor(blocks, key);
        }

        sub_bytes(blocks);
        shift_rows(blocks);
        xor(blocks, last_key);

        BigEndian::to_bytes(data, blocks);
    }

    pub fn decrypt(&self, data: &mut [u8; 16]) {
        let keys = self.round_key;
        let (first_key, keys) = keys.split_first().unwrap();
        let (last_key, keys) = keys.split_last().unwrap();

        let blocks = &mut [0u32; 4];
        BigEndian::from_bytes(blocks, data);

        xor(blocks, last_key);
        inv_shift_rows(blocks);
        inv_sub_bytes(blocks);

        for key in keys.iter().rev() {
            xor(blocks, key);
            inv_mix_columns(blocks);
            inv_shift_rows(blocks);
            inv_sub_bytes(blocks);
        }

        xor(blocks, first_key);

        BigEndian::to_bytes(data, blocks);
    }
}
