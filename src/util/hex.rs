use crate::error::HexCodecError;

const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

const REVERSE_HEX_TABLE: &[u8; 256] = &const {
    let mut table = [0xFFu8; 256];

    macro_rules! fill_table {
        ($table:expr) => {
            let t = $table;
            let mut i = 0;
            while i < t.len() {
                table[t[i] as usize] = i as u8;
                i += 1;
            }
        };
    }

    fill_table!(HEX_TABLE); //lower case
    fill_table!(b"0123456789ABCDEF"); //upper case
    table
};

pub fn encode(input: &[u8], output: &mut [u8]) -> Result<(), HexCodecError> {
    if input.len() * 2 > output.len() {
        return Err(HexCodecError::InvalidHexLength);
    }

    input
        .iter()
        .zip(output.as_chunks_mut::<2>().0)
        .for_each(|(i, o)| {
            let (hi, lo) = (*i >> 4, *i & 0xF);
            *o = [HEX_TABLE[hi as usize], HEX_TABLE[lo as usize]];
        });
    Ok(())
}

pub fn decode(input: &[u8], output: &mut [u8]) -> Result<(), HexCodecError> {
    if input.len() > output.len() * 2 {
        return Err(HexCodecError::InvalidHexLength);
    }

    input
        .as_chunks::<2>()
        .0
        .iter()
        .zip(output.iter_mut())
        .try_for_each(|(i, o)| {
            let [hi, lo] = *i;
            let (hi, lo) = (
                REVERSE_HEX_TABLE[hi as usize],
                REVERSE_HEX_TABLE[lo as usize],
            );
            if hi | lo == 0xFF {
                return Err(HexCodecError::InvalidHexCharacter);
            }
            *o = (hi << 4) | lo;
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{black_box, Bencher};

    const DATA_LENGTH: usize = 1024;

    #[test]
    fn test_decode() {
        const I: [u8; 32] = *b"d41d8cd98f00b204e9800998ecf8427e";
        const O: [u8; 16] = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        let mut r = [0u8; 16];
        decode(&I, &mut r).unwrap();
        assert_eq!(r, O);
    }

    // #[bench]
    // fn bench_std_encode(b: &mut Bencher) {
    //     b.bytes = DATA_LENGTH as u64;
    //     let data = black_box([0u8; DATA_LENGTH]);
    //     let mut result = black_box([0u8; DATA_LENGTH * 2]);

    //     b.iter(|| hex::encode_to_slice(&data, &mut result).unwrap());
    // }

    #[bench]
    fn bench_encode(b: &mut Bencher) {
        b.bytes = DATA_LENGTH as u64;
        let data = black_box([0u8; DATA_LENGTH]);
        let mut result = black_box([0u8; DATA_LENGTH * 2]);

        b.iter(|| encode(&data, &mut result).unwrap());
    }

    #[bench]
    fn bench_decode(b: &mut Bencher) {
        b.bytes = DATA_LENGTH as u64;
        let data = black_box([0x30u8; DATA_LENGTH * 2]);
        let mut result = black_box([0u8; DATA_LENGTH]);

        b.iter(|| decode(&data, &mut result).unwrap());
    }
}
