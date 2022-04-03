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

pub fn encode_fix<const N: usize>(input: &[u8; N]) -> [u8; N * 2] {
    let mut r = [0u8; N * 2];
    encode(input, &mut r).unwrap();
    r
}

pub fn decode_fix<const N: usize>(input: &[u8; N * 2]) -> Result<[u8; N], HexCodecError> {
    let mut r = [0u8; N];
    if let Err(e @ HexCodecError::InvalidHexCharacter) = decode(input, &mut r) {
        return Err(e);
    }
    Ok(r)
}
