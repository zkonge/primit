pub(crate) trait EndianConvertion {
    fn to_bytes(output: &mut [u8], input: &[u32]);
    fn from_bytes(output: &mut [u32], input: &[u8]);
}

pub(crate) struct BigEndian;
pub(crate) struct LittleEndian;

impl EndianConvertion for BigEndian {
    fn to_bytes(output: &mut [u8], input: &[u32]) {
        for (o, i) in output.as_chunks_mut().0.iter_mut().zip(input) {
            *o = i.to_be_bytes();
        }
    }

    fn from_bytes(output: &mut [u32], input: &[u8]) {
        for (o, i) in output.iter_mut().zip(input.as_chunks().0) {
            *o = u32::from_be_bytes(*i);
        }
    }
}

impl EndianConvertion for LittleEndian {
    fn to_bytes(output: &mut [u8], input: &[u32]) {
        for (o, i) in output.as_chunks_mut().0.iter_mut().zip(input) {
            *o = i.to_le_bytes();
        }
    }

    fn from_bytes(output: &mut [u32], input: &[u8]) {
        for (o, i) in output.iter_mut().zip(input.as_chunks().0) {
            *o = u32::from_le_bytes(*i);
        }
    }
}
