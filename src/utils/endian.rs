pub(crate) trait EndianConvertion {
    fn to_bytes(output: &mut [u8], input: &[u32]);
    fn from_bytes(output: &mut [u32], input: &[u8]);
}

pub(crate) struct BigEndian;
pub(crate) struct LittleEndian;

impl EndianConvertion for BigEndian {
    fn to_bytes(output: &mut [u8], input: &[u32]) {
        for (o, i) in output.as_chunks_mut().0.iter_mut().zip(input) {
            *o = u32::to_be_bytes(*i);
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
            *o = u32::to_le_bytes(*i);
        }
    }

    fn from_bytes(output: &mut [u32], input: &[u8]) {
        for (o, i) in output.iter_mut().zip(input.as_chunks().0) {
            *o = u32::from_le_bytes(*i);
        }
    }
}

// macro_rules! implByteIntConvert {
//     ($num_t:ty) => {
//         impl BytesIntConvertable<$num_t> for $num_t {
//             fn to_le_bytes(self) -> [u8; size_of::<$num_t>()] {
//                 <$num_t>::to_le_bytes(self)
//             }

//             fn to_be_bytes(self) -> [u8; size_of::<$num_t>()] {
//                 <$num_t>::to_be_bytes(self)
//             }

//             fn from_le_bytes(d: [u8; size_of::<$num_t>()]) -> $num_t {
//                 <$num_t>::from_le_bytes(d)
//             }

//             fn from_be_bytes(d: [u8; size_of::<$num_t>()]) -> $num_t {
//                 <$num_t>::from_be_bytes(d)
//             }
//         }
//     };
// }

// implByteIntConvert!(u32);
