use core::mem::size_of;

pub(crate) trait SingleEndianConvertion: Sized + Copy {
    fn to_be_bytes(self) -> [u8; size_of::<Self>()];
    fn to_le_bytes(self) -> [u8; size_of::<Self>()];
    fn from_be_bytes(x: [u8; size_of::<Self>()]) -> Self;
    fn from_le_bytes(x: [u8; size_of::<Self>()]) -> Self;
}

macro_rules! impl_convert {
    ($t:ty) => {
        impl SingleEndianConvertion for $t {
            #[inline]
            fn to_be_bytes(self) -> [u8; size_of::<Self>()] {
                self.to_be_bytes()
            }

            #[inline]
            fn to_le_bytes(self) -> [u8; size_of::<Self>()] {
                self.to_le_bytes()
            }

            #[inline]
            fn from_be_bytes(x: [u8; size_of::<Self>()]) -> Self {
                Self::from_be_bytes(x)
            }

            #[inline]
            fn from_le_bytes(x: [u8; size_of::<Self>()]) -> Self {
                Self::from_le_bytes(x)
            }
        }
    };
}

impl_convert!(u8);
impl_convert!(u16);
impl_convert!(u32);

pub(crate) fn assert_len<const N: usize, T: SingleEndianConvertion>(s: &[T]) -> &[T; N] {
    s.try_into().unwrap()
}

pub(crate) fn assert_len_mut<const N: usize, T: SingleEndianConvertion>(
    s: &mut [T],
) -> &mut [T; N] {
    s.try_into().unwrap()
}

pub(crate) trait EndianConvertion<T: SingleEndianConvertion, const N: usize> {
    fn to_bytes(output: &mut [u8; N * size_of::<T>()], input: &[T; N]);
    fn from_bytes(output: &mut [T; N], input: &[u8; N * size_of::<T>()]);
}

pub(crate) struct BigEndian;
pub(crate) struct LittleEndian;

impl<T: SingleEndianConvertion, const N: usize> EndianConvertion<T, N> for BigEndian {
    fn to_bytes(output: &mut [u8; N * size_of::<T>()], input: &[T; N]) {
        for (o, i) in output.as_chunks_mut().0.iter_mut().zip(input) {
            *o = i.to_be_bytes();
        }
    }

    fn from_bytes(output: &mut [T; N], input: &[u8; N * size_of::<T>()]) {
        for (o, i) in output.iter_mut().zip(input.as_chunks().0) {
            *o = T::from_be_bytes(*i);
        }
    }
}

impl<T: SingleEndianConvertion, const N: usize> EndianConvertion<T, N> for LittleEndian {
    fn to_bytes(output: &mut [u8; N * size_of::<T>()], input: &[T; N]) {
        for (o, i) in output.as_chunks_mut().0.iter_mut().zip(input) {
            *o = i.to_le_bytes();
        }
    }

    fn from_bytes(output: &mut [T; N], input: &[u8; N * size_of::<T>()]) {
        for (o, i) in output.iter_mut().zip(input.as_chunks().0) {
            *o = T::from_le_bytes(*i);
        }
    }
}
