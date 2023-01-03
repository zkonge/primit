use core::ops::BitXorAssign;

pub fn xor<T: BitXorAssign + Copy>(output: &mut [T], input: &[T]) {
    output.iter_mut().zip(input).for_each(|(o, i)| *o ^= *i);
}

pub fn xor_static<T: BitXorAssign + Copy, const N: usize>(output: &mut [T; N], input: &[T; N]) {
    output.iter_mut().zip(input).for_each(|(o, i)| *o ^= *i);
}
