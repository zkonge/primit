use std::ops::BitXorAssign;

pub fn xor<T: BitXorAssign + Copy>(output: &mut [T], input: &[T]) {
    output.iter_mut().zip(input).for_each(|(o, i)| *o ^= *i);
}
