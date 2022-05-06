pub fn xor(output: &mut [u8], input: &[u8]) {
    output.iter_mut().zip(input).for_each(|(o, i)| *o ^= i);
}
