pub fn xor(output: &mut [u8], input: &[u8]) {
    for i in 0..output.len().min(input.len()) {
        unsafe {
            *output.get_unchecked_mut(i) ^= input.get_unchecked(i);
        }
    }
}
