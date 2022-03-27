// RFC1321 https://tools.ietf.org/html/rfc1321

const PADDING: [u8; 64] = const {
    let mut p = [0u8; 64];
    p[0] = 0x80;
    p
};

/// MD5 context.
#[derive(Debug, Clone)]
pub struct MD5 {
    buffer: [u8; 64],
    count: [u32; 2],
    state: [u32; 4],
}

impl MD5 {
    pub const LENGTH: usize = 16;

    pub fn new() -> MD5 {
        MD5 {
            buffer: [0; 64],
            count: [0, 0],
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.as_ref().chunks(core::u32::MAX as usize) {
            compress(self, chunk);
        }
    }

    pub fn digest(mut self) -> [u8; Self::LENGTH] {
        let mut input = [0u32; 16];
        let mut digest = [0u8; Self::LENGTH];

        let k = ((self.count[0] >> 3) & 0x3f) as usize;
        input[14] = self.count[0];
        input[15] = self.count[1];
        compress(
            &mut self,
            &PADDING[..(if k < 56 { 56 - k } else { 120 - k })],
        );
        for (output, input) in input[..14].iter_mut().zip(self.buffer.as_chunks().0) {
            *output = u32::from_le_bytes(*input);
        }
        transform(&mut self.state, &input);
        for (output, input) in digest.as_chunks_mut().0.iter_mut().zip(self.state) {
            *output = input.to_le_bytes();
        }
        digest
    }
}

fn compress(
    MD5 {
        buffer,
        count,
        state,
    }: &mut MD5,
    data: &[u8],
) {
    let mut input = [0u32; 16];
    let mut k = ((count[0] >> 3) & 0x3f) as usize;
    let length = data.len() as u32;

    count[0] = count[0].wrapping_add(length << 3);
    if count[0] < length << 3 {
        count[1] = count[1].wrapping_add(1);
    }
    count[1] = count[1].wrapping_add(length >> 29);
    for &value in data {
        buffer[k] = value;
        k += 1;
        if k == 0x40 {
            for (output, input) in input.iter_mut().zip(buffer.as_chunks().0) {
                *output = u32::from_le_bytes(*input);
            }
            transform(state, &input);
            k = 0;
        }
    }
}

fn transform(state: &mut [u32; 4], input: &[u32; 16]) {
    let [mut a, mut b, mut c, mut d] = state;
    macro_rules! add(
        ($a:expr, $b:expr) => ($a.wrapping_add($b));
    );
    macro_rules! rotate(
        ($x:expr, $n:expr) => (($x << $n) | ($x >> (32 - $n)));
    );
    macro_rules! T(
        ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => ({
            $a = add!(add!(add!($a, F!($b, $c, $d)), $x), $ac);
            $a = rotate!($a, $s);
            $a = add!($a, $b);
        });
    );
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => (($x & $y) | (!$x & $z));
        );
        const S1: u32 = 7;
        const S2: u32 = 12;
        const S3: u32 = 17;
        const S4: u32 = 22;
        T!(a, b, c, d, input[0], S1, 3614090360);
        T!(d, a, b, c, input[1], S2, 3905402710);
        T!(c, d, a, b, input[2], S3, 606105819);
        T!(b, c, d, a, input[3], S4, 3250441966);
        T!(a, b, c, d, input[4], S1, 4118548399);
        T!(d, a, b, c, input[5], S2, 1200080426);
        T!(c, d, a, b, input[6], S3, 2821735955);
        T!(b, c, d, a, input[7], S4, 4249261313);
        T!(a, b, c, d, input[8], S1, 1770035416);
        T!(d, a, b, c, input[9], S2, 2336552879);
        T!(c, d, a, b, input[10], S3, 4294925233);
        T!(b, c, d, a, input[11], S4, 2304563134);
        T!(a, b, c, d, input[12], S1, 1804603682);
        T!(d, a, b, c, input[13], S2, 4254626195);
        T!(c, d, a, b, input[14], S3, 2792965006);
        T!(b, c, d, a, input[15], S4, 1236535329);
    }
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => (($x & $z) | ($y & !$z));
        );
        const S1: u32 = 5;
        const S2: u32 = 9;
        const S3: u32 = 14;
        const S4: u32 = 20;
        T!(a, b, c, d, input[1], S1, 4129170786);
        T!(d, a, b, c, input[6], S2, 3225465664);
        T!(c, d, a, b, input[11], S3, 643717713);
        T!(b, c, d, a, input[0], S4, 3921069994);
        T!(a, b, c, d, input[5], S1, 3593408605);
        T!(d, a, b, c, input[10], S2, 38016083);
        T!(c, d, a, b, input[15], S3, 3634488961);
        T!(b, c, d, a, input[4], S4, 3889429448);
        T!(a, b, c, d, input[9], S1, 568446438);
        T!(d, a, b, c, input[14], S2, 3275163606);
        T!(c, d, a, b, input[3], S3, 4107603335);
        T!(b, c, d, a, input[8], S4, 1163531501);
        T!(a, b, c, d, input[13], S1, 2850285829);
        T!(d, a, b, c, input[2], S2, 4243563512);
        T!(c, d, a, b, input[7], S3, 1735328473);
        T!(b, c, d, a, input[12], S4, 2368359562);
    }
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => ($x ^ $y ^ $z);
        );
        const S1: u32 = 4;
        const S2: u32 = 11;
        const S3: u32 = 16;
        const S4: u32 = 23;
        T!(a, b, c, d, input[5], S1, 4294588738);
        T!(d, a, b, c, input[8], S2, 2272392833);
        T!(c, d, a, b, input[11], S3, 1839030562);
        T!(b, c, d, a, input[14], S4, 4259657740);
        T!(a, b, c, d, input[1], S1, 2763975236);
        T!(d, a, b, c, input[4], S2, 1272893353);
        T!(c, d, a, b, input[7], S3, 4139469664);
        T!(b, c, d, a, input[10], S4, 3200236656);
        T!(a, b, c, d, input[13], S1, 681279174);
        T!(d, a, b, c, input[0], S2, 3936430074);
        T!(c, d, a, b, input[3], S3, 3572445317);
        T!(b, c, d, a, input[6], S4, 76029189);
        T!(a, b, c, d, input[9], S1, 3654602809);
        T!(d, a, b, c, input[12], S2, 3873151461);
        T!(c, d, a, b, input[15], S3, 530742520);
        T!(b, c, d, a, input[2], S4, 3299628645);
    }
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => ($y ^ ($x | !$z));
        );
        const S1: u32 = 6;
        const S2: u32 = 10;
        const S3: u32 = 15;
        const S4: u32 = 21;
        T!(a, b, c, d, input[0], S1, 4096336452);
        T!(d, a, b, c, input[7], S2, 1126891415);
        T!(c, d, a, b, input[14], S3, 2878612391);
        T!(b, c, d, a, input[5], S4, 4237533241);
        T!(a, b, c, d, input[12], S1, 1700485571);
        T!(d, a, b, c, input[3], S2, 2399980690);
        T!(c, d, a, b, input[10], S3, 4293915773);
        T!(b, c, d, a, input[1], S4, 2240044497);
        T!(a, b, c, d, input[8], S1, 1873313359);
        T!(d, a, b, c, input[15], S2, 4264355552);
        T!(c, d, a, b, input[6], S3, 2734768916);
        T!(b, c, d, a, input[13], S4, 1309151649);
        T!(a, b, c, d, input[4], S1, 4149444226);
        T!(d, a, b, c, input[11], S2, 3174756917);
        T!(c, d, a, b, input[2], S3, 718787259);
        T!(b, c, d, a, input[9], S4, 3951481745);
    }
    state[0] = add!(state[0], a);
    state[1] = add!(state[1], b);
    state[2] = add!(state[2], c);
    state[3] = add!(state[3], d);
}

impl Default for MD5 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn md5(input: &[u8]) -> [u8; MD5::LENGTH] {
    let mut hasher = MD5::new();
    hasher.update(input);
    hasher.digest()
}

#[cfg(test)]
mod tests {
    use test::Bencher;

    use crate::util::hex::decode;

    use super::*;

    #[test]
    fn test_md5() {
        let inputs = [
            "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "0123456789012345678901234567890123456789012345678901234567890123",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        ];
        let outputs = [
            "d41d8cd98f00b204e9800998ecf8427e",
            "0cc175b9c0f1b6a831c399e269772661",
            "900150983cd24fb0d6963f7d28e17f72",
            "f96b697d7cb7938d525a2f31aaf161d0",
            "c3fcd3d76192e4007dfb496cca67e13b",
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "7f7bfd348709deeaace19e3f535f8c54",
            "57edf4a22be3c955ac49da2e2107b67a",
        ];
        for (input, &output) in inputs.iter().zip(outputs.iter()) {
            let mut output_bytes = [0u8; MD5::LENGTH];
            decode(output.as_bytes(), &mut output_bytes).unwrap();

            let hash = md5(input.as_bytes());

            assert_eq!(hash, output_bytes);
        }
    }

    const DATA_LENGTH: usize = 1024 * 256;

    #[bench]
    fn bench_md5(b: &mut Bencher) {
        b.bytes = DATA_LENGTH as u64;
        let d = [0u8; DATA_LENGTH];
        b.iter(|| md5(&d));
    }
}
