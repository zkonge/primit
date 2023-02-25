use crate::utils::endian::{EndianConvertion, LittleEndian};

const LIMBS: usize = 8;

// 2^32-radix: value = v[0] + 2^32 v[1] + ... + 2^124 v[7]
// value must be < P256
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Int256(pub(crate) [u32; LIMBS]);

// P256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
pub const P256: Int256 = Int256([
    0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, //
    0x00000000, 0x00000000, 0x00000001, 0xffffffff,
]);
pub const ZERO: Int256 = Int256([0; LIMBS]);
pub const ONE: Int256 = Int256([1, 0, 0, 0, 0, 0, 0, 0]);

impl Int256 {
    // return 0 if self == b.
    // otherwise return 1.
    pub fn not_equal(&self, b: &Int256) -> bool {
        self.0 != b.0
    }

    // if flag == 0, returns a
    // if flag == 1, returns b
    pub fn choose(flag: bool, a: &Int256, b: &Int256) -> Int256 {
        if !flag {
            *a
        } else {
            *b
        }
    }

    // return (value, carry) where
    // value = self + b mod 2^256
    // carry = if self + b < P256 { 0 } else { 1 }
    // i.e. self + b == value + 2^256 * carry
    fn add_no_reduce(&self, b: &Int256) -> (Int256, u32) {
        let mut v = ZERO;

        // invariant: carry <= 1
        let mut carry = 0u64;
        for i in 0..LIMBS {
            // add <= 2^33
            let add = (self.0[i] as u64) + (b.0[i] as u64) + carry;
            v.0[i] = add as u32;
            carry = add >> 32;
        }
        (v, carry as u32)
    }

    // return (value, carry) where
    // value = self - b mod 2^256
    // carry = if self > b { 0 } else { 1 }
    // i.e. self - b == value - 2^256 * carry
    fn sub_no_reduce(&self, b: &Int256) -> (Int256, u32) {
        let mut v = Int256([0u32; LIMBS]);

        // invariant: carry_sub <= 1
        let mut carry_sub = 0u64;
        for i in 0..LIMBS {
            // -2^32 <= sub <= 2^32
            let sub = (self.0[i] as u64)
                .wrapping_sub(b.0[i] as u64)
                .wrapping_sub(carry_sub);
            // if sub < 0, set carry_sub = 1 and sub += 2^32
            carry_sub = sub >> 63;
            v.0[i] = sub as u32;
        }

        (v, carry_sub as u32)
    }

    // input may not be reduced
    // precondition: `self + carry * 2^256 < 2 * P256`
    // return `(self + carry * 2^256) mod P256`
    pub fn reduce_once(&self, carry: u32) -> Int256 {
        let (v, carry_sub) = self.sub_no_reduce(&P256);
        debug_assert!(!(carry_sub == 0 && carry == 1)); // precondition violated
        let choose_new = carry ^ carry_sub;
        Int256::choose(choose_new != 0, &v, self)
    }

    pub fn reduce_once_zero(&self) -> Int256 {
        self.reduce_once(0)
    }

    pub fn add(&self, b: &Int256) -> Int256 {
        let (v, carry) = self.add_no_reduce(b);
        v.reduce_once(carry)
    }

    pub fn double(&self) -> Int256 {
        // FIXME can be more efficient
        self.add(self)
    }

    pub fn sub(&self, b: &Int256) -> Int256 {
        let (v, carry_sub) = self.sub_no_reduce(b);
        // if self - b < 0, carry_sub == 1 and v == 2^256 + self - b
        let (v2, _carry_add) = v.add_no_reduce(&P256);
        debug_assert!(!(_carry_add == 0 && carry_sub == 1));
        Int256::choose(carry_sub != 0, &v, &v2)
    }

    pub fn mult(&self, b: &Int256) -> Int256 {
        let mut w = [0u64; LIMBS * 2];
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                let ij = i + j;
                let v_ij = (self.0[i] as u64) * (b.0[j] as u64);
                let v_ij_low = v_ij as u32 as u64;
                let v_ij_high = v_ij >> 32;
                let w_ij = w[ij] + v_ij_low;
                let w_ij_low = w_ij as u32 as u64;
                let w_ij_high = v_ij_high + (w_ij >> 32);
                w[ij] = w_ij_low;
                w[ij + 1] += w_ij_high
            }
        }

        let mut v = [0u32; LIMBS * 2];
        let mut carry = 0u64;
        for i in 0..(LIMBS * 2) {
            let a = w[i] + carry;
            v[i] = a as u32;
            carry = a >> 32;
        }
        debug_assert_eq!(carry, 0);

        let mut buf = ZERO;
        buf.0[..LIMBS].copy_from_slice(&v[..LIMBS]);
        let t = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[3..8].copy_from_slice(&v[11..16]);
        let s1 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[3..7].copy_from_slice(&v[12..16]);
        let s2 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[..3].copy_from_slice(&v[8..11]);
        buf.0[6] = v[14];
        buf.0[7] = v[15];
        let s3 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[..3].copy_from_slice(&v[9..12]);
        buf.0[3..6].copy_from_slice(&v[13..16]);
        buf.0[6] = v[13];
        buf.0[7] = v[8];
        let s4 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[..3].copy_from_slice(&v[11..14]);
        buf.0[6] = v[8];
        buf.0[7] = v[10];
        let d1 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[..4].copy_from_slice(&v[12..16]);
        buf.0[6] = v[9];
        buf.0[7] = v[11];
        let d2 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[..3].copy_from_slice(&v[13..16]);
        buf.0[3..6].copy_from_slice(&v[8..11]);

        buf.0[7] = v[12];
        let d3 = buf.reduce_once_zero();

        let mut buf = ZERO;
        buf.0[3..6].copy_from_slice(&v[9..12]);
        buf.0[7] = v[13];
        buf.0[0] = v[14];
        buf.0[1] = v[15];
        let d4 = buf.reduce_once_zero();

        let r = t.add(&s1.double()).add(&s2.double()).add(&s3).add(&s4);
        r.sub(&d1.add(&d2).add(&d3).add(&d4))
    }

    pub fn square(&self) -> Int256 {
        // FIXME can be more efficient
        self.mult(self)
    }

    // return self^-1 = self^(P256 - 2)
    pub fn inverse(&self) -> Int256 {
        // 2^256 - 2^224 + 2^192 + 2^96 - 3
        // 2^224 (2^32 - 1) + (2^192 - 1) + 2 (2^95 - 1)
        // 2^256 = (2^32)^8
        // 2^224 = (2^32)^7

        // compute a^(2^n)
        fn square_n(a: &Int256, n: usize) -> Int256 {
            let mut y = *a;
            for _ in 0..n {
                y = y.square();
            }
            y
        }

        // compute z^(2^n + 1)
        // if z == self^(2^n - 1), it returns self^(2^(2n) - 1)
        fn z_n(z: &Int256, n: usize) -> Int256 {
            let y = square_n(z, n);
            y.mult(z)
        }

        // for given z_n = a^(2^n - 1), return z_{n+1} = a^(2^(n+1) - 1)
        fn z_1(z: &Int256, a: &Int256) -> Int256 {
            z.square().mult(a)
        }

        // FIXME this routine seems far from optimal

        let z2 = z_n(self, 1);
        let z4 = z_n(&z2, 2);
        let z8 = z_n(&z4, 4);
        let z16 = z_n(&z8, 8);
        let z32 = z_n(&z16, 16);

        let z5 = z_1(&z4, self);

        let z10 = z_n(&z5, 5);
        let z11 = z_1(&z10, self);

        let z22 = z_n(&z11, 11);
        let z23 = z_1(&z22, self);

        let z46 = z_n(&z23, 23);
        let z47 = z_1(&z46, self);

        let z94 = z_n(&z47, 47);
        let z95 = z_1(&z94, self);

        let y96_2 = z95.square();
        let z96 = y96_2.mult(self);

        let z192 = z_n(&z96, 96);

        let y256_224 = square_n(&z32, 224);

        y256_224.mult(&z192).mult(&y96_2)
    }

    #[cfg(test)]
    pub fn divide_by_2(&self) -> Int256 {
        let is_odd = self.0[0] & 1;

        let mut half_even = ZERO;
        for i in 0..(LIMBS - 1) {
            half_even.0[i] = (self.0[i] >> 1) | ((self.0[i + 1] & 1) << 31);
        }
        half_even.0[LIMBS - 1] = self.0[LIMBS - 1] >> 1;

        let mut half_odd = ZERO;
        let (self_p, carry) = self.add_no_reduce(&P256);
        for i in 0..(LIMBS - 1) {
            half_odd.0[i] = (self_p.0[i] >> 1) | ((self_p.0[i + 1] & 1) << 31);
        }
        half_odd.0[LIMBS - 1] = (self_p.0[LIMBS - 1] >> 1) | (carry << 31);
        // we can assume half_odd < P256 since (self + P256) < P256 * 2

        Int256::choose(is_odd != 0, &half_even, &half_odd)
    }

    // big-endian.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut r = [0u8; 32];
        LittleEndian::to_bytes(&mut r, &self.0);
        r.reverse();
        r
    }

    // big-endian.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Self> {
        let mut r = ZERO;
        let mut b = *b;
        b.reverse();
        LittleEndian::from_bytes(&mut r.0, &b);
        Some(r)
    }
}

#[cfg(test)]
mod test {
    use super::{Int256, ONE, P256, ZERO};

    // FIXME more values
    static VALUES_256: &[Int256] = &[
        ZERO,
        ONE,
        Int256([2, 0, 0, 0, 0, 0, 0, 0]),
        Int256([1; 8]),
        Int256([0, 2, 0, 2, 0, 0, 0, 0]),
        Int256([1, 2, 3, 4, 5, 6, 7, 8]),
        Int256([
            0x0, 0x0, 0x0, 0x0, //
            0xffffffff, 0xffffffff, 0, 0xffffffff,
        ]),
        Int256([0xfffffffe; 8]),
    ];

    #[test]
    fn test_int256_compare() {
        for a in VALUES_256.iter() {
            for b in VALUES_256.iter() {
                if a == b {
                    assert_eq!(a.not_equal(b), false);
                } else {
                    assert_eq!(a.not_equal(b), true);
                }
            }
        }
    }

    #[test]
    fn test_int256_reduce_once() {
        // FIXME more tests

        assert_eq!(ZERO.reduce_once(0), ZERO);
        assert_eq!(P256.reduce_once(0), ZERO);

        static P256P1: Int256 = Int256([0, 0, 0, 1, 0, 0, 1, 0xffffffff]);
        assert_eq!(P256P1.reduce_once(0), ONE);

        // 2^256 == 2^224 - 2^192 - 2^96 + 1
        let v = Int256([
            1, 0, 0, 0xffffffff, //
            0xffffffff, 0xffffffff, 0xfffffffe, 0,
        ]);
        assert_eq!(ZERO.reduce_once(1), v);
    }

    #[test]
    fn test_int256_add() {
        for a in VALUES_256.iter() {
            assert_eq!(a.add(&ZERO), *a);

            for b in VALUES_256.iter() {
                let ab = a.add(b);
                assert_eq!(ab, b.add(a));
                for c in VALUES_256.iter() {
                    let abc = ab.add(c);
                    let acb = a.add(c).add(b);
                    assert_eq!(abc, acb);

                    let bca = b.add(c).add(a);
                    assert_eq!(abc, bca);
                }
            }
        }
    }

    #[test]
    fn test_int256_sub() {
        for a in VALUES_256.iter() {
            assert_eq!(a.sub(&ZERO), *a);
            assert_eq!(a.sub(a), ZERO);

            for b in VALUES_256.iter() {
                assert_eq!(a.sub(b).add(b), *a);

                let ab = a.sub(b);
                assert_eq!(ab.reduce_once(0), ab);

                for c in VALUES_256.iter() {
                    let abc = ab.sub(c);
                    let ac = a.sub(c);
                    let acb = ac.sub(b);
                    assert_eq!(abc, acb);

                    let bc = b.add(c);
                    let a_bc = a.sub(&bc);
                    assert_eq!(abc, a_bc);
                }
            }
        }
    }

    #[test]
    fn test_int256_mult() {
        for a in VALUES_256.iter() {
            assert_eq!(a.mult(&ONE), *a);
            assert_eq!(a.mult(&ZERO), ZERO);

            for b in VALUES_256.iter() {
                let ab = a.mult(b);
                assert_eq!(ab, b.mult(a));
                for c in VALUES_256.iter() {
                    let ac = a.mult(c);

                    let abc = ab.mult(c);
                    let acb = ac.mult(b);
                    assert_eq!(abc, acb);

                    let bca = b.mult(c).mult(a);
                    assert_eq!(abc, bca);

                    let abac = ab.add(&ac);
                    let bc = b.add(c);
                    let abc = a.mult(&bc);
                    assert_eq!(abac, abc);
                }
            }
        }
    }

    #[test]
    fn test_int256_inverse() {
        assert_eq!(ONE.inverse(), ONE);

        for a in VALUES_256.iter() {
            if *a == ZERO {
                continue;
            }

            let a_inv = a.inverse();
            let a_inv_a = a_inv.mult(a);
            assert_eq!(a_inv_a, ONE);

            let a_inv_inv = a_inv.inverse();
            assert_eq!(a_inv_inv, *a);
        }
    }

    #[test]
    fn test_int256_divide_by_2() {
        for a in VALUES_256.iter() {
            let a_half = a.divide_by_2();
            assert_eq!(a_half, a_half.reduce_once(0));
            let a_half_2 = a_half.add(&a_half);
            assert_eq!(*a, a_half_2);
        }
    }

    #[test]
    fn test_from_bytes() {
        for a in VALUES_256.iter() {
            let b = a.to_bytes();
            let aa = Int256::from_bytes(&b.try_into().unwrap()).expect("to_bytes failed");
            assert_eq!(*a, aa);
        }
        let one = Int256::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 1u8, //
        ])
        .unwrap();
        assert_eq!(one, ONE);
    }
}
