use super::int256::{Int256, ONE, P256, ZERO};

// Point on Y^2 = X^3 - 3 * X + B mod P256 where B is some obscure big number
// (x, y, z): (X, Y) = (x/z^2, y/z^3) is point of Y^2 = X^3 - 3 * X + c
// identity (INFTY) is (1, 1, 0)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Point256 {
    x: Int256,
    y: Int256,
    z: Int256,
}

pub const G: Point256 = Point256 {
    x: Int256([
        0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81, //
        0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2,
    ]),
    y: Int256([
        0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357, //
        0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2,
    ]),
    z: ONE,
};

pub const B: Int256 = Int256([
    0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0, //
    0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8,
]);

const INFTY: Point256 = Point256 {
    x: ONE,
    y: ONE,
    z: ZERO,
};

impl Point256 {
    pub fn normalize(&self) -> NPoint256 {
        let invz = self.z.inverse();
        let invz2 = invz.square();
        let invz3 = invz2.mult(&invz);
        let x = self.x.mult(&invz2);
        let y = self.y.mult(&invz3);

        NPoint256 { x, y }
    }

    // compute `self + self`
    // self.z must not zero.
    fn double(&self) -> Point256 {
        // delta = Z1^2
        let delta = self.z.square();
        // gamma = Y1^2
        let gamma = self.y.square();
        // beta = X1*gamma
        let beta = self.x.mult(&gamma);
        // alpha = 3*(X1-delta)*(X1+delta)
        let alpha = self.x.sub(&delta).mult(&self.x.add(&delta));
        let alpha = alpha.add(&alpha).add(&alpha);
        // X3 = alpha^2-8*beta
        let beta4 = beta.double().double();
        let x = alpha.square().sub(&beta4.double());
        // Z3 = (Y1+Z1)^2-gamma-delta
        let z = (self.y.add(&self.z).square()).sub(&gamma).sub(&delta);
        // Y3 = alpha*(4*beta-X3)-8*gamma^2
        let gammasq8 = gamma.square().double().double().double();
        let y = alpha.mult(&beta4.sub(&x)).sub(&gammasq8);
        Point256 { x, y, z }
    }

    fn add(&self, b: &Point256) -> Point256 {
        // Z1Z1 = Z1^2
        let z1z1 = self.z.square();
        // Z2Z2 = Z2^2
        let z2z2 = b.z.square();
        // U1 = X1*Z2Z2
        let u1 = self.x.mult(&z2z2);
        // U2 = X2*Z1Z1
        let u2 = b.x.mult(&z1z1);
        // S1 = Y1*Z2*Z2Z2
        let s1 = self.y.mult(&b.z).mult(&z2z2);
        // S2 = Y2*Z1*Z1Z1
        let s2 = b.y.mult(&self.z).mult(&z1z1);
        // H = U2-U1
        let h = u2.sub(&u1);
        // I = (2*H)^2
        let i = (h.double()).square();
        // J = H*I
        let j = h.mult(&i);
        // r = 2*(S2-S1)
        let r = s2.sub(&s1).double();
        // V = U1*I
        let v = u1.mult(&i.add(&P256));
        // X3 = r^2-J-2*V
        let x = r.square().sub(&j).sub(&v.double());
        // Y3 = r*(V-X3)-2*S1*J
        let y = r.mult(&v.sub(&x)).sub(&s1.mult(&j).double());
        // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
        let z = self.z.add(&b.z).square().sub(&z1z1).sub(&z2z2).mult(&h);

        Point256 { x, y, z }
    }

    pub fn mult_scalar(&self, n: &Int256) -> Point256 {
        let mut ret = INFTY;
        for i in (0..8).rev() {
            for j in (0..32).rev() {
                let bit = (n.0[i] >> j) & 1;
                let ret2 = ret.double();
                ret = if bit == 0 {
                    ret2
                } else if ret2 == INFTY {
                    *self
                } else {
                    ret2.add(self)
                };
            }
        }

        ret
    }
}

// normalized
pub struct NPoint256 {
    pub x: Int256,
    pub y: Int256,
}

impl NPoint256 {
    pub fn to_point(&self) -> Point256 {
        Point256 {
            x: self.x,
            y: self.y,
            z: ONE,
        }
    }

    pub fn from_uncompressed_bytes(data: &[u8; 65]) -> Option<NPoint256> {
        if data.len() != 1 + 32 * 2 {
            return None;
        }
        if data[0] != 0x04 {
            return None;
        }

        let x = Int256::from_bytes(&data[1..(32 + 1)].try_into().unwrap());
        let y = Int256::from_bytes(&data[(1 + 32)..(1 + 32 * 2)].try_into().unwrap());

        let (x, y) = match (x, y) {
            (Some(x), Some(y)) => (x, y),
            _ => return None,
        };

        let p = NPoint256 { x, y };

        // wait, but is p on the curve?
        // check if y^2 + 3 * x == x^3 + B

        let y2 = y.square();
        let lhs = y2.add(&x.double().add(&x));

        let x3 = x.square().mult(&x);
        let rhs = x3.add(&B);

        if lhs.not_equal(&rhs) {
            return None;
        }

        Some(p)
    }

    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        // 0x04 || self.x (big endian) || self.y (big endian)
        let mut b = [0u8; 65];
        b[0] = 0x04; // uncompressed
        b[1..33].copy_from_slice(&self.x.to_bytes());
        b[33..65].copy_from_slice(&self.y.to_bytes());
        b
    }
}
