use aes::cipher::generic_array::GenericArray;
use p256::{
    elliptic_curve::{ops::Reduce, AffineXCoordinate},
    AffinePoint, Scalar,
};
use primit::{
    ec::{
        p256::{G, P256},
        ECDH,
    },
    rng::{FastRng, Rng},
    utils::hex::decode_fix,
};

#[test]
fn test_p256() {
    let sk = decode_fix::<32>(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")
        .unwrap();
    let pk=decode_fix::<65>(b"046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A").unwrap();

    let rpk = P256::new(&sk).to_public();

    assert_eq!(pk.as_slice(), rpk.as_slice());
}

#[test]
fn test_std_p256() {
    let mut x = [0u8; 32];
    let mut rng = FastRng::new_from_seed(&[0u8; 32]);
    for _ in 0..1000 {
        rng.fill_bytes(&mut x);

        let g = AffinePoint::GENERATOR;
        let scalar_x = Scalar::from_be_bytes_reduced(*GenericArray::from_slice(&x));
        let std_result = (g * scalar_x).to_affine().x();

        let g = P256::new(&x);
        let result = g.exchange(&G.normalize().to_uncompressed_bytes()).unwrap();

        assert_eq!(std_result.as_slice(), result);
    }
}
