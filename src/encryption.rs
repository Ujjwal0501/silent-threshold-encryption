use std::ops::Mul;

use crate::{kzg::UniversalParams, setup::AggregateKey};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    Group,
};
use ark_poly::{Radix2EvaluationDomain, EvaluationDomain};
use ark_serialize::*;
use ark_std::UniformRand;
use ark_std::{One, Zero};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Ciphertext<E: Pairing> {
    pub gamma_g2: E::G2,
    pub sa1: [E::G1; 2],
    pub sa2: [E::G2; 6],
    pub enc_key: PairingOutput<E>, //key to be used for encapsulation
    pub t: usize,                  //threshold
}

impl<E: Pairing> Ciphertext<E> {
    pub fn new(
        gamma_g2: E::G2,
        sa1: [E::G1; 2],
        sa2: [E::G2; 6],
        enc_key: PairingOutput<E>,
        t: usize,
    ) -> Self {
        Ciphertext {
            gamma_g2,
            sa1,
            sa2,
            enc_key,
            t,
        }
    }
}

/// t is the threshold for encryption and apk is the aggregated public key
pub fn encrypt<E: Pairing>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &UniversalParams<E>,
) -> Ciphertext<E> {
    let mut rng = ark_std::test_rng();
    let gamma = E::ScalarField::rand(&mut rng);
    let gamma_g2 = params.powers_of_h[0] * gamma;

    let g = params.powers_of_g[0];
    let h = params.powers_of_h[0];

    // todo: avoid benchmarking this
    let e_gh = E::pairing(g, h);

    let mut sa1 = [E::G1::generator(); 2];
    let mut sa2 = [E::G2::generator(); 6];

    let mut s: [E::ScalarField; 5] = [E::ScalarField::zero(); 5];
    // s[0] = E::ScalarField::rand(&mut rng);
    // s[1] = E::ScalarField::rand(&mut rng);
    // s[2] = E::ScalarField::rand(&mut rng);
    // s[3] = E::ScalarField::rand(&mut rng);
    s[4] = E::ScalarField::rand(&mut rng);

    // s.iter_mut()
    //     .for_each(|s| *s = E::ScalarField::rand(&mut rng));

    // sa1[0] = s0*ask + s3*g^{tau^t} + s4*g
    sa1[0] = (apk.ask * s[0]) + (params.powers_of_g[t] * s[3]) + (params.powers_of_g[0] * s[4]);

    // sa1[1] = s2*g
    sa1[1] = g * s[2];

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = (h * s[0]) + (gamma_g2 * s[2]);

    // sa2[1] = s0*z_g2
    sa2[1] = apk.z_g2 * s[0];

    // sa2[2] = s0*h^tau + s1*h^tau
    sa2[2] = params.powers_of_h[1] * (s[0] + s[1]);

    // sa2[3] = s1*h
    sa2[3] = h * s[1];

    // sa2[4] = s3*h
    sa2[4] = h * s[3];

    // sa2[5] = s4*h^{tau - omega^0}
    let n = apk.pk.len();
    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).unwrap();
    sa2[5] = (params.powers_of_h[1] + (params.powers_of_h[0] * (-domain.element(0))) ) * s[4];

    // enc_key = s4*e_gh
    let enc_key = e_gh.mul(s[4]);

    println!("sa1 = {:?}", sa1);
    println!("sa2 = {:?}", sa2);
    Ciphertext {
        gamma_g2,
        sa1,
        sa2,
        enc_key,
        t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kzg::KZG10,
        setup::{PublicKey, SecretKey},
    };
    use ark_poly::univariate::DensePolynomial;

    type E = ark_bls12_381::Bls12_381;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_encryption() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let params = KZG10::<E, UniPoly381>::setup(n, &mut rng).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(0, &params, n))
        }

        let ak = AggregateKey::<E>::new(pk, &params);
        let _ct = encrypt::<E>(&ak, 2, &params);
    }
}