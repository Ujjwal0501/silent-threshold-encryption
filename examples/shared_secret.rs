use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::{UniformRand, Zero, rand::Rng};
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};
use ark_serialize::CanonicalSerialize;

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;
use hkdf::Hkdf;
use sha2::Sha256;

fn main() { 
    let mut rng = ark_std::test_rng();
    let n = 1 << 5; // actually n-1 total parties. one party is a dummy party that is always true
    let t: usize = 9;
    debug_assert!(t < n);

    println!("Setting up KZG parameters : {t} of {n}");
    let tau = Fr::rand(&mut rng);

    // 'KZG CRS'
    let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau.clone()).unwrap();

    println!("Preprocessing lagrange powers");

    // Don't know what this is probably 'Lagrange CRS'
    let lagrange_params = LagrangePowers::<E>::new(tau, n);

    println!("Setting up key pairs for {} parties", n);
    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    // create the dummy party's keys
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].lagrange_get_pk(0, &lagrange_params, n));

    for i in 1..n {
        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[i].lagrange_get_pk(i, &lagrange_params, n))
    }

    println!("pk.len() = {}, kzg_params.len() = {:}", pk.len(), kzg_params.powers_of_g.len());
    println!("Compting the aggregate key");
    let agg_key = AggregateKey::<E>::new(pk, &kzg_params);

    println!("Encrypting a message");
    let ct = encrypt::<E>(&agg_key, t, &kzg_params);

    println!("Computing partial decryptions");
    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    for i in 0..t + 1 {
        partial_decryptions.push(sk[i].partial_decryption(&ct));
    }
    for _ in t + 1..n {
        partial_decryptions.push(G2::zero());
    }

    println!("Aggregating partial decryptions and decrypting");
    // compute the decryption key
    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..t + 1 {
        selector.push(true);
    }
    for _ in t + 1..n {
        selector.push(false);
    }

    let _dec_key = agg_dec(&partial_decryptions, &ct, &selector, &agg_key, &kzg_params);
    let mut ikm = vec![];
    _dec_key.serialize_compressed(&mut ikm).unwrap();

     // Use a unique salt in a real application
    let salt = rng.gen::<[u8; 32]>();
    let info = b"aes_encryption";
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    
    let mut okm = [0u8; 32]; // Output key material (256-bit key)
    hk.expand(info, &mut okm).expect("HKDF expand failed");

    // Output the derived key
    println!("Derived key: {:?}", okm);

    println!("Decryption successful!");
}
