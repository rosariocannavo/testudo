use crate::parameters::params_to_base_field;
use crate::poseidon_transcript::PoseidonTranscript;
use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_crypto_primitives::sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::pairing::Pairing;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
  alloc::AllocVar,
  fields::fp::FpVar,
  prelude::EqGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use std::marker::PhantomData;


struct TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
{
  native_sponge: PoseidonTranscript<E::BaseField>,
  constraint_sponge: PoseidonSpongeVar<E::BaseField>,
  point: E::G1Affine,
  scalar_in_fq: E::BaseField,
  hash: E::BaseField,
  _iv: PhantomData<IV>,
}

impl<E, IV> ConstraintSynthesizer<<E as Pairing>::BaseField> for TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
  IV::G1Var: CurveVar<E::G1, E::BaseField>,
  <IV as ark_r1cs_std::pairing::PairingVar<E>>::G1Var: AbsorbGadget<<E as Pairing>::BaseField>,
{
  fn generate_constraints(
    mut self,
    cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
  ) -> Result<(), SynthesisError> {
   

    let params: PoseidonConfig<E::BaseField> = params_to_base_field::<E>();

    let mut buf = Vec::new();
    self.point
      .serialize_with_mode(&mut buf, Compress::No)
      .expect("serialization failed");

    let mut sponge_naive = PoseidonSponge::<E::BaseField>::new(&params);

    let mut sponge_var = PoseidonSpongeVar::<E::BaseField>::new(cs.clone(),&params);

    sponge_naive.absorb(&buf);

    let real_hash: E::BaseField = sponge_naive.squeeze_field_elements(1).remove(0);

    println!("REAL HASH ");
    println!("{}", real_hash);


    let real_hash_var = FpVar::new_input(cs.clone(), || Ok(real_hash)).unwrap();

    println!("REAL HASH VAR");
    println!("{}", real_hash_var.value().unwrap());

    let point_var_affine = IV::G1Var::new_input(cs.clone(), || Ok(self.point.clone())).unwrap();
    
    //start allocation for absorb
    let mut buf2 = Vec::new();
    point_var_affine.value().unwrap()
      .serialize_with_mode(&mut buf2, Compress::No)
      .expect("serialization failed");

    let mut x_var_vec = Vec::new();
  
    for x in buf2 {
      x_var_vec.push(UInt8::new_input(cs.clone(), || Ok(x))?);
    }
    //end allocation for absorb
   
    println!();
    println!("STAMPO BYTE DI VARIABILI");
    for v in x_var_vec.clone() {
        print!("{} - ", v.value()?);
      }
    println!();
    

    sponge_var
      .absorb(&x_var_vec)
      .unwrap();
    
   
    let hash_var = sponge_var
      .squeeze_field_elements(1)
      .unwrap()
      .remove(0);

    println!("HASH_VAR: ");
    println!("{}", hash_var.value().unwrap());

    hash_var.enforce_equal(&real_hash_var).unwrap();
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parameters::get_bls12377_fq_params;
  use crate::transcript::Transcript;
  use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I};
  use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
  use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
  use ark_ec::bls12::Bls12;
  use ark_ec::pairing::Pairing;
  use ark_ff::{BigInteger, PrimeField};
  use ark_relations::r1cs::ConstraintSystem;
  use ark_std::test_rng;
  use ark_std::UniformRand;
  #[test]
  fn absorb_test() {
    let mut rng = test_rng();
    let cs = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();

    let sponge_params = get_bls12377_fq_params();

    let mut native_sponge = PoseidonTranscript::new(&sponge_params);
    let mut constraint_sponge = PoseidonSpongeVar::new(cs.clone(), &sponge_params);

    let mut rng = ark_std::test_rng();
    let point = ark_bls12_377::G1Affine::rand(&mut rng);
    let scalar = ark_bls12_377::Fr::rand(&mut rng);
    let scalar_in_fq =
      <Bls12<ark_bls12_377::Config> as Pairing>::BaseField::from_bigint(<<Bls12<
        ark_bls12_377::Config,
      > as Pairing>::BaseField as PrimeField>::BigInt::from_bits_le(
        scalar.into_bigint().to_bits_le().as_slice(),
      ))
      .unwrap();

 
    native_sponge.append(b"U", &point);

    let hash = native_sponge
      .challenge_scalar::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>(b"random_point");

    println!("HASH: ");
    println!("{}", hash);

    let circuit: TestudoCommVerifier<I, IV> = TestudoCommVerifier {
      native_sponge,
      constraint_sponge,
      point,
      scalar_in_fq,
      hash,
      _iv: PhantomData,
    };

    circuit.generate_constraints(cs.clone()).unwrap();
 ;
    assert!(cs.is_satisfied().unwrap());
  }
}
