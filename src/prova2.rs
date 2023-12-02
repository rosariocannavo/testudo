use crate::parameters::params_to_base_field;
use crate::poseidon_transcript::PoseidonTranscript;
use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_crypto_primitives::sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use poseidon_parameters::PoseidonParameters;
use std::marker::PhantomData;
struct TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
{
  g1: E::G1Affine,
  poseidon_params: PoseidonConfig<E::BaseField>,
  _iv: PhantomData<IV>,
}

impl<E, IV> ConstraintSynthesizer<<E as Pairing>::BaseField> for TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
  IV::G1Var: CurveVar<E::G1, E::BaseField>,
{
  fn generate_constraints(
    mut self,
    cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
  ) -> Result<(), SynthesisError> {
    // let hash_in_fq = &E::BaseField::from_bigint(
    //   <E::BaseField as PrimeField>::BigInt::from_bits_le(self.hash.into_bigint().to_bits_le().as_slice()),
    // )
    // .unwrap();

    // let real_hash_var = NonNativeFieldVar::<E::ScalarField, E::BaseField>::new_input(ark_relations::ns!(cs, "resi"), || Ok(self.hash)).unwrap();

    // println!("REAL HASH VAR");
    // println!("{:?}", real_hash_var.value().unwrap());

    // // let scalar_in_fq = &E::BaseField::from_bigint(
    // //   <E::BaseField as PrimeField>::BigInt::from_bits_le(self.scalar.into_bigint().to_bits_le().as_slice()),
    // // )
    // // .unwrap();

    let g1_var = IV::G1Var::new_input(cs.clone(), || Ok(self.g1))?;

    //let scalar_var = NonNativeFieldVar::<E::ScalarField, E::BaseField>::new_input(ark_relations::ns!(cs, "resi"), || Ok(self.g1))?;

    // //let scalar_var_fq = FpVar::new_input(cs.clone(), || Ok(scalar_in_fq))?;
    // // println!("SCALAR VAR");
    // // println!("{:?}", scalar_var.value().unwrap());

    // // let mut buf3 = Vec::new();
    // // scalar_var.value().unwrap()
    // //   .serialize_with_mode(&mut buf3, Compress::Yes)
    // //   .expect("serialization failed");

    // // println!("SCALAR VAR BYTES");
    // // println!("{:?}", buf3);

    // self.constraint_sponge
    //   .absorb(&scalar_var.to_bytes()?)
    //   .unwrap();

    // let (hash_var1, hash_var2) = self.constraint_sponge
    //   .squeeze_nonnative_field_elements::<E::ScalarField>(1)
    //   .unwrap();

    // //let hash_var1 = self.constraint_sponge.squeeze_field_elements(1).unwrap().remove(0);
    // println!("HASH_VAR 1: ");
    // println!("{:?}", hash_var1.value().unwrap());

    // // for i in hash_var2 {
    // //   println!("{:?}", i.value().unwrap());
    // // }
    // // println!("HASH_VAR 2: ");
    // // println!("{:?}", hash_var2);
    //   real_hash_var.enforce_equal(&hash_var1[0]);

    //     let mut constraint_sponge = PoseidonSpongeVar::new(cs.clone(), &params_to_base_field::<E>());
    //    // let state_var = NonNativeFieldVar::<E::ScalarField, E::BaseField>::new_input(cs.clone(), || Ok(self.scalar)).unwrap();

    //    let scalar_in_fq = &E::BaseField::from_bigint(
    //       <E::BaseField as PrimeField>::BigInt::from_bits_le(self.scalar.into_bigint().to_bits_le().as_slice()),
    //     )
    //     .unwrap();

    // let state_var = FpVar::new_input(cs.clone(), || Ok(scalar_in_fq))?;

    // println!("STATE VAR {:?}", state_var.value().unwrap());

    // let mut x_var_vec: Vec<UInt8<_>> = Vec::new();
    // for x in state_var.to_bytes()?.value().unwrap() {
    //   x_var_vec.push(UInt8::new_input(cs.clone(), || Ok(x))?);
    // }
    // constraint_sponge
    //   .absorb(&scalar_in_fq()?)
    //   .unwrap();

    // let (hash_var1, hash_var2) = constraint_sponge
    //   .squeeze_nonnative_field_elements::<E::BaseField>(1).unwrap().pop()
    //   .unwrap();
    // println!("HASHVAR1 {:?}", hash_var1.value().unwrap()[0]);

    // let scalar_in_fq = &E::BaseField::from_bigint(
    //   <E::BaseField as PrimeField>::BigInt::from_bits_le(self.scalar.into_bigint().to_bits_le().as_slice()),
    // )
    // .unwrap();

    // let p = FpVar::new_input(cs.clone(), || Ok(scalar_in_fq))?;
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_params);

    println!("g1 {:?}", g1_var.value().unwrap().into_affine());

    let mut buf3 = Vec::new();
    g1_var
      .value()
      .unwrap()
      .into_affine()
      .serialize_with_mode(&mut buf3, Compress::No)
      .expect("serialization failed");

    let mut x_var_vec: Vec<UInt8<_>> = Vec::new();
    for x in buf3 {
      x_var_vec.push(UInt8::new_input(cs.clone(), || Ok(x))?);
    }
    sponge.absorb(&x_var_vec);
    let hash = sponge.squeeze_nonnative_field_elements::<E::ScalarField>(1);

    println!("hash {:?}", hash.unwrap().0.value().unwrap());
    // Fp256(BigInteger256([10577417867063568331, 11078737230088386683, 15679987742376005790, 1112270844950899640]))]
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parameters::get_bls12377_fq_params;
  use crate::parameters::get_bw6_fr_params;
  use crate::parameters::poseidon_params;
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

    let params = get_bls12377_fq_params();
    let mut native_sponge = PoseidonTranscript::new(&params);
    let mut rng = ark_std::test_rng();
    //let point = ark_bls12_377::G1Affine::rand(&mut rng);
    let g1 = ark_bls12_377::g1::G1Affine::rand(&mut rng);

    println!("G1 ");
    println!("{:?}", g1);

    native_sponge.append(b"U", &g1);

    let hash = native_sponge.challenge_scalar::<ark_bls12_377::Fr>(b"random_point");

    println!("HASH: ");
    println!("{:?}", hash);

    let circuit: TestudoCommVerifier<I, IV> = TestudoCommVerifier {
      g1,
      poseidon_params: get_bls12377_fq_params(),
      _iv: PhantomData,
    };

    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
  }
}
