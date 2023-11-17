use crate::ark_std::UniformRand;
use crate::parameters::params_to_base_field;
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
  prelude::{EqGadget, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;

use std::marker::PhantomData;
use rand::Rng;

struct TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
{
  A: E::G1,
  B: E::G2,
  C: E::TargetField,
  _iv: PhantomData<IV>,
}


impl<I, IV> TestudoCommVerifier<I, IV>
where
    I: Pairing,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng>(mut rng: R) -> Self {
        let x = I::G1::rand(&mut rng);
        let y = I::G2::rand(&mut rng);

        let ml = I::miller_loop(x, y);
        let z = I::final_exponentiation(ml).unwrap();

        Self {
            A:x,
            B:y,
            C:z.0,
            _iv: PhantomData,
        }
    }
}

impl<E, IV> ConstraintSynthesizer<<E as Pairing>::BaseField> for TestudoCommVerifier<E, IV>
where
  E: Pairing,
  IV: PairingVar<E>,
  IV::G1Var: CurveVar<E::G1, E::BaseField>,
  IV::G2Var: CurveVar<E::G2, E::BaseField>,
  IV::GTVar: FieldVar<E::TargetField, E::BaseField>,

{
  fn generate_constraints(
    self,
    cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
  ) -> Result<(), SynthesisError> {

    let a_var = IV::G1Var::new_input(cs.clone(), || Ok(self.A))?;
    let b_var = IV::G2Var::new_input(cs.clone(), || Ok(self.B))?;

    let prep_a_var = IV::prepare_g1(&a_var)?;
    let prep_b_var = IV::prepare_g2(&b_var)?;

    let c_var = IV::pairing(prep_a_var, prep_b_var)?;
    
   // let c_var = IV::GTVar::new_input(cs.clone(), || Ok(self.C))?;

    let params: PoseidonConfig<E::BaseField> = params_to_base_field::<E>();

    let mut sponge_naive = PoseidonSponge::<E::BaseField>::new(&params);


    let mut buf = Vec::new();
    self.C
      .serialize_with_mode(&mut buf, Compress::No)
      .expect("serialization failed");

    println!();
    println!("PRINT BYTE NAIVE");
    for v in buf.clone() {
        print!("{} - ", v);
      }
    println!();

    sponge_naive.absorb(&buf);

    let real_hash: E::BaseField = sponge_naive.squeeze_field_elements(1).remove(0);

    println!("REAL HASH ");
    println!("{}", real_hash);

    let real_hash_var = FpVar::new_input(cs.clone(), || Ok(real_hash)).unwrap();

    println!("REAL HASH VAR");
    println!("{}", real_hash_var.value().unwrap());


    let mut sponge_var = PoseidonSpongeVar::<E::BaseField>::new(cs.clone(),&params);

    let mut buf2 = Vec::new();
    c_var.value().unwrap()
      .serialize_with_mode(&mut buf2, Compress::No)
      .expect("serialization failed");

    let mut x_var_vec = Vec::new();
    for x in buf2 {
      x_var_vec.push(UInt8::new_input(cs.clone(), || Ok(x))?);
    }

    println!();
    println!("PRINT BYTE VAR");
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
  use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I};
  use ark_ec::bls12::Bls12;
  use ark_ec::pairing::Pairing;
  use ark_relations::r1cs::ConstraintSystem;
  use ark_std::test_rng;

  #[test]
  fn absorb_test() {
    let mut rng = test_rng();
    let cs = ConstraintSystem::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>::new_ref();
    let circuit = TestudoCommVerifier::<I, IV>::new(&mut rng);
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
  }
}
