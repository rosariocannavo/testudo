use crate::ark_std::One;
use crate::ark_std::UniformRand;
use crate::mipp::MippProof;
use crate::parameters::get_bls12377_fq_params;
use crate::parameters::params_to_base_field;
use crate::{
  math::Math,
  poseidon_transcript::PoseidonTranscript,
  sparse_mlpoly::{SparsePolyEntry, SparsePolynomial},
  unipoly::UniPoly,
};
use ark_bls12_377::g1::G1Affine;
use ark_bls12_377::Fr;
use ark_bls12_377::G1Projective;
use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_crypto_primitives::sponge::poseidon;
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_crypto_primitives::Error;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_poly_commit::multilinear_pc::data_structures::CommitmentG2;
use ark_poly_commit::multilinear_pc::data_structures::ProofG1;
use ark_poly_commit::multilinear_pc::{
  data_structures::{Commitment, CommitterKey, Proof, VerifierKey},
  MultilinearPC,
};
use ark_r1cs_std::groups::bls12::G1Var;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
  alloc::{AllocVar, AllocationMode},
  fields::fp::FpVar,
  prelude::{EqGadget, FieldVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_serialize::Compress;
use digest::generic_array::typenum::True;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::MulAssign;
use std::{borrow::Borrow, marker::PhantomData};

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
{
  fn generate_constraints(
    mut self,
    cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
  ) -> Result<(), SynthesisError> {
    let exp_hash_var =
      FpVar::<E::BaseField>::new_witness(cs.clone(), || Ok(self.hash.clone())).unwrap();

    println!("EXP_HASH_VAR: ");
    println!("{}", exp_hash_var.value().unwrap());
    //let point_var_affine = IV::G1Var::new_input(cs.clone(), || Ok(self.point.clone())).unwrap();
    // self
    //   .constraint_sponge
    //   .clone()
    //   .absorb(&point_var_affine)
    //   .unwrap();

    println!("SCALAR_FQ 2: ");
    println!("{}", self.scalar_in_fq);

    let scalar_var = FpVar::new_witness(cs.clone(), || Ok(self.scalar_in_fq)).unwrap();

    println!("SCALAR_VAR: ");
    println!("{}", scalar_var.value().unwrap());
    self.constraint_sponge.absorb(&scalar_var).unwrap();

    let hash_var = self
      .constraint_sponge
      .squeeze_field_elements(1)
      .unwrap()
      .remove(0);

    println!("HASH_VAR: ");
    println!("{}", hash_var.value().unwrap());

    hash_var.enforce_equal(&exp_hash_var).unwrap();
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parameters::get_bls12377_fq_params;
  use crate::transcript::Transcript;
  use ark_bls12_377::constraints::G1Var;
  use ark_bls12_377::{constraints::PairingVar as IV, constraints::*, Bls12_377 as I};
  use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
  use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
  use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
  use ark_crypto_primitives::sponge::CryptographicSponge;
  use ark_ec::bls12::Bls12;
  use ark_ec::pairing::Pairing;
  use ark_ff::{BigInteger, PrimeField};
  use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
  use ark_relations::{ns, r1cs::ConstraintSystem};
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

    //native_sponge.absorb(&point.clone());
    println!("SCALAR_FQ 1: ");
    println!("{}", scalar_in_fq);
    native_sponge.append_scalar(b"U", &scalar_in_fq);

    let hash = native_sponge
      .challenge_scalar::<<Bls12<ark_bls12_377::Config> as Pairing>::BaseField>(b"random_point");

    println!("HASH: ");
    println!("{}", hash);

    // let point_var_affine = G1Var::new_input(cs.clone(), || Ok(point.clone())).unwrap();
    // constraint_sponge.absorb(&point_var_affine);

    // let scalar_var = FpVar::new_witness(cs.clone(), || Ok(scalar_in_fq)).unwrap();
    // let exp_hash_var = FpVar::new_witness(cs.clone(), || Ok(hash.clone())).unwrap();
    // constraint_sponge.absorb(&scalar_var);
    let circuit: TestudoCommVerifier<I, IV> = TestudoCommVerifier {
      native_sponge,
      constraint_sponge,
      point,
      scalar_in_fq,
      hash,
      _iv: PhantomData,
    };

    circuit.generate_constraints(cs.clone()).unwrap();
    //let hash_var = constraint_sponge.squeeze_field_elements(1).unwrap().remove(0);
    //hash_var.enforce_equal(&exp_hash_var).unwrap();
    assert!(cs.is_satisfied().unwrap());
  }
}
