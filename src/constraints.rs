use crate::ark_std::One;
use crate::mipp::MippProof;
use crate::parameters::get_bls12377_fq_params;
use crate::parameters::params_to_base_field;
use crate::{
  math::Math,
  poseidon_transcript::PoseidonTranscript,
  sparse_mlpoly::{SparsePolyEntry, SparsePolynomial},
  unipoly::UniPoly,
};
use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_crypto_primitives::sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_crypto_primitives::Error;
use ark_ec::pairing::Pairing;
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

pub struct PoseidonTranscripVar<F>
where
  F: PrimeField,
{
  pub cs: ConstraintSystemRef<F>,
  pub sponge: PoseidonSpongeVar<F>,
}

impl<F> PoseidonTranscripVar<F>
where
  F: PrimeField,
{
  fn new(cs: ConstraintSystemRef<F>, params: &PoseidonConfig<F>, c_var: FpVar<F>) -> Self {
    let mut sponge = PoseidonSpongeVar::new(cs.clone(), params);

    sponge.absorb(&c_var).unwrap();

    Self { cs, sponge }
  }

  fn append(&mut self, input: &FpVar<F>) -> Result<(), SynthesisError> {
    self.sponge.absorb(&input)
  }

  fn append_vector(&mut self, input_vec: &[FpVar<F>]) -> Result<(), SynthesisError> {
    for input in input_vec.iter() {
      self.append(input)?;
    }
    Ok(())
  }

  fn challenge(&mut self) -> Result<FpVar<F>, SynthesisError> {
    Ok(self.sponge.squeeze_field_elements(1).unwrap().remove(0))
  }

  fn challenge_scalar_vec(&mut self, len: usize) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let c_vars = self.sponge.squeeze_field_elements(len).unwrap();
    Ok(c_vars)
  }
}

/// Univariate polynomial in constraint system
#[derive(Clone)]
pub struct UniPolyVar<F: PrimeField> {
  pub coeffs: Vec<FpVar<F>>,
}

impl<F: PrimeField> AllocVar<UniPoly<F>, F> for UniPolyVar<F> {
  fn new_variable<T: Borrow<UniPoly<F>>>(
    cs: impl Into<Namespace<F>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|c| {
      let cs = cs.into();
      let cp: &UniPoly<F> = c.borrow();
      let mut coeffs_var = Vec::new();
      for coeff in cp.coeffs.iter() {
        let coeff_var = FpVar::<F>::new_variable(cs.clone(), || Ok(coeff), mode)?;
        coeffs_var.push(coeff_var);
      }
      Ok(Self { coeffs: coeffs_var })
    })
  }
}

impl<F: PrimeField> UniPolyVar<F> {
  pub fn eval_at_zero(&self) -> FpVar<F> {
    self.coeffs[0].clone()
  }

  pub fn eval_at_one(&self) -> FpVar<F> {
    let mut res = self.coeffs[0].clone();
    for i in 1..self.coeffs.len() {
      res = &res + &self.coeffs[i];
    }
    res
  }

  // TODO check if mul without reduce can help
  pub fn evaluate(&self, r: &FpVar<F>) -> FpVar<F> {
    let mut eval = self.coeffs[0].clone();
    let mut power = r.clone();

    for i in 1..self.coeffs.len() {
      eval += &power * &self.coeffs[i];
      power *= r;
    }
    eval
  }
}

/// Circuit gadget that implements the sumcheck verifier
#[derive(Clone)]
pub struct SumcheckVerificationCircuit<F: PrimeField> {
  pub polys: Vec<UniPoly<F>>,
}

impl<F: PrimeField> SumcheckVerificationCircuit<F> {
  fn verifiy_sumcheck(
    &self,
    poly_vars: &[UniPolyVar<F>],
    claim_var: &FpVar<F>,
    transcript_var: &mut PoseidonTranscripVar<F>,
  ) -> Result<(FpVar<F>, Vec<FpVar<F>>), SynthesisError> {
    let mut e_var = claim_var.clone();
    let mut r_vars: Vec<FpVar<F>> = Vec::new();

    for (poly_var, _poly) in poly_vars.iter().zip(self.polys.iter()) {
      let res = poly_var.eval_at_one() + poly_var.eval_at_zero();
      res.enforce_equal(&e_var)?;
      transcript_var.append_vector(&poly_var.coeffs)?;
      let r_i_var = transcript_var.challenge()?;
      r_vars.push(r_i_var.clone());
      e_var = poly_var.evaluate(&r_i_var.clone());
    }

    Ok((e_var, r_vars))
  }
}

#[derive(Clone)]
pub struct SparsePolyEntryVar<F: PrimeField> {
  idx: usize,
  val_var: FpVar<F>,
}

impl<F: PrimeField> AllocVar<SparsePolyEntry<F>, F> for SparsePolyEntryVar<F> {
  fn new_variable<T: Borrow<SparsePolyEntry<F>>>(
    cs: impl Into<Namespace<F>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    _mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|s| {
      let cs = cs.into();
      let spe: &SparsePolyEntry<F> = s.borrow();
      let val_var = FpVar::<F>::new_witness(cs, || Ok(spe.val))?;
      Ok(Self {
        idx: spe.idx,
        val_var,
      })
    })
  }
}

#[derive(Clone)]
pub struct SparsePolynomialVar<F: PrimeField> {
  Z_var: Vec<SparsePolyEntryVar<F>>,
}

impl<F: PrimeField> AllocVar<SparsePolynomial<F>, F> for SparsePolynomialVar<F> {
  fn new_variable<T: Borrow<SparsePolynomial<F>>>(
    cs: impl Into<Namespace<F>>,
    f: impl FnOnce() -> Result<T, SynthesisError>,
    mode: AllocationMode,
  ) -> Result<Self, SynthesisError> {
    f().and_then(|s| {
      let cs = cs.into();
      let sp: &SparsePolynomial<F> = s.borrow();
      let mut Z_var = Vec::new();
      for spe in sp.Z.iter() {
        let spe_var = SparsePolyEntryVar::new_variable(cs.clone(), || Ok(spe), mode)?;
        Z_var.push(spe_var);
      }
      Ok(Self { Z_var })
    })
  }
}

impl<F: PrimeField> SparsePolynomialVar<F> {
  fn compute_chi(a: &[bool], r_vars: &[FpVar<F>]) -> FpVar<F> {
    let mut chi_i_var = FpVar::<F>::one();
    let one = FpVar::<F>::one();
    for (i, r_var) in r_vars.iter().enumerate() {
      if a[i] {
        chi_i_var *= r_var;
      } else {
        chi_i_var *= &one - r_var;
      }
    }
    chi_i_var
  }

  pub fn evaluate(&self, r_var: &[FpVar<F>]) -> FpVar<F> {
    let mut sum = FpVar::<F>::zero();
    for spe_var in self.Z_var.iter() {
      // potential problem
      let bits = &spe_var.idx.get_bits(r_var.len());
      sum += SparsePolynomialVar::compute_chi(bits, r_var) * &spe_var.val_var;
    }
    sum
  }
}

#[derive(Clone)]
pub struct R1CSVerificationCircuit<F: PrimeField> {
  pub num_vars: usize,
  pub num_cons: usize,
  pub input: Vec<F>,
  pub input_as_sparse_poly: SparsePolynomial<F>,
  pub evals: (F, F, F),
  pub params: PoseidonConfig<F>,
  pub prev_challenge: F,
  pub claims_phase2: (F, F, F, F),
  pub eval_vars_at_ry: F,
  pub sc_phase1: SumcheckVerificationCircuit<F>,
  pub sc_phase2: SumcheckVerificationCircuit<F>,
  // The point on which the polynomial was evaluated by the prover.
  pub claimed_rx: Vec<F>,
  pub claimed_ry: Vec<F>,
  pub claimed_transcript_sat_state: F,
}

impl<F: PrimeField> R1CSVerificationCircuit<F> {
  pub fn new<E: Pairing<ScalarField = F>>(config: &VerifierConfig<E>) -> Self {
    Self {
      num_vars: config.num_vars,
      num_cons: config.num_cons,
      input: config.input.clone(),
      input_as_sparse_poly: config.input_as_sparse_poly.clone(),
      evals: config.evals,
      params: config.params.clone(),
      prev_challenge: config.prev_challenge,
      claims_phase2: config.claims_phase2,
      eval_vars_at_ry: config.eval_vars_at_ry,
      sc_phase1: SumcheckVerificationCircuit {
        polys: config.polys_sc1.clone(),
      },
      sc_phase2: SumcheckVerificationCircuit {
        polys: config.polys_sc2.clone(),
      },
      claimed_rx: config.rx.clone(),
      claimed_ry: config.ry.clone(),
      claimed_transcript_sat_state: config.transcript_sat_state,
    }
  }
}

/// This section implements the sumcheck verification part of Spartan
impl<F: PrimeField> ConstraintSynthesizer<F> for R1CSVerificationCircuit<F> {
  fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ark_relations::r1cs::Result<()> {
    let initial_challenge_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.prev_challenge))?;
    let mut transcript_var =
      PoseidonTranscripVar::new(cs.clone(), &self.params, initial_challenge_var);

    let poly_sc1_vars = self
      .sc_phase1
      .polys
      .iter()
      .map(|p| UniPolyVar::new_variable(cs.clone(), || Ok(p), AllocationMode::Witness).unwrap())
      .collect::<Vec<UniPolyVar<_>>>();

    let poly_sc2_vars = self
      .sc_phase2
      .polys
      .iter()
      .map(|p| UniPolyVar::new_variable(cs.clone(), || Ok(p), AllocationMode::Witness).unwrap())
      .collect::<Vec<UniPolyVar<_>>>();

    let input_vars = self
      .input
      .iter()
      .map(|i| FpVar::<F>::new_variable(cs.clone(), || Ok(i), AllocationMode::Input).unwrap())
      .collect::<Vec<FpVar<F>>>();

    let claimed_rx_vars = self
      .claimed_rx
      .iter()
      .map(|r| FpVar::<F>::new_variable(cs.clone(), || Ok(r), AllocationMode::Input).unwrap())
      .collect::<Vec<FpVar<F>>>();

    let claimed_ry_vars = self
      .claimed_ry
      .iter()
      .map(|r| FpVar::<F>::new_variable(cs.clone(), || Ok(r), AllocationMode::Input).unwrap())
      .collect::<Vec<FpVar<F>>>();

    transcript_var.append_vector(&input_vars)?;

    let num_rounds_x = self.num_cons.log_2();
    let _num_rounds_y = (2 * self.num_vars).log_2();

    let tau_vars = transcript_var.challenge_scalar_vec(num_rounds_x)?;

    let claim_phase1_var = FpVar::<F>::new_witness(cs.clone(), || Ok(F::zero()))?;

    let (claim_post_phase1_var, rx_var) =
      self
        .sc_phase1
        .verifiy_sumcheck(&poly_sc1_vars, &claim_phase1_var, &mut transcript_var)?;

    // The prover sends (rx, ry) to the verifier for the evaluation proof so
    // the constraints need to ensure it is indeed the result from the first
    // round of sumcheck verification.
    for (i, r) in claimed_rx_vars.iter().enumerate() {
      rx_var[i].enforce_equal(r)?;
    }

    let (Az_claim, Bz_claim, Cz_claim, prod_Az_Bz_claims) = &self.claims_phase2;

    let Az_claim_var = FpVar::<F>::new_witness(cs.clone(), || Ok(Az_claim))?;
    let Bz_claim_var = FpVar::<F>::new_witness(cs.clone(), || Ok(Bz_claim))?;
    let Cz_claim_var = FpVar::<F>::new_witness(cs.clone(), || Ok(Cz_claim))?;
    let prod_Az_Bz_claim_var = FpVar::<F>::new_witness(cs.clone(), || Ok(prod_Az_Bz_claims))?;
    let one = FpVar::<F>::one();
    let prod_vars: Vec<FpVar<F>> = (0..rx_var.len())
      .map(|i| (&rx_var[i] * &tau_vars[i]) + (&one - &rx_var[i]) * (&one - &tau_vars[i]))
      .collect();
    let mut taus_bound_rx_var = FpVar::<F>::one();

    for p_var in prod_vars.iter() {
      taus_bound_rx_var *= p_var;
    }

    let expected_claim_post_phase1_var =
      (&prod_Az_Bz_claim_var - &Cz_claim_var) * &taus_bound_rx_var;

    claim_post_phase1_var.enforce_equal(&expected_claim_post_phase1_var)?;

    let r_A_var = transcript_var.challenge()?;
    let r_B_var = transcript_var.challenge()?;
    let r_C_var = transcript_var.challenge()?;

    let claim_phase2_var =
      &r_A_var * &Az_claim_var + &r_B_var * &Bz_claim_var + &r_C_var * &Cz_claim_var;

    let (claim_post_phase2_var, ry_var) =
      self
        .sc_phase2
        .verifiy_sumcheck(&poly_sc2_vars, &claim_phase2_var, &mut transcript_var)?;

    //  Because the verifier checks the commitment opening on point ry outside
    //  the circuit, the prover needs to send ry to the verifier (making the
    //  proof size O(log n)). As this point is normally obtained by the verifier
    //  from the second round of sumcheck, the circuit needs to ensure the
    //  claimed point, coming from the prover, is actually the point derived
    //  inside the circuit. These additional checks will be removed
    //  when the commitment verification is done inside the circuit.
    //  Moreover, (rx, ry) will be used in the evaluation proof.
    for (i, r) in claimed_ry_vars.iter().enumerate() {
      ry_var[i].enforce_equal(r)?;
    }

    let input_as_sparse_poly_var = SparsePolynomialVar::new_variable(
      cs.clone(),
      || Ok(&self.input_as_sparse_poly),
      AllocationMode::Witness,
    )?;

    let poly_input_eval_var = input_as_sparse_poly_var.evaluate(&ry_var[1..]);

    let eval_vars_at_ry_var = FpVar::<F>::new_input(cs.clone(), || Ok(&self.eval_vars_at_ry))?;

    let eval_Z_at_ry_var =
      (FpVar::<F>::one() - &ry_var[0]) * &eval_vars_at_ry_var + &ry_var[0] * &poly_input_eval_var;

    let (eval_A_r, eval_B_r, eval_C_r) = self.evals;

    let eval_A_r_var = FpVar::<F>::new_input(cs.clone(), || Ok(eval_A_r))?;
    let eval_B_r_var = FpVar::<F>::new_input(cs.clone(), || Ok(eval_B_r))?;
    let eval_C_r_var = FpVar::<F>::new_input(cs.clone(), || Ok(eval_C_r))?;

    let scalar_var = &r_A_var * &eval_A_r_var + &r_B_var * &eval_B_r_var + &r_C_var * &eval_C_r_var;

    let expected_claim_post_phase2_var = eval_Z_at_ry_var * scalar_var;
    claim_post_phase2_var.enforce_equal(&expected_claim_post_phase2_var)?;
    let expected_transcript_state_var = transcript_var.challenge()?;
    let claimed_transcript_state_var =
      FpVar::<F>::new_input(cs, || Ok(self.claimed_transcript_sat_state))?;

    // Ensure that the prover and verifier transcipt views are consistent at
    // the end of the satisfiability proof.
    expected_transcript_state_var.enforce_equal(&claimed_transcript_state_var)?;
    Ok(())
  }
}

#[derive(Clone)]
pub struct VerifierConfig<E: Pairing> {
  pub comm: Commitment<E>,
  pub num_vars: usize,
  pub num_cons: usize,
  pub input: Vec<E::ScalarField>,
  pub input_as_sparse_poly: SparsePolynomial<E::ScalarField>,
  pub evals: (E::ScalarField, E::ScalarField, E::ScalarField),
  pub params: PoseidonConfig<E::ScalarField>,
  pub prev_challenge: E::ScalarField,
  pub claims_phase2: (
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
    E::ScalarField,
  ),
  pub eval_vars_at_ry: E::ScalarField,
  pub polys_sc1: Vec<UniPoly<E::ScalarField>>,
  pub polys_sc2: Vec<UniPoly<E::ScalarField>>,
  pub rx: Vec<E::ScalarField>,
  pub ry: Vec<E::ScalarField>,
  pub transcript_sat_state: E::ScalarField,
}

// Skeleton for the polynomial commitment verification circuit
// #[derive(Clone)]
// pub struct VerifierCircuit {
//   pub inner_circuit: R1CSVerificationCircuit,
//   pub inner_proof: GrothProof<I>,
//   pub inner_vk: PreparedVerifyingKey<I>,
//   pub eval_vars_at_ry: Fr,
//   pub claims_phase2: (Fr, Fr, Fr, Fr),
//   pub ry: Vec<Fr>,
//   pub transcript_sat_state: Scalar,
// }

// impl VerifierCircuit {
//   pub fn new<R: Rng + CryptoRng>(
//     config: &VerifierConfig,
//     mut rng: &mut R,
//   ) -> Result<Self, SynthesisError> {
//     let inner_circuit = R1CSVerificationCircuit::new(config);
//     let (pk, vk) = Groth16::<I>::setup(inner_circuit.clone(), &mut rng).unwrap();
//     let proof = Groth16::<I>::prove(&pk, inner_circuit.clone(), &mut rng)?;
//     let pvk = Groth16::<I>::process_vk(&vk).unwrap();
//     Ok(Self {
//       inner_circuit,
//       inner_proof: proof,
//       inner_vk: pvk,
//       eval_vars_at_ry: config.eval_vars_at_ry,
//       claims_phase2: config.claims_phase2,
//       ry: config.ry.clone(),
//       transcript_sat_state: config.transcript_sat_state,
//     })
//   }
// }

// impl ConstraintSynthesizer<Fq> for VerifierCircuit {
//   fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> ark_relations::r1cs::Result<()> {
//     let proof_var = ProofVar::<I, IV>::new_witness(cs.clone(), || Ok(self.inner_proof.clone()))?;
//     let (v_A, v_B, v_C, v_AB) = self.claims_phase2;
//     let mut pubs = vec![];
//     pubs.extend(self.ry);
//     pubs.extend(vec![v_A, v_B, v_C, v_AB]);
//     pubs.extend(vec![self.eval_vars_at_ry, self.transcript_sat_state]);
//     let bits = pubs
//       .iter()
//       .map(|c| {
//         let bits: Vec<bool> = BitIteratorLE::new(c.into_bigint().as_ref().to_vec()).collect();
//         Vec::new_witness(cs.clone(), || Ok(bits))
//       })
//       .collect::<Result<Vec<_>, _>>()?;
//     let input_var = BooleanInputVar::<Fr, Fq>::new(bits);
//     let vk_var = PreparedVerifyingKeyVar::new_witness(cs, || Ok(self.inner_vk.clone()))?;
//     Groth16VerifierGadget::verify_with_processed_vk(&vk_var, &input_var, &proof_var)?
//       .enforce_equal(&Boolean::constant(true))?;
//     Ok(())
//   }
// }
// struct MippTUVar<E, IV>
// where
//   E: Pairing,
//   IV: PairingVar<E>,
//   IV::G1Var: CurveVar<E::G1, E::BaseField>,
//   IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
// {
//   pub tc: IV::GTVar,
//   pub uc: IV::G1Var,
// }

// impl<E, IV> Default for MippTUVar<E, IV>
// where
//   E: Pairing,
//   IV: PairingVar<E>,
//   IV::G1Var: CurveVar<E::G1, E::BaseField>,
//   IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
// {
//   fn default() -> Self {
//     Self {
//       tc: IV::GTVar::one(),
//       uc: IV::G1Var::zero(),
//     }
//   }
// }
// impl<E, IV> MippTUVar<E, IV>
// where
//   E: Pairing,
//   IV: PairingVar<E>,
//   IV::G1Var: CurveVar<E::G1, E::BaseField>,
//   IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
// {
//   fn merge(&mut self, other: &Self) {
//     self.tc.mul_assign(&other.tc);
//     self.uc.add_assign(&other.uc);
//   }
// }
// pub struct CommitmentG2Var<E: Pairing, IV: PairingVar<E>> {
//   /// number of variables
//   pub nv: usize,
//   /// product of g as described by the vRAM paper
//   pub h_product: IV::G2Var,
// }

// struct TestudoCommVerifier<E, IV>
// where
//   E: Pairing,
//   IV: PairingVar<E>,
// {
//   //transcript: PoseidonTranscript<E::ScalarField>,
//   vk: VerifierKey<E>,
//   U: Commitment<E>,
//   point: Vec<E::ScalarField>,
//   v: E::ScalarField,
//   pst_proof: Proof<E>,
//   mipp_proof: MippProof<E>,
//   T: E::TargetField,
//   _iv: PhantomData<IV>,
// }
// impl<E,IV> Clone for TestudoCommVerifier<E,IV>
// where
//   E: Pairing,
//   IV: PairingVar<E>,
// {
//   fn clone(&self) -> Self {
//     Self {
//      // transcript: self.transcript.clone(),
//       vk: self.vk.clone(),
//       U: self.U.clone(),
//       point: self.point.clone(),
//       v: self.v.clone(),
//       pst_proof: self.pst_proof.clone(),
//       mipp_proof: self.mipp_proof.clone(),
//       T: self.T.clone(),
//       _iv: self._iv,
//     }
//   }
// }

// impl<E, IV> ConstraintSynthesizer<<E as Pairing>::BaseField> for TestudoCommVerifier<E, IV>
// where
//   E: Pairing,
//   IV: PairingVar<E>,
//   IV::G1Var: CurveVar<E::G1, E::BaseField>,
//   IV::G2Var: CurveVar<E::G2, E::BaseField>,
//   IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
//   IV::G1Var: AbsorbGadget<E::BaseField>,
//   // IV::GTVar: AbsorbGadget<E::BaseField>,
//   //<IV as ark_r1cs_std::pairing::PairingVar<E>>::GTVar: AbsorbGadget<<E as Pairing>::BaseField>
// {
//   fn generate_constraints(
//     self,
//     cs: ConstraintSystemRef<<E as Pairing>::BaseField>,
//   ) -> Result<(), SynthesisError> {
//     // allocate point
//     let mut point_var = Vec::new();
//     for p in self.point.clone().into_iter() {
//       let scalar_in_fq = &E::BaseField::from_bigint(
//         <E::BaseField as PrimeField>::BigInt::from_bits_le(p.into_bigint().to_bits_le().as_slice()),
//       )
//       .unwrap();
//       let p_var = FpVar::new_input(cs.clone(), || Ok(scalar_in_fq))?;
//       point_var.push(p_var);
//     }
//     let len = point_var.len();
//     let odd = if len % 2 == 1 { 1 } else { 0 };
//     let a_var = &point_var[0..len / 2 + odd];
//     let b_var = &point_var[len / 2 + odd..len];

//     // start mipp verify
//     // start allocate struct mipp proof
//     // allocate comms_u
//     let mut comms_u_var = Vec::new();
//     for (first, second) in self.mipp_proof.comms_u.clone().into_iter() {
//       let first_var = IV::G1Var::new_input(cs.clone(), || Ok(first))?;
//       let second_var = IV::G1Var::new_input(cs.clone(), || Ok(second))?;
//       comms_u_var.push((first_var, second_var));
//     }
//     // allocate comms_t
//     let mut comms_t_var = Vec::new();
//     for (first, second) in self.mipp_proof.comms_t.clone().into_iter() {
//       let first_var = IV::GTVar::new_input(cs.clone(), || Ok(first))?;
//       let second_var = IV::GTVar::new_input(cs.clone(), || Ok(second))?;
//       comms_t_var.push((first_var, second_var));
//     }

//     let mut xs = Vec::new();
//     let mut xs_inv = Vec::new();
//     let mut final_y = E::BaseField::one();
//     let mut final_y_var = FpVar::new_input(cs.clone(), || Ok(final_y))?;

//     // start allocate T
//     let T_var = IV::GTVar::new_input(cs.clone(), || Ok(self.T))?;
//     // start allocate U.g_product
//     let U_g_product_var = IV::G1Var::new_input(cs.clone(), || Ok(self.U.g_product))?;

//     let mut final_res_var: MippTUVar<E, IV> = MippTUVar {
//       tc: T_var.clone(),
//       uc: U_g_product_var.clone(),
//     };

//     let params: PoseidonConfig<E::BaseField> = params_to_base_field::<E>();
//     let mut transcript_var = PoseidonSpongeVar::new(cs.clone(), &params);
//     transcript_var.absorb(&U_g_product_var);

//     for (i, (comm_u, comm_t)) in comms_u_var.iter().zip(comms_t_var.iter()).enumerate() {
//       let (comm_u_l, comm_u_r) = comm_u;
//       let (comm_t_l, comm_t_r) = comm_t;
//       // Fiat-Shamir challenge

//       transcript_var.absorb(comm_u_l);
//       transcript_var.absorb(comm_u_r);
//       // ATTENTION
//       let comm_t_l_bit = comm_t_l.to_bytes()?;
//       transcript_var.absorb(&comm_t_l_bit);
//       let comm_t_r_bit = comm_t_r.to_bytes()?;
//       transcript_var.absorb(&comm_t_r_bit);
//       // transcript_var.absorb(comm_t_r);
//       let c_inv_var = transcript_var.squeeze_field_elements(1).unwrap().remove(0);
//       let c_var = c_inv_var.inverse().unwrap();

//       xs.push(c_var.clone());
//       xs_inv.push(c_inv_var.clone());

//       let one_var = FpVar::new_input(cs.clone(), || Ok(E::BaseField::one()))?;
//       final_y_var *= one_var + c_inv_var.mul(&point_var[i]) - &point_var[i];
//     }

//     enum Op<'a, E: Pairing, IV: PairingVar<E>> {
//       TC(&'a IV::GTVar, FpVar<<E>::BaseField>),
//       UC(&'a IV::G1Var, &'a FpVar<<E>::BaseField>),
//     }

//     let res_var = comms_t_var
//       .iter()
//       .zip(comms_u_var.iter())
//       .zip(xs.iter().zip(xs_inv.iter()))
//       .flat_map(|((comm_t, comm_u), (c, c_inv))| {
//         let (comm_t_l, comm_t_r) = comm_t;
//         let (comm_u_l, comm_u_r) = comm_u;

//         // we multiple left side by x^-1 and right side by x
//         vec![
//           Op::TC(comm_t_l, c_inv.clone()),
//           Op::TC(comm_t_r, c.clone()),
//           Op::UC(comm_u_l, c_inv),
//           Op::UC(comm_u_r, c),
//         ]
//       })
//       .fold(MippTUVar::<E, IV>::default(), |mut res, op: Op<E, IV>| {
//         match op {
//           Op::TC(tx, c) => {
//             // let bits_c = c_var.to_bits_le()?; let exp = t_var.pow_le(&bits_c)?;
//             let tx = tx.pow_le(&c.to_bits_le().unwrap()).unwrap();
//             res.tc.mul_assign(&tx);
//           }
//           Op::UC(zx, c) => {
//             let uxp = zx.scalar_mul_le(c.to_bits_le().unwrap().iter()).unwrap();
//             res.uc.add_assign(&uxp);
//           }
//         }
//         res
//       });

//     let ref_final_res_var = &mut final_res_var;
//     ref_final_res_var.merge(&res_var);

//     let mut rs: Vec<FpVar<<E>::BaseField>> = Vec::new();
//     let m = xs_inv.len();
//     for _i in 0..m {
//       let r = transcript_var.squeeze_field_elements(1).unwrap().remove(0);
//       rs.push(r);
//     }

//     let one_var = FpVar::new_input(cs.clone(), || Ok(E::BaseField::one()))?;

//     // let rs_var = rs.clone();
//     let v_var: FpVar<<E as Pairing>::BaseField> = (0..m)
//       .into_iter()
//       .map(|i| one_var.clone() + (&rs[i]).mul(&xs_inv[m - i - 1]) - &rs[i])
//       .fold(one_var.clone(), |acc, x| acc * x);

//     let comm_h = CommitmentG2::<E> {
//       nv: m,
//       h_product: self.mipp_proof.final_h,
//     };

//     let check_h = check_2_gadget::<E, IV>(
//       cs.clone(),
//       self.vk.clone(),
//       &comm_h,
//       &rs,
//       v_var,
//       &self.mipp_proof.pst_proof_h,
//     );
//     assert!(check_h == true);

//     let final_a_var = IV::G1Var::new_input(cs.clone(), || Ok(self.mipp_proof.final_a))?;
//     let final_u_var = final_a_var
//       .scalar_mul_le(final_y_var.to_bits_le().unwrap().iter())
//       .unwrap();

//     let final_h_var = IV::G2Var::new_input(cs.clone(), || Ok(self.mipp_proof.final_h))?;

//     let final_u_var_prep = IV::prepare_g1(&final_a_var).unwrap();
//     let final_h_var_prep = IV::prepare_g2(&final_h_var).unwrap();

//     let final_t_var = IV::pairing(final_u_var_prep, final_h_var_prep).unwrap();
//     let check_t;

//     if () == ref_final_res_var.tc.enforce_equal(&final_t_var).unwrap() {
//       check_t = true;
//     } else {
//       check_t = false;
//     }
//     assert!(check_t == true);

//     let check_u;
//     if () == ref_final_res_var.uc.enforce_equal(&final_u_var).unwrap() {
//       check_u = true;
//     } else {
//       check_u = false;
//     }
//     assert!(check_u == true);

//     let mut a_rev_var = a_var.to_vec().clone();
//     a_rev_var.reverse();

//     // MAKE PST CHECKKK
//     let res_var = check_gadget::<E, IV>(
//       cs.clone(),
//       self.vk,
//       self.U,
//       &a_rev_var,
//       self.v,
//       self.pst_proof,
//     );
//     assert!(res_var.unwrap() == true);
//     Ok(())
//   }
// }

// fn check_2_gadget<E: Pairing, IV: PairingVar<E>>(
//   cs: ConstraintSystemRef<E::BaseField>,
//   vk: VerifierKey<E>,
//   commitment: &CommitmentG2<E>,
//   point_var: &Vec<FpVar<<E>::BaseField>>,
//   value_var: FpVar<<E as Pairing>::BaseField>,
//   proof: &ProofG1<E>,
// ) -> bool
// where
//   IV::G1Var: CurveVar<E::G1, E::BaseField>,
//   IV::G2Var: CurveVar<E::G2, E::BaseField>,
//   IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
// {
//   let vk_g_var = IV::G1Var::new_input(cs.clone(), || Ok(vk.g)).unwrap();
//   let vk_h_var = IV::G2Var::new_input(cs.clone(), || Ok(vk.h)).unwrap();
//   let mut vk_gmask_var = Vec::new();
//   for g_mask in vk.g_mask_random.clone().into_iter() {
//     let g_mask_var = IV::G1Var::new_input(cs.clone(), || Ok(g_mask)).unwrap();
//     vk_gmask_var.push(g_mask_var);
//   }
//   // allocate commitment
//   let com_g2_prod_var = IV::G2Var::new_input(cs.clone(), || Ok(commitment.h_product)).unwrap();

//   let pair_right_op = com_g2_prod_var
//     - (vk_h_var
//       .scalar_mul_le(value_var.to_bits_le().unwrap().iter())
//       .unwrap());
//   let right_prepared = IV::prepare_g2(&pair_right_op).unwrap();
//   let left_prepared = IV::prepare_g1(&vk_g_var).unwrap();
//   let left = IV::pairing(left_prepared, right_prepared).unwrap();

//   let mut h_mul_var = Vec::new();

//   for p in point_var.into_iter() {
//     let x = vk_h_var
//       .scalar_mul_le(p.to_bits_le().unwrap().iter())
//       .unwrap();
//     h_mul_var.push(x);
//   }
//   let h_mask_random = vk.h_mask_random[vk.nv - point_var.len()..].to_vec();
//   let mut h_mask_random_var = Vec::new();
//   for h_mask in h_mask_random.clone().into_iter() {
//     let h_mask_var = IV::G2Var::new_input(cs.clone(), || Ok(h_mask)).unwrap();
//     h_mask_random_var.push(h_mask_var);
//   }
//   let pairing_rights_var: Vec<_> = (0..vk.nv)
//             .map(|i| h_mask_random_var[i].clone() - h_mul_var[i].clone()) //.map(|i| vk_gmask_var[i].clone() - g_mul_var[i].clone())
//             .collect();
//   let pairing_rights_var: Vec<IV::G2PreparedVar> = pairing_rights_var
//     .into_iter()
//     .map(|p| IV::prepare_g2(&p).unwrap())
//     .collect();
//   let mut proofs_var = Vec::new();
//   for p in proof.proofs.clone().into_iter() {
//     let proof_var = IV::G1Var::new_input(cs.clone(), || Ok(p)).unwrap();
//     proofs_var.push(proof_var);
//   }
//   let pairing_lefts_var: Vec<IV::G1PreparedVar> = proofs_var
//     .into_iter()
//     .map(|p| IV::prepare_g1(&p).unwrap())
//     .collect();

//   let right_ml = IV::miller_loop(&pairing_lefts_var, &pairing_rights_var).unwrap();
//   let right = IV::final_exponentiation(&right_ml).unwrap();

//   if () == left.enforce_equal(&right).unwrap() {
//     true
//   } else {
//     false
//   }
// }

// fn check_gadget<E: Pairing, IV: PairingVar<E>>(
//   cs: ConstraintSystemRef<E::BaseField>,
//   vk: VerifierKey<E>,
//   commitment: Commitment<E>,
//   point_var: &Vec<FpVar<<E>::BaseField>>,
//   value: E::ScalarField,
//   proof: Proof<E>,
// ) -> Result<bool, Error>
// where
//   IV::G1Var: CurveVar<E::G1, E::BaseField>,
//   IV::G2Var: CurveVar<E::G2, E::BaseField>,
//   IV::GTVar: FieldVar<E::TargetField, E::BaseField>,
// {
//   let vk_g_var = IV::G1Var::new_input(cs.clone(), || Ok(vk.g))?;
//   let vk_h_var = IV::G2Var::new_input(cs.clone(), || Ok(vk.h))?;
//   let mut vk_gmask_var = Vec::new();
//   for g_mask in vk.g_mask_random.clone().into_iter() {
//     let g_mask_var = IV::G1Var::new_input(cs.clone(), || Ok(g_mask))?;
//     vk_gmask_var.push(g_mask_var);
//   }
//   // allocate commitment
//   let com_g1_prod_var = IV::G1Var::new_input(cs.clone(), || Ok(commitment.g_product))?;
//   // allocate value
//   let scalar_in_fq = &E::BaseField::from_bigint(
//     <E::BaseField as PrimeField>::BigInt::from_bits_le(value.into_bigint().to_bits_le().as_slice()),
//   )
//   .unwrap();
//   let value_var = FpVar::new_input(cs.clone(), || Ok(scalar_in_fq))?;
//   // allocate proof
//   let mut proofs_var = Vec::new();
//   for proof in proof.proofs.clone().into_iter() {
//     let proof_var = IV::G2Var::new_witness(cs.clone(), || Ok(proof))?;
//     proofs_var.push(proof_var);
//   }
//   // start operation on circuit
//   let pair_left_op = com_g1_prod_var - (vk_g_var.scalar_mul_le(value_var.to_bits_le()?.iter())?);
//   let left_prepared = IV::prepare_g1(&pair_left_op)?;
//   let right_prepared = IV::prepare_g2(&vk_h_var)?;
//   let left = IV::pairing(left_prepared, right_prepared)?;

//   //calculating msm with framework function outside the circuit
//   // let scalar_size = E::ScalarField::MODULUS_BIT_SIZE as usize;
//   // let window_size = FixedBase::get_mul_window_size(self.vk.nv);

//   // let g_table = FixedBase::get_window_table(scalar_size, window_size, self.vk.g.into_group());
//   // let g_mul: Vec<E::G1> =
//   //     FixedBase::msm(scalar_size, window_size, &g_table, self.point.as_slice());

//   //calculate basic msm
//   // let mut res = Vec::new();
//   // for s in point.into_iter() {
//   //     res.push(vk.g.mul(s));
//   // }

//   //check basic msm with basic vector
//   //assert_eq!(res, g_mul);

//   let mut res_var = Vec::new();

//   for p in point_var.into_iter() {
//     let x = vk_g_var.scalar_mul_le(p.to_bits_le()?.iter())?;
//     res_var.push(x);
//   }

//   //do msm with circuit variable
//   // let mut g_mul_var = Vec::new();
//   // for g_m in g_mul.clone().into_iter() {
//   //     let g_m_var = IV::G1Var::new_witness(cs.clone(), || Ok(g_m))?;
//   //     g_mul_var.push(g_m_var);
//   // }

//   //assert vector calculated with msm and allocated is equal to msm calculated locally with variable
//   //res_var.enforce_equal(&g_mul_var)?;

//   //computing other part of the circuit
//   let pairing_lefts_var: Vec<_> = (0..vk.nv)
//             .map(|i| vk_gmask_var[i].clone() - res_var[i].clone()) //.map(|i| vk_gmask_var[i].clone() - g_mul_var[i].clone())
//             .collect();

//   let mut pairing_lefts_prep = Vec::new();
//   for var in pairing_lefts_var.clone().into_iter() {
//     pairing_lefts_prep.push(IV::prepare_g1(&var).unwrap());
//   }

//   let mut pairing_right_prep = Vec::new();
//   for var in proofs_var.clone().into_iter() {
//     pairing_right_prep.push(IV::prepare_g2(&var).unwrap());
//   }

//   let right_ml = IV::miller_loop(&pairing_lefts_prep, &pairing_right_prep)?;
//   let right = IV::final_exponentiation(&right_ml).unwrap();
//   if () == left.enforce_equal(&right).unwrap() {
//     Ok(true)
//   } else {
//     Ok(false)
//   }
// }

// #[cfg(test)]
// mod tests {
//   use crate::ark_std::UniformRand;
//   use ark_bls12_377::{Bls12_377, Config, FqConfig};
//   use ark_bls12_381::Bls12_381;
//   use ark_ec::pairing::Pairing;
//   use ark_ec::short_weierstrass::Affine;
//   use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
//   use ark_std::rand::RngCore;
//   use ark_std::test_rng;
//   use ark_std::vec::Vec;
//   type E = Bls12_377;
//   use ark_relations::r1cs::ConstraintSystem;
//   type Fr = <E as Pairing>::ScalarField;
//   use super::*;
//   use ark_ec::bls12::Bls12;
//   type IV = ark_bls12_377::constraints::PairingVar;
//   use crate::ark_std::rand::SeedableRng;
//   use ark_bw6_761::BW6_761 as P;
//   use ark_crypto_primitives::snark::SNARK;
//   use ark_ff::Field;
//   use ark_ff::{MontBackend, QuadExtField, ToConstraintField};
//   use ark_groth16::prepare_verifying_key;
//   use ark_groth16::Groth16;
//   type Fp = <E as Pairing>::BaseField;
//   use super::*;
//   type F = ark_bls12_377::Fr;
//   use crate::parameters::poseidon_params;
//   use crate::sqrt_pst::Polynomial;

//   #[test]
//   fn check_commit() {
//     // check odd case
//     check_sqrt_poly_commit(5);
//   }

//   fn check_sqrt_poly_commit(num_vars: u32) {
//     let mut rng = ark_std::test_rng();
//     let len = 2_usize.pow(num_vars);
//     let Z: Vec<F> = (0..len).into_iter().map(|_| F::rand(&mut rng)).collect();
//     let r: Vec<F> = (0..num_vars)
//       .into_iter()
//       .map(|_| F::rand(&mut rng))
//       .collect();

//     let gens = MultilinearPC::<E>::setup(3, &mut rng);
//     let (ck, vk) = MultilinearPC::<E>::trim(&gens, 3);

//     let mut pl = Polynomial::from_evaluations(&Z.clone());

//     let v = pl.eval(&r);

//     let (comm_list, t) = pl.commit(&ck);

//     let params = poseidon_params();
//     let mut prover_transcript = PoseidonTranscript::new(&params);

//     let (u, pst_proof, mipp_proof) = pl.open(&mut prover_transcript, comm_list, &ck, &r, &t);

//     let mut verifier_transcript = PoseidonTranscript::new(&params);

//     let circuit = TestudoCommVerifier {
//       vk,
//       U: u,
//       point: r,
//       v,
//       pst_proof,
//       mipp_proof,
//       T: t,
//       _iv: PhantomData::<IV>,
//     };

//     let mut rng2 = rand_chacha::ChaChaRng::seed_from_u64(1776);
//     let (opk, ovk) = Groth16::<P>::circuit_specific_setup(circuit.clone(), &mut rng2).unwrap();
//     let opvk = Groth16::<P>::process_vk(&ovk).unwrap();
//     let oproof = Groth16::<P>::prove(&opk, circuit, &mut rng2).unwrap();
//     let public_input = vec![];
//     assert!(Groth16::<P>::verify_proof(&opvk, &oproof, &public_input).unwrap());
//   }
// }
