use std::{rc::Rc, vec};

use crate::{
    loader::halo2::{self},
    protocol::halo2::test::{
        kzg::{BITS, LIMBS},
        MainGateWithRangeConfig,
    },
    scheme::kzg::{self, CircomPlonkAccumulationScheme},
};
use group::Curve;
use halo2_curves::bn256::{Fr, G1Affine, G1};
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{self, Circuit},
    transcript::TranscriptReadBuffer,
};
use halo2_wrong_maingate::RegionCtx;
use halo2_wrong_transcript::NativeRepresentation;
use itertools::Itertools;

const T: usize = 17;
const RATE: usize = 16;
const R_F: usize = 8;
const R_P: usize = 10;

type Halo2Loader<'a, 'b, C> = halo2::Halo2Loader<'a, 'b, C, LIMBS, BITS>;
type SameCurveAccumulation<C, L> = kzg::SameCurveAccumulation<C, L, LIMBS, BITS>;
type PoseidonTranscript<C, L, S, B> =
    halo2::PoseidonTranscript<C, L, S, B, NativeRepresentation, LIMBS, BITS, T, RATE, R_F, R_P>;
type BaseFieldEccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<C, LIMBS, BITS>;

pub struct SnarkWitness<C: Curve> {
    protocol: kzg::CircomProtocol<C>,
    proof: Value<Vec<u8>>,
    public_signals: Vec<Value<C::Scalar>>,
}

impl<C: Curve> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            proof: Value::unknown(),
            public_signals: vec![Value::unknown(); self.public_signals.len()],
        }
    }
}

fn accumulate<'a, 'b>(
    loader: &Rc<Halo2Loader<'a, 'b, G1Affine>>,
    strategy: &mut SameCurveAccumulation<G1, Rc<Halo2Loader<'a, 'b, G1Affine>>>,
    snark: &SnarkWitness<G1>,
) -> Result<(), plonk::Error> {
    let mut transcript = PoseidonTranscript::<G1Affine, Rc<Halo2Loader<G1Affine>>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let public_signals = snark
        .public_signals
        .iter()
        .map(|signal| loader.assign_scalar(*signal))
        .collect_vec();

    CircomPlonkAccumulationScheme::accumulate(
        &snark.protocol,
        loader,
        &public_signals,
        &mut transcript,
        strategy,
    )
    .map_err(|_| plonk::Error::Synthesis)?;

    Ok(())
}

struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
}

impl Accumulation {}

impl Circuit<Fr> for Accumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::configure::<Fr>(
            meta,
            vec![BITS / LIMBS],
            BaseFieldEccChip::<G1Affine>::rns().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        config.load_table(&mut layouter)?;
        println!("snrks {}", self.snarks.len());
        let (lhs, rhs) = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let ctx = RegionCtx::new(&mut region, &mut offset);

                let loader = Halo2Loader::<G1Affine>::new(config.ecc_config(), ctx);
                let mut strategy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    accumulate(&loader, &mut strategy, snark)?;
                }
                let (lhs, rhs) = strategy.finalize(self.g1);

                loader.print_row_metering();
                println!("Total: {}", offset);

                Ok((lhs, rhs))
            },
        )?;

        let ecc_chip = BaseFieldEccChip::<G1Affine>::new(config.ecc_config());
        ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        loader::{
            native::{self, NativeLoader},
            ScalarLoader,
        },
        util::{fe_to_limbs, read_proof_instances, read_protocol, read_public_signals},
    };
    use ff::{Field, PrimeField};
    use halo2_curves::bn256::Fq;
    use halo2_proofs::dev::MockProver;
    use num::BigUint;
    use rand::SeedableRng;
    use rand_chacha::{rand_core::RngCore, ChaCha12Rng};

    #[test]
    fn circom_accumulation() {
        let protocol = read_protocol("./test-files/verification_key.json");
        let native_snarks: Vec<(Vec<u8>, Vec<Fr>)> =
            read_proof_instances(vec!["./test-files/proof.json".to_string()])
                .iter()
                .zip(read_public_signals(vec![
                    "./test-files/public.json".to_string()
                ]))
                .map(|(proof, public)| (proof.clone(), public))
                .collect();
        let snarks: Vec<SnarkWitness<G1>> =
            read_proof_instances(vec!["./test-files/proof.json".to_string()])
                .iter()
                .zip(read_public_signals(vec![
                    "./test-files/public.json".to_string()
                ]))
                .map(|(proof, public)| SnarkWitness {
                    protocol: protocol.clone(),
                    proof: Value::known(proof.clone()),
                    public_signals: public.iter().map(|v| Value::known(*v)).collect(),
                })
                .collect();

        // Perform `Native` to check validity and calculate instance values.
        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        let native_loader = NativeLoader {};
        for snark in native_snarks {
            let mut t =
                PoseidonTranscript::<G1Affine, NativeLoader, _, _>::init(snark.0.as_slice());
            CircomPlonkAccumulationScheme::accumulate(
                &protocol,
                &native_loader,
                &snark
                    .1
                    .iter()
                    .map(|el| native_loader.load_const(el))
                    .collect(),
                &mut t,
                &mut strategy,
            )
            .unwrap();
        }

        // strategy.decide(g1, g2, s_g2)

        let (lhs, rhs) = strategy.finalize(G1::generator());
        let instance = [
            lhs.to_affine().x,
            lhs.to_affine().y,
            rhs.to_affine().x,
            rhs.to_affine().y,
        ]
        .map(fe_to_limbs::<Fq, Fr, LIMBS, BITS>)
        .concat();

        // Generate proof and verify

        let circuit = Accumulation {
            g1: G1Affine::generator(),
            snarks,
        };
        let k = 20;

        const ZK: bool = true;
        MockProver::run::<_, ZK>(k, &circuit, vec![instance])
            .unwrap()
            .assert_satisfied();

        // TODO:
        // (0) Provide instance values: LHS and RHS
        // (1) halo2_kzg_create_snark to create snark proof
        // (2) halo2_kzg_native_verify to verify the snakr proof and accumulation pairing
    }

   
}
