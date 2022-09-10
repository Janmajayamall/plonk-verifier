use crate::{
    loader::{
        halo2::{self, test::MainGateWithRangeConfig},
        native::NativeLoader,
    },
    pcs::{
        kzg::{Accumulator, Gwc19, KzgOnSameCurve, PreAccumulator},
        AccumulationStrategy, PreAccumulator as _,
    },
    system::{
        self,
        circom::{
            compile,
            test::testdata::{Testdata, TESTDATA_HALO2},
            Proof, PublicSignals, VerifyingKey,
        },
    },
    util::{arithmetic::fe_to_limbs, transcript::Transcript, Itertools},
    verifier::{self, PlonkVerifier},
    Protocol,
};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    dev::MockProver,
    plonk::{self, Circuit, ConstraintSystem},
};
use halo2_wrong_ecc::{
    self,
    integer::rns::Rns,
    maingate::{RangeInstructions, RegionCtx},
};
use halo2_wrong_transcript::NativeRepresentation;
use std::rc::Rc;

const LIMBS: usize = 4;
const BITS: usize = 68;
const T: usize = 17;
const RATE: usize = 16;
const R_F: usize = 8;
const R_P: usize = 10;

type Plonk = verifier::Plonk<KzgOnSameCurve<Bn256, Gwc19<Bn256>, LIMBS, BITS>>;

type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
type Halo2Loader<'a> = halo2::Halo2Loader<'a, G1Affine, Fr, BaseFieldEccChip>;
type PoseidonTranscript<L, S, B> = system::circom::transcript::halo2::PoseidonTranscript<
    G1Affine,
    Fr,
    NativeRepresentation,
    L,
    S,
    B,
    LIMBS,
    BITS,
    T,
    RATE,
    R_F,
    R_P,
>;

pub struct SnarkWitness {
    protocol: Protocol<G1Affine>,
    instances: Vec<Vec<Value<Fr>>>,
    proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }
}

pub fn accumulate<'a>(
    g1: &G1Affine,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &SnarkWitness,
    curr_accumulator: Option<PreAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
) -> PreAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let instances = snark
        .instances
        .iter()
        .map(|instances| {
            instances
                .iter()
                .map(|instance| loader.assign_scalar(*instance))
                .collect_vec()
        })
        .collect_vec();
    let proof = Plonk::read_proof(&snark.protocol, &instances, &mut transcript).unwrap();
    let mut accumulator = Plonk::succint_verify(g1, &snark.protocol, &instances, &proof).unwrap();
    if let Some(curr_accumulator) = curr_accumulator {
        accumulator += curr_accumulator * transcript.squeeze_challenge();
    }
    accumulator
}

struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
}

impl Accumulation {
    pub fn new<const N: usize>(testdata: Testdata<N>) -> Self {
        let vk: VerifyingKey<Bn256> = serde_json::from_str(testdata.vk).unwrap();
        let protocol = compile(&vk);

        let public_signals = testdata
            .public_signals
            .iter()
            .map(|public_signals| {
                serde_json::from_str::<PublicSignals<Fr>>(public_signals).unwrap()
            })
            .collect_vec();
        let proofs = testdata
            .proofs
            .iter()
            .map(|proof| {
                serde_json::from_str::<Proof<Bn256>>(proof)
                    .unwrap()
                    .to_compressed_le()
            })
            .collect_vec();

        let accumulator = public_signals
            .iter()
            .zip(proofs.iter())
            .fold(None, |curr_accumulator, (public_signals, proof)| {
                let instances = [public_signals.clone().to_vec()];
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _, _>::new(proof.as_slice());
                let proof = Plonk::read_proof(&protocol, &instances, &mut transcript).unwrap();
                let mut accumulator =
                    Plonk::succint_verify(&vk.svk(), &protocol, &instances, &proof).unwrap();
                if let Some(curr_accumulator) = curr_accumulator {
                    accumulator += curr_accumulator * transcript.squeeze_challenge();
                }
                Some(accumulator)
            })
            .unwrap()
            .evaluate();

        assert!(
            <KzgOnSameCurve::<Bn256, Gwc19<Bn256>, LIMBS, BITS> as AccumulationStrategy<
                _,
                NativeLoader,
                _,
            >>::finalize(&vk.dk(), accumulator.clone())
            .unwrap()
        );

        let Accumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            g1: vk.svk(),
            snarks: public_signals
                .into_iter()
                .zip(proofs)
                .map(|(public_signals, proof)| SnarkWitness {
                    protocol: protocol.clone(),
                    instances: vec![public_signals
                        .to_vec()
                        .into_iter()
                        .map(Value::known)
                        .collect_vec()],
                    proof: Value::known(proof),
                })
                .collect(),
            instances,
        }
    }
}

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
            instances: self.instances.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::configure::<Fr>(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let range_chip = config.range_chip();
        let ecc_chip = config.ecc_chip();

        range_chip.load_table(&mut layouter)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |region| {
                let offset = 0;
                let ctx = RegionCtx::new(region, offset);

                let loader = Halo2Loader::new(ecc_chip.clone(), ctx);
                let accumulator = self
                    .snarks
                    .iter()
                    .fold(None, |accumulator, snark| {
                        Some(accumulate(&self.g1, &loader, snark, accumulator))
                    })
                    .unwrap();
                let Accumulator { lhs, rhs } = accumulator.evaluate();

                loader.print_row_metering();
                println!("Total row cost: {}", loader.ctx().offset());

                Ok((lhs.into_normalized(), rhs.into_normalized()))
            },
        )?;

        ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

        Ok(())
    }
}

#[test]
fn test() {
    let k = 21;
    let circuit = Accumulation::new(TESTDATA_HALO2);

    let _mock_prover = MockProver::run(k, &circuit, vec![circuit.instances.clone()]).unwrap();
    // FIXME: Make sure either vk or proof doesn't contain ec point at infinity.
    // _mock_prover.assert_satisfied();
}
