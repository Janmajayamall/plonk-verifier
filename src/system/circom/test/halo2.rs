use crate::{
    loader::{
        halo2::{self, test::MainGateWithRangeConfig},
        native::NativeLoader,
    },
    pcs::{
        self,
        kzg::{
            Gwc19, Kzg, KzgAccumulator, KzgAs, KzgAsProvingKey, KzgAsVerifyingKey, KzgDecidingKey,
            KzgSuccinctVerifyingKey, LimbsEncoding,
        },
        AccumulationScheme, AccumulationSchemeProver, Decider,
    },
    system::{
        self,
        circom::{
            compile,
            test::testdata::{Testdata, TESTDATA_HALO2_CORRECT, TESTDATA_HALO2_INCORRECT},
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
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::ParamsKZG,
    },
};
use halo2_wrong_ecc::{
    self,
    integer::rns::Rns,
    maingate::{MainGateInstructions, RangeInstructions, RegionCtx},
};
use halo2_wrong_transcript::NativeRepresentation;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{iter, rc::Rc};

const LIMBS: usize = 4;
const BITS: usize = 68;
const T: usize = 17;
const RATE: usize = 16;
const R_F: usize = 8;
const R_P: usize = 10;

type Pcs = Kzg<Bn256, Gwc19>;
type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type As = KzgAs<Pcs>;
type AsPk = KzgAsProvingKey<G1Affine>;
type AsVk = KzgAsVerifyingKey;
type Plonk = verifier::Plonk<Pcs, LimbsEncoding<LIMBS, BITS>>;

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

    pub fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}

pub fn accumulate<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness],
    as_vk: &AsVk,
    as_proof: Value<&'_ [u8]>,
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec()
    };

    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let instances = assign_instances(&snark.instances);
            let mut transcript =
                PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(loader, snark.proof());
            let proof =
                Plonk::read_proof(svk, &snark.protocol, &instances, &mut transcript).unwrap();
            Plonk::succinct_verify(svk, &snark.protocol, &instances, &proof).unwrap()
        })
        .collect_vec();

    let acccumulator = if accumulators.len() > 1 {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(loader, as_proof);
        let proof = As::read_proof(as_vk, &accumulators, &mut transcript).unwrap();
        As::verify(as_vk, &accumulators, &proof).unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    acccumulator
}

struct Accumulation {
    svk: Svk,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
    as_vk: AsVk,
    as_proof: Value<Vec<u8>>,
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

        let mut accumulators = public_signals
            .iter()
            .zip(proofs.iter())
            .flat_map(|(public_signal, proof)| {
                let instances = [public_signal.clone().to_vec(); 1];
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _, _>::new(proof.as_slice());
                let proof =
                    Plonk::read_proof(&vk.svk().into(), &protocol, &instances, &mut transcript)
                        .unwrap();
                Plonk::succinct_verify(&vk.svk().into(), &protocol, &instances, &proof).unwrap()
            })
            .collect_vec();

        let as_pk = AsPk::new(Some(vk.apk().into()));
        let (accumulator, as_proof) = if accumulators.len() > 1 {
            let mut transcript = PoseidonTranscript::<NativeLoader, _, _>::new(Vec::new());
            let accumulator = As::create_proof(
                &as_pk,
                &accumulators,
                &mut transcript,
                ChaCha20Rng::from_seed(Default::default()),
            )
            .unwrap();
            (accumulator, Value::known(transcript.finalize()))
        } else {
            (accumulators.pop().unwrap(), Value::unknown())
        };

        assert!(Pcs::decide(&vk.dk().into(), accumulator.clone()));

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            svk: vk.svk().into(),
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
            as_vk: as_pk.vk(),
            as_proof,
        }
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for Accumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: self.instances.clone(),
            as_vk: self.as_vk,
            as_proof: Value::unknown(),
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
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let KzgAccumulator { lhs, rhs } = accumulate(
                    &self.svk,
                    &loader,
                    &self.snarks,
                    &self.as_vk,
                    self.as_proof(),
                );

                loader.print_row_metering();
                println!("Total row cost: {}", loader.ctx().offset());

                Ok((lhs.assigned(), rhs.assigned()))
            },
        )?;

        for (limb, row) in iter::empty()
            .chain(lhs.x().limbs())
            .chain(lhs.y().limbs())
            .chain(rhs.x().limbs())
            .chain(rhs.y().limbs())
            .zip(0..)
        {
            main_gate.expose_public(layouter.namespace(|| ""), limb.into(), row)?;
        }

        Ok(())
    }
}

#[test]
fn test() {
    let k = 21;
    let circuit = Accumulation::new(TESTDATA_HALO2_CORRECT);
    // let circuit = Accumulation::new(TESTDATA_HALO2_CORRECT);

    let _mock_prover = MockProver::run(k, &circuit, vec![circuit.instances.clone()]).unwrap();
    // FIXME: Make sure either vk or proof doesn't contain ec point at infinity.
    // _mock_prover.assert_satisfied();
}
