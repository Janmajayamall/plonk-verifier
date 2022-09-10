use std::rc::Rc;

use crate::{
    loader::{
        evm::{encode_calldata, EvmLoader},
        native::NativeLoader,
    },
    pcs::kzg::{Gwc19, KzgOnSameCurve},
    system::circom::{
        compile, test::testdata::TESTDATA_EVM, transcript::evm::EvmTranscript, Proof,
        PublicSignals, VerifyingKey,
    },
    verifier::{self, PlonkVerifier},
};
use ethereum_types::Address;
use foundry_evm::executor::{fork::MultiFork, Backend, ExecutorBuilder};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};

const LIMBS: usize = 4;
const BITS: usize = 68;

type Plonk = verifier::Plonk<KzgOnSameCurve<Bn256, Gwc19<Bn256>, LIMBS, BITS>>;

#[test]
fn test() {
    let vk: VerifyingKey<Bn256> = serde_json::from_str(TESTDATA_EVM.vk).unwrap();
    let protocol = compile(&vk);

    let [public_signal] = TESTDATA_EVM.public_signals.map(|public_signals| {
        serde_json::from_str::<PublicSignals<Fr>>(public_signals)
            .unwrap()
            .to_vec()
    });
    let [proof] = TESTDATA_EVM.proofs.map(|proof| {
        serde_json::from_str::<Proof<Bn256>>(proof)
            .unwrap()
            .to_uncompressed_be()
    });

    {
        let instances = [public_signal.clone()];
        let mut transcript = EvmTranscript::<G1Affine, NativeLoader, _, _>::new(proof.as_slice());
        let proof = Plonk::read_proof(&protocol, &instances, &mut transcript).unwrap();
        assert!(Plonk::verify(&vk.svk(), &vk.dk(), &protocol, &instances, &proof).unwrap());
    }

    let deployment_code = {
        let loader = EvmLoader::new::<Fq, Fr>();
        let mut transcript = EvmTranscript::<G1Affine, Rc<EvmLoader>, _, _>::new(loader.clone());
        let instances = transcript.load_instances(vec![public_signal.len()]);
        let proof = Plonk::read_proof(&protocol, &instances, &mut transcript).unwrap();
        Plonk::verify(&vk.svk(), &vk.dk(), &protocol, &instances, &proof).unwrap();
        loader.deployment_code()
    };

    let calldata = encode_calldata(&[public_signal], &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build(Backend::new(MultiFork::new().0, None));

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm
            .deploy(caller, deployment_code.into(), 0.into(), None)
            .unwrap()
            .address;
        let result = evm
            .call_raw(caller, verifier, calldata.into(), 0.into())
            .unwrap();

        dbg!(result.gas);

        !result.reverted
    };
    assert!(success);
}
