use group::Curve;

use crate::{
    loader::Loader,
    scheme::kzg::accumulation::{AccumulationScheme, AccumulationStrategy, Accumulator},
    util::TranscriptRead,
};

pub struct CircomPlonkProof<C: Curve, L: Loader<C>> {
    public_signals: Vec<L::LoadedScalar>,
    A: L::LoadedEcPoint,
    B: L::LoadedEcPoint,
    C: L::LoadedEcPoint,
    Z: L::LoadedEcPoint,
    T1: L::LoadedEcPoint,
    T2: L::LoadedEcPoint,
    T3: L::LoadedEcPoint,
    Wxi: L::LoadedEcPoint,
    Wxiw: L::LoadedEcPoint,
    eval_a: L::LoadedScalar,
    eval_b: L::LoadedScalar,
    eval_c: L::LoadedScalar,
    eval_s1: L::LoadedScalar,
    eval_s2: L::LoadedScalar,
    eval_zw: L::LoadedScalar,
    eval_r: L::LoadedScalar,
}

impl<C: Curve, L: Loader<C>> CircomPlonkProof<C, L> {
    fn read<T: TranscriptRead<C, L>>(
        public_signals: &Vec<L::LoadedScalar>,
        transcript: &mut T,
    ) -> Result<Self, Error> {
        public_signals
            .iter()
            .for_each(|signal| transcript.common_scalar(signal));

        let A = transcript.read_ec_point()?;
        let B = transcript.read_ec_point()?;
        let C = transcript.read_ec_point()?;

        let beta = transcript.squeeze_challenge();

        transcript.common_scalar(beta);
        let gamma = transcript.squeeze_challenge();

        let Z = transcript.read_ec_point()?;
        let alpha = transcript.squeeze_challenge();

        let T1 = transcript.read_ec_point()?;
        let T2 = transcript.read_ec_point()?;
        let T3 = transcript.read_ec_point()?;
        let xi = transcript.squeeze_challenge();

        let eval_points: [L::LoadedScalar; 7] = transcript.read_n_scalars(7).into()?;
        let v = transcript.squeeze_challenge();

        let Wxi = transcript.read_ec_point()?;
        let Wxiw = transcript.read_ec_point()?;
        let u = transcript.squeeze_challenge();

        Ok(Self {
            public_signals,
            A,
            B,
            C,
            Z,
            T1,
            T2,
            T3,
            Wxi,
            Wxiw,
            eval_a: eval_points[0],
            eval_b: eval_points[1],
            eval_c: eval_points[2],
            eval_s1: eval_points[3],
            eval_s2: eval_points[4],
            eval_zw: eval_points[5],
            eval_r: eval_points[6],
        })
    }
}

#[derive(Default)]
pub struct CircomPlonkAccumulationScheme;

impl<C, L, T, S> AccumulationScheme for CircomPlonkAccumulationScheme
where
    C: Curve,
    L: Loader,
    T: TranscriptRead<C, L>,
    S: AccumulationStrategy<C, L, CircomPlonkProof<C, L>>,
{
    type Proof = CircomPlonkProof<C, L>;

    fn accumulate(
        protocol: &crate::protocol::Protocol<C>,
        loader: &L,
        public_signals: &Vec<L::LoadedScalar>,
        transcript: &mut T,
        strategy: &mut S,
    ) -> Result<S::Output, crate::Error> {
        let proof = CircomPlonkProof::read(public_signals, transcript)?;

        todo!()
    }
}
