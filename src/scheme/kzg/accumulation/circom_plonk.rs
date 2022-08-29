use core::num;
use std::vec;

use group::Curve;
use halo2_curves::pasta::pallas::Scalar;
use itertools::Itertools;

use crate::{
    loader::{LoadedScalar, Loader},
    scheme::kzg::{
        accumulation::{AccumulationScheme, AccumulationStrategy, Accumulator},
        MSM,
    },
    util::TranscriptRead,
};

struct VerificationKey<C: Curve, L: Loader<C>> {
    // All Loaded values for the verification key.
    k: usize,
    n: usize,
    n_inv: L::LoadedScalar,
    omega: C::Scalar,
    omega_inv: C::Scalar,
    public_inputs_count: usize,
    k1: L::LoadedScalar,
    k2: L::LoadedScalar,
    Qm: L::LoadedEcPoint,
    Ql: L::LoadedEcPoint,
    Qr: L::LoadedEcPoint,
    Qo: L::LoadedEcPoint,
    Qc: L::LoadedEcPoint,
    S1: L::LoadedEcPoint,
    S2: L::LoadedEcPoint,
    S3: L::LoadedEcPoint,
    // Contains omega^j `for j in range(0, public_inputs.length)`.
    // This is to avoid more constraints.
    omegas: Vec<L::LoadedScalar>,
    // all `omegas` inversed
    omegas_inv: Vec<LoadedScalar>,
}

impl<C: Curve, L: Loader<C>> VerificationKey<C, L> {
    pub fn read() -> Self {
        todo!()
    }
}

pub struct Challenges<C: Curve, L: Loader<C>> {
    beta: L::LoadedScalar,
    alpha: L::LoadedScalar,
    gamma: L::LoadedScalar,
    xi: L::LoadedScalar,
    v: L::LoadedScalar,
    u: L::LoadedScalar,
}

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
    challenges: Challenges<C, L>,
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
            challenges: Challenges {
                beta,
                alpha,
                gamma,
                xi,
                v,
                u,
            },
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
        vk_key: &VerificationKey<C, L>,
        loader: &L,
        public_signals: &Vec<L::LoadedScalar>,
        transcript: &mut T,
        strategy: &mut S,
    ) -> Result<S::Output, crate::Error> {
        // perform necessary checks
        assert_eq!(public_signals.len(), vk_key.public_inputs_count);
        // 2  check that omegas length in `vk` match public inputs length

        let proof = CircomPlonkProof::read(public_signals, transcript)?;

        // xi^n
        let xi = proof.challenges.xi;
        let xi_power_n = xi.pow_constant(vk_key.n);

        // z_h(xi) = xi^n - 1;
        let one = loader.load_const(C::Scalar::one());
        let z_h_eval_xi = xi_power_n - one;

        // Compute first lagrange evaluation.
        // Snarkjs's plonk prover starts with `omega^0`
        // in permutation polynomial. Thus we compute
        // `L0(xi)` here.
        //
        // `L0(xi) = (xi^n) - 1 / (n * (xi - 1))`
        //
        // More info on this - https://github.com/ZK-Garage/plonk/blob/79dffa1bacbe73ab42e2d7e48194efe5c0070bd6/plonk-core/src/proof_system/proof.rs#L622
        let l1_eval_xi = {
            let denom = xi - one;
            z_h_eval_xi * denom.invert()
        };

        // Compute public input poly evaluation at `xi`.
        // We do this using `barycentric evaluation` approach.
        // For more details on this approach check following:
        //  (1) https://hackmd.io/@vbuterin/barycentric_evaluation
        //  (2) https://github.com/ZK-Garage/plonk/blob/79dffa1bacbe73ab42e2d7e48194efe5c0070bd6/plonk-core/src/proof_system/proof.rs#L635
        //
        // TODO: We store `omegas` in `vk`. We only need them at this
        // step of verification. This means we shall only load omages
        // omegas_inv for range (0..public_inputs.length). Implement this
        // optimization.
        let pi_poly_eval_xi = {
            // (xi^n - 1) / n
            //
            // TODO: store `n.invert()` in `vk` to avoid
            // having to constrain it in every accumulation step.
            let numerator = z_h_eval_xi * n.invert();

            // In case of no public inputs PI(x)
            // can be reduced to
            // PI(x) = (x^n - 1) / n
            if public_signals.len() == 0 {
                numerator
            } else {
                let denominator = {
                    let denoms = (0..public_signals.len())
                        .map(|index| {
                            // (xi - omega^j) * omega^-j => (omega^-j * xi - 1)
                            // for `j`th index.
                            let d = xi * vk_key.omegas_inv[index].unwrap();
                            let d = d - one;
                            d
                        })
                        .collect();
                    let denoms = loader.batch_invert(denoms);

                    // Computes
                    // `sum_of { pi_j * (xi * omega^-j - 1)^-1 }`
                    // for j in range 0..public_signals.len()
                    let mut sum = denoms[0] * public_signals[0];
                    denoms
                        .iter()
                        .skip(1)
                        .chain(public_signals.iter().skip(1))
                        .for_each(|d, pi| {
                            sum += d * pi;
                        });
                    sum
                };
                numerator * denominator
            }
        };

        // Compute pairing rhs
        let rhs = {
            // We first calculate all scalars and delay MSM
            // till end
            let ab = proof.eval_a * proof.eval_b;

            let alpha = proof.challenges.alpha;
            let alpha_square = proof.challenges.alpha.square();

            let scalar_batch_poly_commit_identity = {
                let a = proof.eval_a
                    + (proof.challenges.beta * proof.challenges.xi)
                    + proof.challenges.gamma;
                let b = proof.eval_b
                    + (proof.challenges.beta * vk_key.k1 * proof.challenges.xi)
                    + proof.challenges.gamma;
                let c = proof.eval_b
                    + (proof.challenges.beta * vk_key.k2 * proof.challenges.xi)
                    + proof.challenges.gamma;
                let val = a * b * c * alpha;
                let val2 = l1_eval_xi * alpha_square + proof.challenges.u;
                val + val2
            };

            let scalar_batch_poly_commit_permuted = {
                let a =
                    proof.eval_a + (proof.challenges.beta * proof.eval_s1) + proof.challenges.gamma;
                let b =
                    proof.eval_b + (proof.challenges.beta * proof.eval_s2) + proof.challenges.gamma;
                a * b * alpha * proof.eval_zw
            };
            let neg_scalar_batch_poly_commit_permuted = scalar_batch_poly_commit_permuted.neg();

            // powers of `v`
            let v_powers: vec![L::LoadedScalar; 5] = (1..6)
                .fold(proof.challenges.v, |acc, i| {
                    if i > 1 {
                        acc * proof.challenges.v
                    }
                })
                .into();

            let r0 = {
                let l1_alpha_sq = l1_eval_xi * alpha_square;

                // permutation product
                let p1 =
                    proof.eval_a + (proof.challenges.beta * proof.eval_s1) + proof.challenges.gamma;
                let p2 =
                    proof.eval_b + (proof.challenges.beta * proof.eval_s2) + proof.challenges.gamma;
                let p3 = (proof.eval_c + proof.challenges.gamma) * proof.eval_zw;
                let pp = p1 * p2 * p3 * alpha;

                pi_poly_eval_xi - l1_alpha_sq - pp
            };
            let neg_r0 = r0.neg();

            // -1`E` scalar
            let group_batch_eval_scalar = {
                let mut sum = neg_r0;
                sum = sum + (v[0] * proof.eval_a);
                sum = sum + (v[1] * proof.eval_b);
                sum = sum + (v[3] * proof.eval_c);
                sum = sum + (v[4] * proof.eval_s1);
                sum = sum + (v[5] * proof.eval_s2);
                sum = sum + (proof.challenges.u * proof.eval_zw);
                sum.neg()
            };

            let neg_z_h_eval_xi = z_h_eval_xi.neg();
            let neg_z_h_eval_xi_by_xi = neg_z_h_eval_xi * xi_power_n;
            let neg_z_h_eval_xi_by_xi_2n = neg_z_h_eval_xi * xi_power_n.square();

            let u_xi_omega = proof.challenges.u * proof.challenges.xi * vk_key.omega;

            // perform all msm
            // TODO: Fix the mess to use APIs properly
            vec![
                // W
                (proof.challenges.xi, proof.Wxi),
                // + Ww
                (u_xi_omega, proof.Wxiw),
                // + F
                // D
                (ab, vk_key.Qm),
                (proof.eval_a, vk_key.Ql),
                (proof.eval_b, vk_key.Qr),
                (proof.eval_c, vk_key.Qo),
                (one, Qc),
                (scalar_batch_poly_commit_identity, proof.Z),
                (scalar_batch_poly_commit_permuted, vk_key.S3),
                (neg_z_h_eval_xi, proof.T1),
                (neg_z_h_eval_xi_by_xi, proof.T2),
                (neg_z_h_eval_xi_by_xi_2n, proof.T3),
                // gates + permutation
                (v_powers[0], proof.A),
                (v_powers[1], proof.B),
                (v_powers[2], proof.C),
                (v_powers[3], vk_key.S1),
                (v_powers[4], vk_key.S2),
                // - E
                (one.neg(), loader.ec_point_load_one()),
            ]
            .iter()
            .map(|pair| MSM::base(pair.1) * pair.0)
            .collect()
            .sum()
        };

        // Compute pairing lhs
        let lhs = {
            vec![(one, proof.Wxi), (proof.challenges.u, proof.Wxiw)]
                .iter()
                .map(|pair| MSM::base(pair.1) * pair.0)
                .collect()
                .sum()
        };

        let accumulator = Accumulator::new(lhs, rhs);
        strategy.process(loader, transcript, proof, accumulator)
    }
}
