#![allow(non_snake_case)]

use crate::{
    loader::{LoadedScalar, Loader},
    scheme::kzg::{
        accumulation::{AccumulationStrategy, Accumulator},
        MSM,
    },
    util::{Domain, TranscriptRead},
    Error,
};
use group::Curve;
use std::marker::PhantomData;

#[derive(Clone)]

pub struct Protocol<C: Curve> {
    pub domain: Domain<C::Scalar>,
    pub public_inputs_count: usize,
    pub k1: C::Scalar,
    pub k2: C::Scalar,
    pub Qm: C,
    pub Ql: C,
    pub Qr: C,
    pub Qo: C,
    pub Qc: C,
    pub S1: C,
    pub S2: C,
    pub S3: C,
}

#[derive(Debug)]
pub struct Challenges<C: Curve, L: Loader<C>> {
    pub beta: L::LoadedScalar,
    pub alpha: L::LoadedScalar,
    pub gamma: L::LoadedScalar,
    pub xi: L::LoadedScalar,
    pub v: L::LoadedScalar,
    pub u: L::LoadedScalar,
}

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct CircomPlonkProof<C: Curve, L: Loader<C>> {
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
        public_signals.iter().for_each(|signal| {
            transcript.common_scalar(signal).unwrap();
        });

        let A = transcript.read_ec_point()?;
        // println!("Just read A: {:#?}", A);
        let B = transcript.read_ec_point()?;
        // println!("Just read B: {:#?}", B);
        let C = transcript.read_ec_point()?;
        // println!("Just read C: {:#?}", C);

        let beta = transcript.squeeze_challenge();
        // println!("beta: {:#?}", beta);

        transcript.common_scalar(&beta)?;
        let gamma = transcript.squeeze_challenge();
        // println!("gamma: {:#?}", gamma);

        let Z = transcript.read_ec_point()?;
        // println!("Just read Z: {:#?}", Z);
        let alpha = transcript.squeeze_challenge();
        // println!("alpha: {:#?}", alpha);

        let T1 = transcript.read_ec_point()?;
        // println!("Just read T1: {:#?}", T1);
        let T2 = transcript.read_ec_point()?;
        // println!("Just read T2: {:#?}", T2);
        let T3 = transcript.read_ec_point()?;
        // println!("Just read T3: {:#?}", T3);
        let xi = transcript.squeeze_challenge();
        // println!("xi: {:#?}", xi);

        let eval_points = transcript.read_n_scalars(7)?;
        // println!("Just read a: {:#?}", eval_points[0].clone());
        // println!("Just read b: {:#?}", eval_points[1].clone());
        // println!("Just read c: {:#?}", eval_points[2].clone());
        // println!("Just read s1: {:#?}", eval_points[3].clone());
        // println!("Just read s2: {:#?}", eval_points[4].clone());
        // println!("Just read zw: {:#?}", eval_points[5].clone());
        // println!("Just read r: {:#?}", eval_points[6].clone());

        let v = transcript.squeeze_challenge();
        // println!("v: {:#?}", v);
        let Wxi: L::LoadedEcPoint = transcript.read_ec_point()?;
        // println!("Just read WXI: {:#?}", Wxi);
        let Wxiw = transcript.read_ec_point()?;
        // println!("Just read WXIW: {:#?}", Wxiw);
        let u = transcript.squeeze_challenge();
        // println!("u: {:#?}", u);

        Ok(Self {
            A,
            B,
            C,
            Z,
            T1,
            T2,
            T3,
            Wxi,
            Wxiw,
            eval_a: eval_points[0].clone(),
            eval_b: eval_points[1].clone(),
            eval_c: eval_points[2].clone(),
            eval_s1: eval_points[3].clone(),
            eval_s2: eval_points[4].clone(),
            eval_zw: eval_points[5].clone(),
            eval_r: eval_points[6].clone(),
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
pub struct CircomPlonkAccumulationScheme<C, L, T, S> {
    _marker: PhantomData<(C, L, T, S)>,
}

impl<C, L, T, S> CircomPlonkAccumulationScheme<C, L, T, S>
where
    C: Curve,
    L: Loader<C>,
    T: TranscriptRead<C, L>,
    S: AccumulationStrategy<C, L, T, CircomPlonkProof<C, L>>,
{
    pub fn accumulate(
        protocol: &Protocol<C>,
        loader: &L,
        public_signals: &Vec<L::LoadedScalar>,
        transcript: &mut T,
        strategy: &mut S,
    ) -> Result<S::Output, crate::Error> {
        // perform necessary checks
        assert_eq!(public_signals.len(), protocol.public_inputs_count);

        let proof = CircomPlonkProof::read(public_signals, transcript)?;

        // println!("Proof {:#?}", proof);
        let Qm = loader.ec_point_load_const(&protocol.Qm);
        let Ql = loader.ec_point_load_const(&protocol.Ql);
        let Qr = loader.ec_point_load_const(&protocol.Qr);
        let Qo = loader.ec_point_load_const(&protocol.Qo);
        let Qc = loader.ec_point_load_const(&protocol.Qc);
        let S1 = loader.ec_point_load_const(&protocol.S1);
        let S2 = loader.ec_point_load_const(&protocol.S2);
        let S3 = loader.ec_point_load_const(&protocol.S3);
        let k1 = loader.load_const(&protocol.k1);
        let k2 = loader.load_const(&protocol.k2);

        let xi = proof.challenges.xi.clone();
        let n = loader.load_const(&C::Scalar::from(protocol.domain.n as u64));
        let n_inv = loader.load_const(&protocol.domain.n_inv);
        let xi_power_n = xi.clone().pow_const(protocol.domain.n as u64);
        let omega = loader.load_const(&protocol.domain.gen);
        let omega_inv = loader.load_const(&protocol.domain.gen_inv);
        let omega_inv_powers = omega_inv.clone().powers(public_signals.len());

        // println!("domain {:#?}", protocol.domain);
        // println!("omega {:#?}", omega);
        // println!("omega_inv {:#?}", omega_inv);
        // println!("omega_inv_powers {:#?}", omega_inv_powers);

        // z_h(xi) = xi^n - 1;
        let one = loader.load_one();
        let z_h_eval_xi = xi_power_n.clone() - one.clone();
        let z_h_eval_xi_inv = z_h_eval_xi
            .clone()
            .invert()
            .unwrap_or_else(|| z_h_eval_xi.clone());

        // Compute first lagrange evaluation.
        // Snarkjs's plonk prover starts with `omega^0`
        // in permutation polynomial. Thus we compute
        // `L0(xi)` here.
        //
        // `L0(xi) = (xi^n) - 1 / (n * (xi - 1))`
        //
        // More info on this - https://github.com/ZK-Garage/plonk/blob/79dffa1bacbe73ab42e2d7e48194efe5c0070bd6/plonk-core/src/proof_system/proof.rs#L622
        let l1_eval_xi = {
            let denom = (xi.clone() - one.clone()) * n;
            z_h_eval_xi.clone() * denom.invert().unwrap()
        };
        // println!("l1_eval_xi {:#?}", l1_eval_xi);

        // Compute public input poly evaluation at `xi`.
        // We do this using `barycentric evaluation` approach.
        // For more details on this approach check following:
        //  (1) https://hackmd.io/@vbuterin/barycentric_evaluation
        //  (2) https://github.com/ZK-Garage/plonk/blob/79dffa1bacbe73ab42e2d7e48194efe5c0070bd6/plonk-core/src/proof_system/proof.rs#L635
        let pi_poly_eval_xi = {
            // In case of no public inputs PI(x)
            // can be reduced to
            // PI(x) = (x^n - 1) / n
            if public_signals.is_empty() {
                loader.load_zero()
            } else {
                // (xi^n - 1) / n
                let numerator = z_h_eval_xi.clone() * n_inv.clone();
                let denominator = {
                    let denoms_inv: Vec<L::LoadedScalar> = (0..public_signals.len())
                        .map(|index| {
                            // (xi - omega^j) * omega^-j => (omega^-j * xi - 1)
                            // for `j`th index.
                            let value =
                                (xi.clone() * omega_inv_powers[index].clone()) - one.clone();
                            value.invert().unwrap_or_else(|| value.clone())
                        })
                        .collect();

                    // Computes
                    // `sum_of { pi_j * (xi * omega^-j - 1)^-1 }`
                    // for j in range 0..public_signals.len()
                    let mut sum = denoms_inv[0].clone() * public_signals[0].clone();
                    denoms_inv.iter().enumerate().for_each(|(index, d)| {
                        if index > 0 {
                            sum += d.clone() * public_signals[index].clone();
                        }
                    });
                    sum
                };
                -numerator * denominator
            }
        };
        // println!("pi_poly_eval_xi {:#?}", pi_poly_eval_xi);

        let alpha_square = proof.challenges.alpha.clone().square();

        // powers of `v`
        let v_powers = proof.challenges.v.powers(7);
        // println!("challenges.v {:#?}", proof.challenges.v);
        // println!("v_powers {:#?}", v_powers);

        // t
        let t = {
            let e = (proof.eval_a.clone()
                + (proof.challenges.beta.clone() * proof.eval_s1.clone())
                + proof.challenges.gamma.clone())
                * (proof.eval_b.clone()
                    + (proof.challenges.beta.clone() * proof.eval_s2.clone())
                    + proof.challenges.gamma.clone())
                * (proof.eval_c.clone() + proof.challenges.gamma.clone())
                * proof.eval_zw.clone()
                * proof.challenges.alpha.clone();
            let num = (proof.eval_r.clone() + pi_poly_eval_xi.clone())
                - e
                - (l1_eval_xi.clone() * alpha_square.clone());
            num * z_h_eval_xi_inv
        };
        // println!("t: {:#?}", t.clone());

        let D: MSM<C, L> = {
            let v_1 = v_powers[1].clone();
            let beta_xi = proof.challenges.beta.clone() * proof.challenges.xi.clone();

            let mut d = MSM::default();
            d.push(
                proof.eval_a.clone() * proof.eval_b.clone() * v_1.clone(),
                Qm.clone(),
            );
            d.push(proof.eval_a.clone() * v_1.clone(), Ql.clone());
            d.push(proof.eval_b.clone() * v_1.clone(), Qr.clone());
            d.push(proof.eval_c.clone() * v_1.clone(), Qo.clone());
            d.push(v_1.clone(), Qc.clone());
            d.push(
                ((proof.eval_a.clone() + beta_xi.clone() + proof.challenges.gamma.clone())
                    * (proof.eval_b.clone()
                        + (beta_xi.clone() * k1.clone())
                        + proof.challenges.gamma.clone())
                    * (proof.eval_c.clone()
                        + (beta_xi.clone() * k2.clone())
                        + proof.challenges.gamma.clone())
                    * proof.challenges.alpha.clone()
                    * v_1.clone())
                    + (l1_eval_xi.clone() * alpha_square.clone() * v_1.clone())
                    + proof.challenges.u.clone(),
                proof.Z.clone(),
            );
            d.push(
                -((proof.eval_a.clone()
                    + (proof.challenges.beta.clone() * proof.eval_s1.clone())
                    + proof.challenges.gamma.clone())
                    * (proof.eval_b.clone()
                        + (proof.challenges.beta.clone() * proof.eval_s2.clone())
                        + proof.challenges.gamma.clone())
                    * proof.challenges.alpha.clone()
                    * v_1.clone()
                    * proof.challenges.beta.clone()
                    * proof.eval_zw.clone()),
                S3.clone(),
            );

            d
        };

        // let res: L::LoadedEcPoint = D.clone().evaluate(C::generator());
        // println!("D: {:#?}", res);

        let F: MSM<C, L> = {
            let mut res = MSM::default();
            res.push(one.clone(), proof.T1.clone());
            res.push(xi_power_n.clone(), proof.T2.clone());
            res.push(xi_power_n.clone().square(), proof.T3.clone());
            res.push(v_powers[2].clone(), proof.A.clone());
            res.push(v_powers[3].clone(), proof.B.clone());
            res.push(v_powers[4].clone(), proof.C.clone());
            res.push(v_powers[5].clone(), S1.clone());
            res.push(v_powers[6].clone(), S2.clone());
            res.extend(D);
            res
        };

        // let res = F.clone().evaluate(C::generator());
        // println!("F: {:#?}", res);

        let e_scalar = t
            + (v_powers[1].clone() * proof.eval_r.clone())
            + (v_powers[2].clone() * proof.eval_a.clone())
            + (v_powers[3].clone() * proof.eval_b.clone())
            + (v_powers[4].clone() * proof.eval_c.clone())
            + (v_powers[5].clone() * proof.eval_s1.clone())
            + (v_powers[6].clone() * proof.eval_s2.clone())
            + (proof.challenges.u.clone() * proof.eval_zw.clone());

        // println!("e_scalar: {:#?}", e_scalar);

        let mut lhs = MSM::default();
        lhs.push(proof.challenges.xi.clone(), proof.Wxi.clone());
        lhs.push(
            proof.challenges.u.clone() * proof.challenges.xi.clone() * omega.clone(),
            proof.Wxiw.clone(),
        );
        lhs.extend(F);
        lhs.push(-e_scalar, loader.ec_point_load_one());

        let mut rhs = MSM::default();
        rhs.push(one.clone(), proof.Wxi.clone());
        rhs.push(proof.challenges.u.clone(), proof.Wxiw.clone());

        // println!("{:#?} LHS", lhs.clone().evaluate(C::generator()));
        // println!("{:#?} RHS", rhs.clone().evaluate(C::generator()));

        let accumulator = Accumulator::new(lhs, rhs);
        strategy.process(loader, transcript, proof, accumulator)
    }
}

#[cfg(test)]
mod tests {}
