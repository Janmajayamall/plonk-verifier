use crate::{
    util::{
        arithmetic::{
            powers, Curve, CurveAffine, CurveExt, Domain, Field, GroupEncoding, MultiMillerLoop,
            PrimeCurveAffine, PrimeField, Rotation,
        },
        expression::{
            CommonPolynomial, Expression, LinearizationStrategy, Query, QuotientPolynomial,
        },
        Itertools,
    },
    Protocol,
};
use serde::{Deserialize, Deserializer};
use std::iter;

pub mod transcript;

#[cfg(test)]
mod test;

pub fn compile<M: MultiMillerLoop>(vk: &VerifyingKey<M>) -> Protocol<M::G1Affine> {
    let domain = Domain::new(vk.k, vk.gen);

    let [q_m, q_l, q_r, q_o, q_c, s_1, s_2, s_3, pi, a, b, c, z] =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(|poly| Query::new(poly, Rotation::cur()));
    let z_w = Query::new(12, Rotation::next());
    let r = Query::new(14, Rotation::cur());
    let t = Query::new(13, Rotation::cur());

    let quotient = {
        let [q_l, q_r, q_o, q_m, q_c, s_1, s_2, s_3, pi, a, b, c, z, z_w] =
            &[q_l, q_r, q_o, q_m, q_c, s_1, s_2, s_3, pi, a, b, c, z, z_w]
                .map(Expression::Polynomial);
        let [beta, gamma, alpha] = &[0, 1, 2].map(Expression::<M::Scalar>::Challenge);
        let [l_0, identity] = &[CommonPolynomial::Lagrange(0), CommonPolynomial::Identity]
            .map(Expression::CommonPolynomial);
        let [one, k_1, k_2] = &[M::Scalar::one(), vk.k_1, vk.k_2].map(Expression::Constant);
        let constraints = {
            vec![
                a * b * q_m + a * q_l + b * q_r + c * q_o + q_c - pi,
                ((a + beta * one * identity + gamma)
                    * (b + beta * k_1 * identity + gamma)
                    * (c + beta * k_2 * identity + gamma))
                    * z
                    - ((a + beta * s_1 + gamma)
                        * (b + beta * s_2 + gamma)
                        * (c + beta * s_3 + gamma))
                        * z_w,
                (z - one) * l_0,
            ]
        };
        let numerator = powers(alpha.clone())
            .zip(constraints.iter())
            .map(|(power_of_alpha, constraint)| power_of_alpha * constraint)
            .sum();
        QuotientPolynomial {
            numerator,
            chunk_degree: 1,
        }
    };

    Protocol {
        zk: true,
        domain,
        preprocessed: vec![
            vk.q_m, vk.q_l, vk.q_r, vk.q_o, vk.q_c, vk.s_1, vk.s_2, vk.s_3,
        ],
        num_instance: vec![vk.num_instnace],
        num_witness: vec![3, 1],
        num_challenge: vec![2, 1],
        evaluations: vec![a, b, c, s_1, s_2, z_w, r],
        queries: vec![t, r, a, b, c, s_1, s_2, z_w],
        quotient,
        linearization: Some(LinearizationStrategy::WithoutConstant),
        transcript_initial_state: None,
        accumulator_indices: Vec::new(),
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct VerifyingKey<M: MultiMillerLoop> {
    #[serde(rename(deserialize = "nPublic"))]
    num_instnace: usize,
    #[serde(rename(deserialize = "power"))]
    k: usize,
    #[serde(rename(deserialize = "w"), deserialize_with = "deserialize_scalar")]
    gen: M::Scalar,
    #[serde(rename(deserialize = "k1"), deserialize_with = "deserialize_scalar")]
    k_1: M::Scalar,
    #[serde(rename(deserialize = "k2"), deserialize_with = "deserialize_scalar")]
    k_2: M::Scalar,
    #[serde(rename(deserialize = "Qm"), deserialize_with = "deserialize_g1")]
    q_m: M::G1Affine,
    #[serde(rename(deserialize = "Ql"), deserialize_with = "deserialize_g1")]
    q_l: M::G1Affine,
    #[serde(rename(deserialize = "Qr"), deserialize_with = "deserialize_g1")]
    q_r: M::G1Affine,
    #[serde(rename(deserialize = "Qo"), deserialize_with = "deserialize_g1")]
    q_o: M::G1Affine,
    #[serde(rename(deserialize = "Qc"), deserialize_with = "deserialize_g1")]
    q_c: M::G1Affine,
    #[serde(rename(deserialize = "S1"), deserialize_with = "deserialize_g1")]
    s_1: M::G1Affine,
    #[serde(rename(deserialize = "S2"), deserialize_with = "deserialize_g1")]
    s_2: M::G1Affine,
    #[serde(rename(deserialize = "S3"), deserialize_with = "deserialize_g1")]
    s_3: M::G1Affine,
    #[serde(
        rename(deserialize = "X_2"),
        deserialize_with = "deserialize_g2::<_, M>"
    )]
    s_g2: M::G2Affine,
}

impl<M: MultiMillerLoop> VerifyingKey<M> {
    pub fn svk(&self) -> M::G1Affine {
        M::G1Affine::generator()
    }

    pub fn dk(&self) -> (M::G2Affine, M::G2Affine) {
        (M::G2Affine::generator(), self.s_g2)
    }
}

#[derive(Clone, Debug)]
pub struct PublicSignals<F: PrimeField>(Vec<F>);

impl<F: PrimeField> PublicSignals<F> {
    pub fn to_vec(self) -> Vec<F> {
        self.0
    }
}

impl<'de, F: PrimeField> Deserialize<'de> for PublicSignals<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .iter()
            .map(|string| F::from_str_vartime(string.as_str()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| serde::de::Error::custom(format!("Invalid public signals {:?}", values)))
            .map(|values| Self(values))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Proof<M: MultiMillerLoop> {
    #[serde(rename(deserialize = "A"), deserialize_with = "deserialize_g1")]
    a: M::G1Affine,
    #[serde(rename(deserialize = "B"), deserialize_with = "deserialize_g1")]
    b: M::G1Affine,
    #[serde(rename(deserialize = "C"), deserialize_with = "deserialize_g1")]
    c: M::G1Affine,
    #[serde(rename(deserialize = "Z"), deserialize_with = "deserialize_g1")]
    z: M::G1Affine,
    #[serde(rename(deserialize = "T1"), deserialize_with = "deserialize_g1")]
    t_1: M::G1Affine,
    #[serde(rename(deserialize = "T2"), deserialize_with = "deserialize_g1")]
    t_2: M::G1Affine,
    #[serde(rename(deserialize = "T3"), deserialize_with = "deserialize_g1")]
    t_3: M::G1Affine,
    #[serde(deserialize_with = "deserialize_scalar")]
    eval_a: M::Scalar,
    #[serde(deserialize_with = "deserialize_scalar")]
    eval_b: M::Scalar,
    #[serde(deserialize_with = "deserialize_scalar")]
    eval_c: M::Scalar,
    #[serde(
        rename(deserialize = "eval_s1"),
        deserialize_with = "deserialize_scalar"
    )]
    eval_s_1: M::Scalar,
    #[serde(
        rename(deserialize = "eval_s2"),
        deserialize_with = "deserialize_scalar"
    )]
    eval_s_2: M::Scalar,
    #[serde(
        rename(deserialize = "eval_zw"),
        deserialize_with = "deserialize_scalar"
    )]
    eval_z_w: M::Scalar,
    #[serde(deserialize_with = "deserialize_scalar")]
    eval_r: M::Scalar,
    #[serde(rename(deserialize = "Wxi"), deserialize_with = "deserialize_g1")]
    w: M::G1Affine,
    #[serde(rename(deserialize = "Wxiw"), deserialize_with = "deserialize_g1")]
    w_omega: M::G1Affine,
}

impl<M: MultiMillerLoop> Proof<M> {
    pub fn to_compressed_le(&self) -> Vec<u8> {
        iter::empty()
            .chain(
                [self.a, self.b, self.c, self.z, self.t_1, self.t_2, self.t_3]
                    .into_iter()
                    .map(|ec_point| ec_point.to_bytes().as_ref().to_vec()),
            )
            .chain(
                [
                    self.eval_a,
                    self.eval_b,
                    self.eval_c,
                    self.eval_s_1,
                    self.eval_s_2,
                    self.eval_z_w,
                    self.eval_r,
                ]
                .into_iter()
                .map(|scalar| scalar.to_repr().as_ref().to_vec()),
            )
            .chain(
                [self.w, self.w_omega]
                    .into_iter()
                    .map(|ec_point| ec_point.to_bytes().as_ref().to_vec()),
            )
            .flatten()
            .collect()
    }

    pub fn to_uncompressed_be(&self) -> Vec<u8> {
        let ec_point_to_uncompressed_be = |ec_point: M::G1Affine| {
            let coordinates = ec_point.coordinates().unwrap();
            iter::empty()
                .chain(coordinates.x().to_repr().as_ref().iter().rev().cloned())
                .chain(coordinates.y().to_repr().as_ref().iter().rev().cloned())
                .collect_vec()
        };
        iter::empty()
            .chain(
                [self.a, self.b, self.c, self.z, self.t_1, self.t_2, self.t_3]
                    .into_iter()
                    .map(ec_point_to_uncompressed_be),
            )
            .chain(
                [
                    self.eval_a,
                    self.eval_b,
                    self.eval_c,
                    self.eval_s_1,
                    self.eval_s_2,
                    self.eval_z_w,
                    self.eval_r,
                ]
                .into_iter()
                .map(|scalar| {
                    scalar
                        .to_repr()
                        .as_ref()
                        .iter()
                        .rev()
                        .cloned()
                        .collect_vec()
                }),
            )
            .chain(
                [self.w, self.w_omega]
                    .into_iter()
                    .map(ec_point_to_uncompressed_be),
            )
            .flatten()
            .collect()
    }
}

fn deserialize_scalar<'de, D, F>(deserializer: D) -> Result<F, D::Error>
where
    D: Deserializer<'de>,
    F: PrimeField,
{
    let buf = String::deserialize(deserializer)?;
    F::from_str_vartime(&buf)
        .ok_or_else(|| serde::de::Error::custom(format!("Invalid scalar {}", buf)))
}

fn deserialize_g1<'de, D, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    C: CurveAffine,
{
    let buf = <[String; 3]>::deserialize(deserializer)?;
    let [x, y, z] =
        [buf[0].as_str(), buf[1].as_str(), buf[2].as_str()].map(PrimeField::from_str_vartime);
    x.and_then(|x| {
        Some(
            Option::<C::CurveExt>::from(<C::CurveExt as CurveExt>::new_jacobian(x, y?, z?))?
                .to_affine(),
        )
    })
    .ok_or_else(move || serde::de::Error::custom(format!("Invalid G1 point {:?}", buf)))
}

fn deserialize_g2<'de, D, M>(deserializer: D) -> Result<M::G2Affine, D::Error>
where
    D: Deserializer<'de>,
    M: MultiMillerLoop,
{
    let buf = <[[String; 2]; 3]>::deserialize(deserializer)?;
    let [x0, x1] = [buf[0][0].as_str(), buf[0][1].as_str()].map(|buf| {
        <<M::G1Affine as CurveAffine>::Base as PrimeField>::from_str_vartime(buf)
            .map(|fe| fe.to_repr())
    });
    let [y0, y1] = [buf[1][0].as_str(), buf[1][1].as_str()].map(|buf| {
        <<M::G1Affine as CurveAffine>::Base as PrimeField>::from_str_vartime(buf)
            .map(|fe| fe.to_repr())
    });
    x0.and_then(|x0| {
        let [mut x, mut y] =
            [<<M::G2Affine as CurveAffine>::Base as PrimeField>::Repr::default(); 2];
        x.as_mut()[..x0.as_ref().len()].copy_from_slice(x0.as_ref());
        x.as_mut()[x0.as_ref().len()..].copy_from_slice(x1?.as_ref());
        y.as_mut()[..x0.as_ref().len()].copy_from_slice(y0?.as_ref());
        y.as_mut()[x0.as_ref().len()..].copy_from_slice(y1?.as_ref());
        Option::<M::G2Affine>::from(M::G2Affine::from_xy(
            Option::from(<<M::G2Affine as CurveAffine>::Base as PrimeField>::from_repr(x))?,
            Option::from(<<M::G2Affine as CurveAffine>::Base as PrimeField>::from_repr(y))?,
        ))
    })
    .ok_or_else(move || serde::de::Error::custom(format!("Invalid G2 point {:?}", buf)))
}
