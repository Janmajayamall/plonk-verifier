mod arithmetic;
mod expression;
mod parser;
mod transcript;

pub use arithmetic::{
    batch_invert, batch_invert_and_mul, fe_from_limbs, fe_to_limbs, BatchInvert, Curve, Domain,
    DomainType, Field, FieldOps, Fraction, Group, GroupEncoding, GroupOps, PrimeCurveAffine,
    PrimeField, Rotation, UncompressedEncoding,
};
pub use expression::{CommonPolynomial, CommonPolynomialEvaluation, Expression, Query};
pub use parser::{read_proof_instances, read_protocol, read_public_signals};
pub use transcript::{Transcript, TranscriptRead};

pub use itertools::{EitherOrBoth, Itertools};

#[macro_export]
macro_rules! collect_slice {
    ($vec:ident) => {
        use $crate::util::Itertools;

        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect_vec();
    };
    ($vec:ident, 2) => {
        use $crate::util::Itertools;

        let $vec = $vec
            .iter()
            .map(|vec| {
                collect_slice!(vec);
                vec
            })
            .collect_vec();
        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect_vec();
    };
}
