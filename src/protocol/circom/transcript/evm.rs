use crate::{
    loader::{
        evm::{fe_to_u256, loader::Value, u256_to_fe, EcPoint, EvmLoader, MemoryChunk, Scalar},
        native::{self, NativeLoader},
        Loader,
    },
    util::{
        arithmetic::{Coordinates, CurveAffine, PrimeField},
        transcript::{Transcript, TranscriptRead},
        Itertools,
    },
    Error,
};
use ethereum_types::U256;
use sha3::{Digest, Keccak256};
use std::{
    io::{self, Read, Write},
    iter,
    marker::PhantomData,
    rc::Rc,
};

pub struct EvmTranscript<C: CurveAffine, L: Loader<C>, S, B> {
    loader: L,
    stream: S,
    buf: B,
    adjacent_challenge: Option<L::LoadedScalar>,
    _marker: PhantomData<C>,
}

impl<C> EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    pub fn new(loader: Rc<EvmLoader>) -> Self {
        Self {
            loader,
            stream: 0,
            buf: MemoryChunk::new(0),
            adjacent_challenge: None,
            _marker: PhantomData,
        }
    }

    pub fn load_instances(&mut self, num_instance: Vec<usize>) -> Vec<Vec<Scalar>> {
        num_instance
            .into_iter()
            .map(|len| {
                iter::repeat_with(|| {
                    let scalar = self.loader.calldataload_scalar(self.stream);
                    self.stream += 0x20;
                    scalar
                })
                .take(len)
                .collect_vec()
            })
            .collect()
    }
}

impl<C> Transcript<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &Rc<EvmLoader> {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> Scalar {
        if let Some(adjacent_challenge) = self.adjacent_challenge.take() {
            self.buf.reset(adjacent_challenge.ptr());
            self.buf.extend(0x20);
        }
        let hash_ptr = self.loader.keccak256(self.buf.ptr(), self.buf.len());

        let challenge_ptr = self.loader.allocate(0x20);
        self.loader
            .code_mut()
            .push(self.loader.scalar_modulus())
            .push(hash_ptr)
            .mload()
            .r#mod()
            .push(challenge_ptr)
            .mstore();

        self.buf.reset(challenge_ptr + 0x20);

        let challenge = self.loader.scalar(Value::Memory(challenge_ptr));
        self.adjacent_challenge = Some(challenge.clone());
        challenge
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint) -> Result<(), Error> {
        self.adjacent_challenge = None;
        if let Value::Memory(ptr) = ec_point.value() {
            assert_eq!(self.buf.end(), ptr);
            self.buf.extend(0x40);
        } else {
            unreachable!()
        }
        Ok(())
    }

    fn common_scalar(&mut self, scalar: &Scalar) -> Result<(), Error> {
        self.adjacent_challenge = None;
        match scalar.value() {
            Value::Memory(ptr) => {
                assert_eq!(self.buf.end(), ptr);
                self.buf.extend(0x20);
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl<C> TranscriptRead<C, Rc<EvmLoader>> for EvmTranscript<C, Rc<EvmLoader>, usize, MemoryChunk>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn read_scalar(&mut self) -> Result<Scalar, Error> {
        let scalar = self.loader.calldataload_scalar(self.stream);
        self.stream += 0x20;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint, Error> {
        let ec_point = self.loader.calldataload_ec_point(self.stream);
        self.stream += 0x40;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, S> EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
{
    pub fn new(stream: S) -> Self {
        Self {
            loader: NativeLoader,
            stream,
            buf: Vec::new(),
            adjacent_challenge: None,
            _marker: PhantomData,
        }
    }
}

impl<C, S> Transcript<C, NativeLoader> for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
{
    fn loader(&self) -> &NativeLoader {
        &native::LOADER
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        if let Some(adjacent_challenge) = self.adjacent_challenge.take() {
            self.buf = vec![0; 32];
            fe_to_u256(adjacent_challenge).to_big_endian(&mut self.buf);
        }
        let hash: [u8; 32] = Keccak256::digest(&self.buf).into();
        self.buf = Vec::new();
        let challenge = u256_to_fe(U256::from_big_endian(hash.as_slice()));
        self.adjacent_challenge = Some(challenge);
        challenge
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        self.adjacent_challenge = None;
        let coordinates =
            Option::<Coordinates<C>>::from(ec_point.coordinates()).ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Cannot write points at infinity to the transcript".to_string(),
                )
            })?;

        [coordinates.x(), coordinates.y()].map(|coordinate| {
            self.buf
                .extend(coordinate.to_repr().as_ref().iter().rev().cloned());
        });

        Ok(())
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.adjacent_challenge = None;
        self.buf.extend(scalar.to_repr().as_ref().iter().rev());

        Ok(())
    }
}

impl<C, S> TranscriptRead<C, NativeLoader> for EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 0x20]>,
    S: Read,
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = [0; 32];
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        data.reverse();
        let scalar = C::Scalar::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid scalar encoding in proof".to_string(),
            )
        })?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        let [mut x, mut y] = [<C::Base as PrimeField>::Repr::default(); 2];
        for repr in [&mut x, &mut y] {
            self.stream
                .read_exact(repr.as_mut())
                .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
            repr.as_mut().reverse();
        }
        let x = Option::from(<C::Base as PrimeField>::from_repr(x));
        let y = Option::from(<C::Base as PrimeField>::from_repr(y));
        let ec_point = x
            .zip(y)
            .and_then(|(x, y)| Option::from(C::from_xy(x, y)))
            .ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point encoding in proof".to_string(),
                )
            })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C, S> EvmTranscript<C, NativeLoader, S, Vec<u8>>
where
    C: CurveAffine,
    S: Write,
{
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn finalize(self) -> S {
        self.stream
    }
}
