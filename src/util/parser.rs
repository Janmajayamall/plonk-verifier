use crate::scheme::kzg::CircomProtocol;
use ff::PrimeField;
use halo2_curves::{
    bn256::{Fq, Fr, G1},
    FieldExt,
};
use num::BigUint;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

use super::Domain;

#[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
pub struct CircomVerificationKeyUninitialized {
    protocol: String,
    curve: String,
    nPublic: usize,
    power: usize,
    k1: String,
    k2: String,
    Qm: Vec<String>,
    Ql: Vec<String>,
    Qr: Vec<String>,
    Qo: Vec<String>,
    Qc: Vec<String>,
    S1: Vec<String>,
    S2: Vec<String>,
    S3: Vec<String>,
}

pub fn str_to_bn256_g1(x: &str, y: &str, z: &str) -> G1 {
    let x = Fq::from_str_vartime(x).unwrap();
    let y = Fq::from_str_vartime(y).unwrap();
    let z = Fq::from_str_vartime(z).unwrap();
    G1 { x, y, z }
}

pub fn read_verification_key(path: &str) -> CircomVerificationKeyUninitialized {
    // let cwd = std::env::current_dir().unwrap();
    // let cwd = cwd.to_str().unwrap();
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).unwrap()
}

pub fn read_protocol(path: &str) -> CircomProtocol<G1> {
    let vk = read_verification_key(path);

    CircomProtocol {
        domain: Domain::<Fr>::new(vk.power),
        public_inputs_count: vk.nPublic,
        k1: Fr::from_str_vartime(&vk.k1).unwrap(),
        k2: Fr::from_str_vartime(&vk.k2).unwrap(),
        Qm: str_to_bn256_g1(vk.Qm[0].as_str(), vk.Qm[1].as_str(), vk.Qm[2].as_str()),
        Ql: str_to_bn256_g1(vk.Ql[0].as_str(), vk.Ql[1].as_str(), vk.Ql[2].as_str()),
        Qr: str_to_bn256_g1(vk.Qr[0].as_str(), vk.Qr[1].as_str(), vk.Qr[2].as_str()),
        Qo: str_to_bn256_g1(vk.Qo[0].as_str(), vk.Qo[1].as_str(), vk.Qo[2].as_str()),
        Qc: str_to_bn256_g1(vk.Qc[0].as_str(), vk.Qc[1].as_str(), vk.Qc[2].as_str()),
        S1: str_to_bn256_g1(vk.S1[0].as_str(), vk.S1[1].as_str(), vk.S1[2].as_str()),
        S2: str_to_bn256_g1(vk.S2[0].as_str(), vk.S2[1].as_str(), vk.S2[2].as_str()),
        S3: str_to_bn256_g1(vk.S3[0].as_str(), vk.S3[1].as_str(), vk.S3[2].as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read() {
        let cwd = std::env::current_dir().unwrap();
        let cwd = cwd.to_str().unwrap();
        let protocol = read_protocol(format!("{}/target/verification_key.json", cwd).as_str());
        println!("{:#?}", protocol.Qm);
    }
}
