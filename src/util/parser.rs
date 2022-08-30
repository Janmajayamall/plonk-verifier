use num::BigUint;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

pub trait Parser {}

#[derive(Serialize, Deserialize, Debug)]
struct VerificationKey {
    protocol: String,
    curve: String,
    n_public: usize,
    power: usize,
    k1: usize,
    k2: usize,
    n: usize,
    // n_inv: L::LoadedScalar,
    // omega: C::Scalar,
    // omega_inv: C::Scalar,
    // public_inputs_count: usize,
    // k1: L::LoadedScalar,
    // k2: L::LoadedScalar,
    Qm: String, // Ql: L::LoadedEcPoint,
                // Qr: L::LoadedEcPoint,
                // Qo: L::LoadedEcPoint,
                // Qc: L::LoadedEcPoint,
                // S1: L::LoadedEcPoint,
                // S2: L::LoadedEcPoint,
                // S3: L::LoadedEcPoint,
}

struct CircomParser {}

impl CircomParser {
    pub fn read_vk_file() -> VerificationKey {
        let file = File::open(format!(
            "{}/verification_key.json",
            env::current_dir().unwrap().to_str().unwrap()
        ))
        .expect("Failed to open verification file");
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::CircomParser;

    #[test]
    fn test() {
        let parser = CircomParser::read_vk_file();
        println!("{:#?} parse vk", parser);
    }
}
