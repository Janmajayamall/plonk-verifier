// // use crate::scheme::kzg::CircomProtocol;
// // use num::BigUint;
// // use serde::{Deserialize, Serialize};
// // use std::env;
// use std::fs::File;
// use std::io::BufReader;
// use std::str::FromStr;

// // pub trait Parser {}

// // struct CircomParser {}

// impl CircomParser {
//     pub fn load_vk(path: &str) {
//         let file = File::open(path).unwrap();
//         let reader = BufReader::new(file);
//         let vk_unint: VerificationKeyUnInit = serde_json::from_reader(reader).unwrap();

//         // convert to vk
//     }
// }

// // #[cfg(test)]
// // mod tests {
// //     use super::CircomParser;

// //     #[test]
// //     fn test() {
// //         // let parser = CircomParser::read_vk_file();
// //         // println!("{:#?} parse vk", parser);
// //     }
// // }
