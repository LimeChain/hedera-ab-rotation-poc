// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Generated crate containing the image ID and ELF binary of the build guest.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {
    use alloy_primitives::{FixedBytes, U256};
    use alloy_sol_types::SolValue;
    use risc0_zkvm::{default_executor, ExecutorEnv};
    use serde_big_array::Array;

    const ED25519_PUBLIC_KEY: &[u8; 32] = include_bytes!("../../keys/ed25519_public.raw");

    // TODO: automate this and put in scripts in `examples/`
    const MESSAGE: [u8; 8] = [98, 97, 110, 105, 99, 97, 33, 33];
    const SIGNATURE: [u8; 64] = [
        219, 60, 244, 121, 220, 232, 37, 207, 81, 176, 197, 63, 121, 39, 8, 67, 0, 27, 12, 143, 0,
        68, 250, 163, 178, 69, 20, 120, 168, 87, 193, 44, 23, 224, 67, 65, 127, 230, 225, 181, 103,
        242, 117, 46, 23, 127, 180, 207, 91, 190, 175, 57, 137, 98, 147, 132, 185, 180, 23, 132,
        73, 20, 127, 3,
    ];

    #[test]
    fn corrects() {
        use serde::Serialize;
        use serde_big_array::Array;

        #[derive(Serialize)]
        pub struct StatementIn {
            pub ab_curr: Vec<([u8; 32], u64)>,
            pub ab_next_hash: u64,
            pub signatures: Vec<Array<u8, 64>>,
        }

        let statement = StatementIn {
            ab_curr: vec![(*ED25519_PUBLIC_KEY, 15), (*ED25519_PUBLIC_KEY, 16)],
            ab_next_hash: u64::from_be_bytes(MESSAGE),
            signatures: vec![
                Array(SIGNATURE),
            ],
        };

        let env = ExecutorEnv::builder()
            .write(&statement)
            .unwrap()
            .build()
            .unwrap();

        let session_info = default_executor()
            .execute(env, super::AB_ROTATION_ELF)
            .unwrap();

        let total_weight = session_info.journal.decode::<u64>().unwrap();

        assert_eq!(total_weight, 31);
    }
}
