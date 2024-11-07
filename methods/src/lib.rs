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
    use risc0_zkvm::{default_executor, ExecutorEnv};

    const ED25519_PUBLIC_KEY: &[u8; 32] = include_bytes!("../../keys/ed25519_public.raw");

    // TODO: automate this and put in scripts in `examples/`
    const SIGNATURE: [u8; 64] = [
        183, 28, 102, 187, 19, 176, 149, 173, 5, 182, 206, 4, 40, 226, 210, 144, 195, 235, 163, 94,
        191, 80, 122, 114, 105, 21, 142, 186, 161, 165, 250, 31, 130, 202, 46, 157, 79, 171, 52,
        218, 112, 177, 233, 36, 8, 252, 197, 44, 20, 20, 198, 212, 50, 16, 189, 26, 107, 188, 242,
        24, 33, 210, 93, 13,
    ];
    const AB_CURR_HASH: [u32; risc0_zkvm::sha::DIGEST_WORDS] = [
        1470853495, 1794819450, 2790785571, 1857589074, 172372429, 2283190261, 1194808541,
        3428754279,
    ];

    #[test]
    fn corrects() {
        use serde::Serialize;
        use serde_big_array::Array;

        #[derive(Serialize)]
        pub struct StatementIn {
            pub ab_curr: Vec<([u8; 32], u64)>,
            pub ab_next_hash: [u32; risc0_zkvm::sha::DIGEST_WORDS],
            pub signatures: Vec<Array<u8, 64>>,
        }

        let statement = StatementIn {
            ab_curr: vec![(*ED25519_PUBLIC_KEY, 30), (Default::default(), 70)],
            ab_next_hash: Default::default(),
            signatures: vec![Array(SIGNATURE)],
        };

        let env = ExecutorEnv::builder()
            .write(&statement)
            .unwrap()
            .build()
            .unwrap();

        let session_info = default_executor()
            .execute(env, super::AB_ROTATION_ELF)
            .unwrap();

        let ab_curr_hash = session_info
            .journal
            .decode::<[u32; risc0_zkvm::sha::DIGEST_WORDS]>()
            .unwrap();

        println!("{:?}", ab_curr_hash);

        assert_eq!(ab_curr_hash, AB_CURR_HASH)
    }
}
