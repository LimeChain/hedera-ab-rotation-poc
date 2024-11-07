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
    use ed25519_dalek::ed25519::signature::Signer;
    use risc0_zkvm::{default_executor, sha::{Digest, Sha256}, ExecutorEnv};

    use serde::Serialize;
    use serde_big_array::Array;

    type AddressBookIn = Vec<([u8; 32], u64)>;

    #[derive(Serialize)]
    pub struct StatementIn {
        pub ab_curr: AddressBookIn,
        pub ab_next_hash: Digest,
        pub signatures: Vec<Array<u8, 64>>,
    }

    #[test]
    fn corrects() {
        let mut csprng = rand::rngs::OsRng;
        let mut signing_keys: [_; 4] =
            std::array::from_fn(|_| ed25519_dalek::SigningKey::generate(&mut csprng));

        let ab_next: AddressBookIn = vec![
            // Not important
            ([0; 32], 15),
            ([1; 32], 60),
        ];
        let ab_next_words = risc0_zkvm::serde::to_vec(&ab_next).unwrap();
        let ab_next_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_next_words);

        let ab_curr: AddressBookIn = vec![
            (*signing_keys[0].verifying_key().as_bytes(), 15),
            (*signing_keys[1].verifying_key().as_bytes(), 15),
            (*signing_keys[2].verifying_key().as_bytes(), 70),
            // (*signing_keys[3].verifying_key().as_bytes(), 1),
        ];

        let ab_curr_words = risc0_zkvm::serde::to_vec(&ab_curr).unwrap();
        let ab_curr_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_curr_words);

        let signatures = vec![
           (Array(signing_keys[0].sign(ab_next_hash.as_bytes()).to_bytes())),
           (Array(signing_keys[1].sign(ab_next_hash.as_bytes()).to_bytes())),
        ];

        let statement = StatementIn {
            ab_curr,
            ab_next_hash,
            signatures,
        };

        let env = ExecutorEnv::builder()
            .write(&statement)
            .unwrap()
            .build()
            .unwrap();

        let session_info = default_executor()
            .execute(env, super::AB_ROTATION_ELF)
            .unwrap();

        let ab_curr_hash_committed = session_info
            .journal
            .decode::<Digest>()
            .unwrap();

        assert_eq!(ab_curr_hash, ab_curr_hash_committed)
    }
}
