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
    use risc0_zkvm::{
        default_executor,
        sha::{Digest, Sha256},
        ExecutorEnv,
    };

    use serde::Serialize;
    use serde_big_array::Array;

    type AddressBookIn = Vec<([u8; ed25519_dalek::PUBLIC_KEY_LENGTH], u64)>;

    #[derive(Serialize)]
    pub struct StatementIn {
        pub ab_curr: AddressBookIn,
        pub ab_next_hash: Digest,
        pub signatures: Vec<Array<u8, 64>>,
    }

    #[derive(Debug)]
    #[repr(transparent)]
    struct SigningKeys<const N: usize>([ed25519_dalek::SigningKey; N]);
    impl<const N: usize> SigningKeys<N> {
        fn verifying_key(&self, i: usize) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
            *self.0[i].verifying_key().as_bytes()
        }

        fn sign(&self, i: usize, message: &[u8]) -> Array<u8, 64> {
            use ed25519_dalek::ed25519::signature::Signer;
            Array(self.0[0].sign(message).to_bytes())
        }
    }

    // FIXME: `LazyCell` is broken on the RISC0 target, `force`-ing the lazy cell
    //        has no effect, generates a new state on each access
    // const VALIDATORS: LazyCell<SigningKeys<4>> = LazyCell::new(|| {
    //     let mut csprng = rand::rngs::OsRng;
    //     let keys = std::array::from_fn(|_| ed25519_dalek::SigningKey::generate(&mut csprng));
    //     SigningKeys(keys)
    // });

    fn gen_validators<const N: usize>() -> SigningKeys<N> {
        let mut csprng = rand::rngs::OsRng;
        let keys = std::array::from_fn(|_| ed25519_dalek::SigningKey::generate(&mut csprng));
        SigningKeys(keys)
    }

    #[test]
    fn successful_rotation() {
        let validators = gen_validators::<3>();

        let ab_next: AddressBookIn = vec![
            // Not important
            ([0; 32], 15),
            ([1; 32], 60),
        ];
        let ab_next_words = risc0_zkvm::serde::to_vec(&ab_next).unwrap();
        let ab_next_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_next_words);

        let ab_curr: AddressBookIn = vec![
            (validators.verifying_key(0), 15),
            (validators.verifying_key(1), 15),
            (validators.verifying_key(2), 70),
        ];

        let ab_curr_words = risc0_zkvm::serde::to_vec(&ab_curr).unwrap();
        let ab_curr_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_curr_words);

        let message = ab_next_hash.as_bytes();

        let signatures = vec![validators.sign(0, message), validators.sign(1, message)];

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

        let ab_curr_hash_committed = session_info.journal.decode::<Digest>().unwrap();

        assert_eq!(ab_curr_hash, ab_curr_hash_committed)
    }

    #[test]
    fn insufficient_signatures() {
        let validators = gen_validators::<4>();

        let ab_next: AddressBookIn = vec![
            // Not important
            ([0; 32], 15),
            ([1; 32], 60),
        ];
        let ab_next_words = risc0_zkvm::serde::to_vec(&ab_next).unwrap();
        let ab_next_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_next_words);

        let ab_curr: AddressBookIn = vec![
            (validators.verifying_key(0), 15),
            (validators.verifying_key(1), 15),
            (validators.verifying_key(2), 70),
            (validators.verifying_key(3), 1),
        ];

        let ab_curr_words = risc0_zkvm::serde::to_vec(&ab_curr).unwrap();
        let ab_curr_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_curr_words);

        let message = ab_next_hash.as_bytes();

        let signatures = vec![validators.sign(0, message), validators.sign(1, message)];

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
            .execute(env, super::AB_ROTATION_ELF);

        assert!(session_info.is_err());
    }
}
