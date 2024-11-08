#[cfg(test)]
mod tests {
    use apps::*;

    use risc0_zkvm::{
        default_executor,
        sha::{Digest, Sha256},
        ExecutorEnv,
    };

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
            .execute(env, methods::AB_ROTATION_ELF)
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

        let session_info = default_executor().execute(env, methods::AB_ROTATION_ELF);

        assert!(session_info.is_err());
    }
}
