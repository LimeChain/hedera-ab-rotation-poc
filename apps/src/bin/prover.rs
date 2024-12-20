use std::io::Write;

use anyhow::Result;
use apps::{gen_validators, AddressBookIn, StatementIn};
use methods::AB_ROTATION_ELF;
use risc0_zkvm::sha::{Digest, Sha256};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

fn main() -> Result<()> {
    env_logger::init();

    let validators = gen_validators::<1>();

    let ab_next: AddressBookIn = vec![
        // Not important
        ([0; 32], 15),
        ([1; 32], 60),
    ];
    let ab_next_words = risc0_zkvm::serde::to_vec(&ab_next).unwrap();
    let ab_next_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_next_words);

    let ab_curr: AddressBookIn = validators.verifying_keys_with_weights([1]).to_vec();

    let ab_curr_words = risc0_zkvm::serde::to_vec(&ab_curr).unwrap();
    let ab_curr_hash = *risc0_zkvm::sha::Impl::hash_words(&ab_curr_words);

    let message = ab_next_hash.as_bytes();

    let signatures = validators.all_sign(1, message).to_vec();

    let statement = StatementIn {
        ab_curr,
        ab_next_hash,
        signatures,
    };

    let mut output = Vec::new();
    let env = ExecutorEnv::builder()
        .write(&statement)?
        .stdout(&mut output)
        .build()?;

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            AB_ROTATION_ELF,
            &ProverOpts::groth16(),
        )?
        .receipt;

    // Encode the seal with the selector.
    // let seal = encode_seal(&receipt)?;

    let cycle_count = risc0_zkvm::serde::from_slice::<u64, u8>(&output)?;
    println!("Cycle count: {}", cycle_count);

    let ab_curr_hash_committed = receipt.journal.decode::<Digest>()?;

    assert_eq!(ab_curr_hash, ab_curr_hash_committed);

    let mut receipt_file = std::fs::File::create_new("./receipt.json")?;

    receipt_file.write_all(&serde_json::to_vec(&receipt)?)?;

    Ok(())
}
