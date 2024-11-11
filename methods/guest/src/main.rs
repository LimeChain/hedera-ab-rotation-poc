#![no_main]
#![no_std]

use risc0_zkvm::guest::env;
// use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
// use ark_ec::pairing::Pairing;
// use ark_ff::PrimeField;
// use ark_serialize::CanonicalDeserialize;

mod address_book;
mod ed25519;
mod statement;

use statement::{Statement, StatementIn};

use crate::address_book::digest_address_book_in;

risc0_zkvm::guest::entry!(main);
fn main() {
    let start_cycle_count = env::cycle_count();

    // Fetch the statement from the environment ...
    let statement_in: StatementIn = env::read::<StatementIn>();

    // Get the SHA256 of the current AB (using the provided ECALL)
    let ab_curr_hash = digest_address_book_in(&statement_in.ab_curr);

    // ... (attempt to) convert it to our internal representation
    let statement: Statement = statement_in.try_into().unwrap();

    // Calculate total weight
    let total_weight: u64 = statement.ab_curr.iter().map(|abe| abe.weight).sum();

    // Convert the ab_next_hash into bytes (from words)
    let ab_next_hash_bytes: &[u8] = statement.ab_next_hash.as_bytes();

    let signers_weight: u64 = statement
        .signatures
        .iter()
        .try_fold(0, |acc, signature| -> Option<u64> {
            statement
                .ab_curr
                .get_validator_weight_from_signature(signature, ab_next_hash_bytes)
                .map(|w| acc + w)
        })
        .expect("Verification failed");

    // Assert that enough (30%) of the current validators have signed the next AB
    // NOTE: not using floats to avoid rounding issues
    let enough_signatures = (10 * signers_weight) >= (3 * total_weight);
    assert!(enough_signatures);

    let end_cycle_count = env::cycle_count();
    let cycle_count = end_cycle_count - start_cycle_count;

    env::write(&cycle_count);
    env::commit(&ab_curr_hash);
}
