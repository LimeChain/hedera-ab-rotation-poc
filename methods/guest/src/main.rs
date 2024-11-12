#![no_main]
#![no_std]

use address_book::MAXIMUM_VALIDATORS;
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

    assert!(
        statement_in.signatures.len() == statement_in.ab_curr.len(),
        "There has to be an (optional) signature for each current validator"
    );

    // Get the SHA256 of the current AB (using the provided ECALL)
    let ab_curr_hash = digest_address_book_in(&statement_in.ab_curr);

    // ... (attempt to) convert it to our internal representation
    let statement: Statement = statement_in.try_into().unwrap();

    // Calculate total weight
    let total_weight: u64 = statement.ab_curr.iter().map(|abe| abe.weight).sum();

    // Convert the ab_next_hash into bytes (from words)
    let ab_next_hash_bytes: &[u8] = statement.ab_next_hash.as_bytes();

    let signers_weight: u64 = core::iter::zip(statement.ab_curr.0, statement.signatures.0).fold(
        0,
        |acc, (abe, ms)| -> u64 {
            let added_weight = ms
                .map(|signature| {
                    abe.ed25519_public_key
                        .verify_strict(ab_next_hash_bytes, &signature)
                        .map(|_| abe.weight)
                        .expect("Invalid signature")
                })
                .unwrap_or(0);

            acc + added_weight
        },
    );

    // Assert that enough (30%) of the current validators have signed the next AB
    // NOTE: not using floats to avoid rounding issues
    let enough_signatures = (10 * signers_weight) >= (3 * total_weight);
    assert!(enough_signatures);

    let end_cycle_count = env::cycle_count();
    let cycle_count = end_cycle_count - start_cycle_count;

    env::write(&cycle_count);
    env::commit(&ab_curr_hash);
}
