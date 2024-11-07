#![no_main]

use risc0_zkvm::guest::env;
// use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
// use ark_ec::pairing::Pairing;
// use ark_ff::PrimeField;
// use ark_serialize::CanonicalDeserialize;
// use sha2::{Digest, Sha384};

mod address_book;
mod ed25519;
mod statement;

use statement::{Statement, StatementIn};

risc0_zkvm::guest::entry!(main);
fn main() {
    let start_cycle_count = env::cycle_count();

    // Fetch the statement from the environment and
    // (attempt to) convert it to our internal representation
    let statement: Statement = env::read::<StatementIn>().try_into().unwrap();

    // Calculate total weight
    let total_weight: u64 = statement.ab_curr.iter().map(|abe| abe.weight).sum();

    // Convert the ab_next_hash into bytes (from words)
    let ab_next_hash_bytes = statement
        .ab_next_hash
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<u8>>();

    let signers_weight: u64 = statement
        .signatures
        .iter()
        .try_fold(0, |acc, signature| -> Option<u64> {
            statement
                .ab_curr
                .get_validator_weight_from_signature(signature, &ab_next_hash_bytes)
                .map(|w| acc + w)
        })
        .expect("Verification failed");

    // Assert that enough (30%) of the current validators have signed the next AB
    let proportion: f64 = (signers_weight as f64) / (total_weight as f64);
    env::log(&format!("Proportion is {}", proportion));
    assert!(proportion >= 0.3);

    // Get the SHA256 of the current AB (using the provided ECALL)
    let ab_curr_hash = statement.ab_curr.digest();

    let end_cycle_count = env::cycle_count();
    env::log(&format!(
        "Cycle count after rotation validation: {}",
        end_cycle_count - start_cycle_count
    ));

    env::commit(&ab_curr_hash);
}
