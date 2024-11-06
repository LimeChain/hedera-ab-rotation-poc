#![no_main]

use risc0_zkvm::guest::env;
use std::io::Read;
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

    // Fetch the statement from the environment
    // and convert it to our internal representation
    let statement: Statement = env::read::<StatementIn>().try_into().unwrap();

    // Calculate total weight
    let total_weight: u64 = statement.ab_curr.iter().map(|abe| abe.weight).sum();

    env::log(&format!("Got sigs: {:?}", statement.signatures));

    let vk = *statement.ab_curr[0].ed25519_public_key;

    statement.signatures.iter().for_each(|sig| {
        vk.verify_strict(&statement.ab_next_hash.to_be_bytes(), sig)
            .expect("Verification failed");
    });

    let end_cycle_count = env::cycle_count();
    env::log(&format!(
        "cycle count after roation validation: {}",
        end_cycle_count - start_cycle_count
    ));

    // Commit total weight
    env::commit(&total_weight);
}
