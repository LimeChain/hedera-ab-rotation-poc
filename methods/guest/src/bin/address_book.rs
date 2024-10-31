#![no_main]
#![allow(clippy::four_forward_slashes)]

use alloy_sol_types::SolValue;
use derive_more::derive::Deref;
use risc0_zkvm::guest::env;
use std::io::Read;
// use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
// use ark_ec::pairing::Pairing;
// use ark_ff::PrimeField;
// use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha384};

///////////////////////////
//// SOLIDITY ENCODING ////
///////////////////////////

alloy_sol_types::sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct AddressBookEntryEth {
        bytes32 ed25519_public_key;
        // #[cfg(feature = "with_bls_aggregate")]
        // bytes bls_public_key;
        uint64 weight;
    }
}
type AddressBookEth = Vec<AddressBookEntryEth>;

///////////////////////
//// RUST ENCODING ////
///////////////////////

type Ed25519PublicKey = ed25519_dalek::VerifyingKey;
type Ed25519SecretKey = ed25519_dalek::SigningKey;
#[cfg(feature = "with_bls_aggregate")]
type BlsPublicKey = ();
type Weight = u64;

#[derive(Debug)]
struct AddressBookEntry {
    ed25519_public_key: Ed25519PublicKey,
    // #[cfg(feature = "with_bls_aggregate")]
    // bls_public_key: BlsPublicKey,
    weight: Weight,
}
#[repr(transparent)]
#[derive(Debug, Deref)]
#[deref(forward)]
struct AddressBook(Vec<AddressBookEntry>);

impl TryFrom<AddressBookEntryEth> for AddressBookEntry {
    type Error = ();

    fn try_from(value: AddressBookEntryEth) -> Result<Self, Self::Error> {
        let ed25519_public_key = Ed25519PublicKey::from_bytes(&value.ed25519_public_key).unwrap();

        // #[cfg(feature = "with_bls_aggregate")]
        // let bls_public_key = ();

        let weight = value.weight;

        Ok(Self {
            ed25519_public_key,
            // #[cfg(feature = "with_bls_aggregate")]
            // bls_public_key,
            weight,
        })
    }
}

impl TryFrom<AddressBookEth> for AddressBook {
    type Error = ();

    fn try_from(value: AddressBookEth) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())
            .map(Self)
    }
}

risc0_zkvm::guest::entry!(main);
fn main() {
    let start_cycle_count = env::cycle_count();

    // Fetch the input from the environment.
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Decode eth representation AB from input
    let abees = <AddressBookEth>::abi_decode(&input_bytes, true).expect("Couldn't decode AB");

    // Transform into our internal representation
    let abes = <AddressBook>::try_from(abees).unwrap();
    env::log(&format!("Got abes: {:?}", abes));

    // Calculate total weight
    let total_weight: u64 = abes.iter().map(|abe| abe.weight).sum();

    let end_cycle_count = env::cycle_count();
    env::log(&format!(
        "cycle count after roation validation: {}",
        end_cycle_count - start_cycle_count
    ));

    // Commit total weight
    env::commit_slice(total_weight.abi_encode().as_slice());
}
