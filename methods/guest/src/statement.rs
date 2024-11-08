use risc0_zkvm::sha::Digest;
use serde::Deserialize;

use crate::{
    address_book::{AddressBook, AddressBookIn},
    ed25519::{Signatures, SignaturesIn},
};

#[derive(Debug, Deserialize)]
pub struct StatementIn {
    pub ab_curr: AddressBookIn,
    pub ab_next_hash: Digest,
    pub signatures: SignaturesIn,
}

#[derive(Debug)]
pub struct Statement {
    pub ab_curr: AddressBook,
    pub ab_next_hash: Digest,
    pub signatures: Signatures,
}

impl TryFrom<StatementIn> for Statement {
    type Error = ();

    fn try_from(value: StatementIn) -> Result<Self, Self::Error> {
        Ok(Self {
            ab_curr: <AddressBook>::try_from(value.ab_curr)?,
            ab_next_hash: value.ab_next_hash,
            signatures: <Signatures>::try_from(value.signatures)?,
        })
    }
}
