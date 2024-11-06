use serde::Deserialize;

use crate::{address_book::{AddressBook, AddressBookIn}, ed25519::{Signatures, SignaturesIn}};

// TODO: real data
type ABHash = u64;

#[derive(Deserialize)]
pub struct StatementIn {
    pub ab_curr: AddressBookIn,
    pub ab_next_hash: ABHash,
    pub signatures: SignaturesIn,
}

pub struct Statement {
    pub ab_curr: AddressBook,
    pub ab_next_hash: ABHash,
    pub signatures: Signatures,
}

impl TryFrom<StatementIn> for Statement {
    type Error = ();

    fn try_from(value: StatementIn) -> Result<Self, Self::Error> {
        Ok(Self {
            ab_curr: <AddressBook>::try_from(value.ab_curr)?,
            // TODO: adequate encoding in both sides
            ab_next_hash: value.ab_next_hash,
            signatures: <Signatures>::try_from(value.signatures)?,
        })
    }
}
