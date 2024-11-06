use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use derive_more::derive::Deref;
use serde_big_array::Array;

use crate::ed25519;

#[cfg(feature = "with_bls_aggregate")]
pub type BlsPublicKey = ();
pub type Weight = u64;

#[derive(Debug, Absorb)]
pub struct AddressBookEntry {
    pub ed25519_public_key: ed25519::VerifyingKey,
    // #[cfg(feature = "with_bls_aggregate")]
    // pub bls_public_key: BlsPublicKey,
    pub weight: Weight,
}
#[repr(transparent)]
#[derive(Debug, Deref, Absorb)]
pub struct AddressBook(pub Vec<AddressBookEntry>);

pub type AddressBookEntryIn = (Array<u8, {ed25519::PUBLIC_KEY_LENGTH}>, Weight);
pub type AddressBookIn = Vec<AddressBookEntryIn>;

impl TryFrom<AddressBookEntryIn> for AddressBookEntry {
    type Error = ();

    fn try_from(value: AddressBookEntryIn) -> Result<Self, Self::Error> {
        Ok(Self {
            ed25519_public_key: <ed25519::VerifyingKey>::from_bytes(&value.0)?,
            weight: value.1,
        })
    }
}
impl TryFrom<AddressBookIn> for AddressBook {
    type Error = ();

    fn try_from(value: AddressBookIn) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())
            .map(Self)
    }
}
