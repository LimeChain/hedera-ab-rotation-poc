use derive_more::derive::Deref;
use risc0_zkvm::sha::Digest;
use serde::Serialize;
use serde_big_array::Array;

use crate::ed25519::{self, Signature};

#[cfg(feature = "with_bls_aggregate")]
pub type BlsPublicKey = ();
pub type Weight = u64;

#[derive(Debug, Serialize)]
pub struct AddressBookEntry {
    pub ed25519_public_key: ed25519::VerifyingKey,
    // #[cfg(feature = "with_bls_aggregate")]
    // pub bls_public_key: BlsPublicKey,
    pub weight: Weight,
}
#[repr(transparent)]
#[derive(Debug, Deref, Serialize)]
pub struct AddressBook(pub Vec<AddressBookEntry>);

pub type AddressBookEntryIn = (Array<u8, { ed25519::PUBLIC_KEY_LENGTH }>, Weight);
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

pub fn digest_address_book_in(ab: &AddressBookIn) -> Digest {
    use risc0_zkvm::sha::{Impl as Sha256, Sha256 as _};

    let ab_words = risc0_zkvm::serde::to_vec(ab).unwrap();

    *Sha256::hash_words(&ab_words)
}

impl AddressBook {
    pub fn get_validator_weight_from_signature(
        &self,
        signature: &Signature,
        message: &[u8],
    ) -> Option<Weight> {
        self.iter().find_map(|abe| {
            abe.ed25519_public_key
                .verify_strict(message, signature)
                .ok()
                .map(|_| abe.weight)
        })
    }
}
