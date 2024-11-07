use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use derive_more::derive::Deref;
use serde::Serialize;
use serde_big_array::Array;

#[repr(transparent)]
#[derive(Debug, Deref, Serialize)]
pub struct VerifyingKey(pub ed25519_dalek::VerifyingKey);

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ()> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| ())
    }
}

impl Absorb for VerifyingKey {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        // Ed25519 public key is always 32 bytes
        // Simply extend destination with all bytes
        dest.extend_from_slice(&self.0.to_bytes());
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let key_bytes = self.0.to_bytes();

        // Split 32 bytes into chunks that fit into field elements
        // For BN254, field elements are 32 bytes but we use 31 bytes to stay under modulus
        // Therefore split into two parts with some safety margin

        // First chunk: bytes [0,15]
        let mut first_chunk = [0u8; 32];
        first_chunk[..16].copy_from_slice(&key_bytes[..16]);
        dest.push(F::from_le_bytes_mod_order(&first_chunk));

        // Second chunk: bytes [16,31]
        let mut second_chunk = [0u8; 32];
        second_chunk[..16].copy_from_slice(&key_bytes[16..]);
        dest.push(F::from_le_bytes_mod_order(&second_chunk));
    }
}

///////////

#[repr(transparent)]
#[derive(Debug, Deref, Serialize)]
pub struct Signature(pub ed25519_dalek::Signature);
#[repr(transparent)]
#[derive(Debug, Deref, Serialize)]
pub struct Signatures(Vec<Signature>);

pub type SignatureIn = Array<u8, { SIGNATURE_LENGTH }>;
pub type SignaturesIn = Vec<SignatureIn>;

impl TryFrom<SignatureIn> for Signature {
    type Error = ();

    fn try_from(value: SignatureIn) -> Result<Self, Self::Error> {
        Ok(Self(<ed25519_dalek::Signature>::from_bytes(&value)))
    }
}

impl TryFrom<SignaturesIn> for Signatures {
    type Error = ();

    fn try_from(value: SignaturesIn) -> Result<Self, Self::Error> {
        value
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ())
            .map(Self)
    }
}
