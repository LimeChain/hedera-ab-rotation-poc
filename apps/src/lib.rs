use risc0_zkvm::{
    default_executor,
    sha::{Digest, Sha256},
    ExecutorEnv,
};

use serde::Serialize;
use serde_big_array::Array;

pub type AddressBookIn = Vec<([u8; ed25519_dalek::PUBLIC_KEY_LENGTH], u64)>;

#[derive(Serialize)]
pub struct StatementIn {
    pub ab_curr: AddressBookIn,
    pub ab_next_hash: Digest,
    pub signatures: Vec<Array<u8, 64>>,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct SigningKeys<const N: usize>([ed25519_dalek::SigningKey; N]);
impl<const N: usize> SigningKeys<N> {
    pub fn verifying_key(&self, i: usize) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        *self.0[i].verifying_key().as_bytes()
    }

    pub fn sign(&self, i: usize, message: &[u8]) -> Array<u8, 64> {
        use ed25519_dalek::ed25519::signature::Signer;
        Array(self.0[0].sign(message).to_bytes())
    }
}

// FIXME: `LazyCell` is broken on the RISC0 target, `force`-ing the lazy cell
//        has no effect, generates a new state on each access
// const VALIDATORS: LazyCell<SigningKeys<4>> = LazyCell::new(|| {
//     let mut csprng = rand::rngs::OsRng;
//     let keys = std::array::from_fn(|_| ed25519_dalek::SigningKey::generate(&mut csprng));
//     SigningKeys(keys)
// });

pub fn gen_validators<const N: usize>() -> SigningKeys<N> {
    let mut csprng = rand::rngs::OsRng;
    let keys = std::array::from_fn(|_| ed25519_dalek::SigningKey::generate(&mut csprng));
    SigningKeys(keys)
}
