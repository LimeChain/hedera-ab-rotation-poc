use risc0_zkvm::{
    default_executor,
    sha::{Digest, Sha256},
    ExecutorEnv,
};

use serde::Serialize;
use serde_big_array::Array;

pub type AddressBookIn = Vec<([u8; ed25519_dalek::PUBLIC_KEY_LENGTH], u64)>;
pub type SignaturesIn = Vec<Option<Array<u8, { ed25519_dalek::SIGNATURE_LENGTH }>>>;

#[derive(Serialize)]
pub struct StatementIn {
    pub ab_curr: AddressBookIn,
    pub ab_next_hash: Digest,
    pub signatures: SignaturesIn,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct SigningKeys<const N: usize>([ed25519_dalek::SigningKey; N]);

impl<const N: usize> SigningKeys<N> {
    pub fn verifying_key(&self, i: usize) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        *self.0[i].verifying_key().as_bytes()
    }

    pub fn all_sign(
        &self,
        signers: impl Into<Signers<N>>,
        message: &[u8],
    ) -> [Option<Array<u8, { ed25519_dalek::SIGNATURE_LENGTH }>>; N] {
        use ed25519_dalek::ed25519::signature::Signer;
        let signers: [bool; N] = signers.into().0;
        core::array::from_fn(|i| signers[i].then_some(Array(self.0[i].sign(message).to_bytes())))
    }
}

pub struct Signers<const N: usize>(pub [bool; N]);

impl<const N: usize> From<usize> for Signers<N> {
    fn from(n: usize) -> Self {
        assert!(n <= N, "Cannot sign with more validators than available");
        let mut signers = [false; N];
        for i in 0..n {
            signers[i] = true;
        }
        Self(signers)
    }
}

impl<const N: usize> From<&[usize]> for Signers<N> {
    fn from(indices: &[usize]) -> Self {
        let mut signers = [false; N];
        for &idx in indices {
            assert!(idx < N, "Validator index out of bounds");
            signers[idx] = true;
        }
        Self(signers)
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
