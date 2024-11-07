use ed25519_dalek::{ed25519::signature::SignerMut, pkcs8::{DecodePrivateKey, DecodePublicKey}, SecretKey, SigningKey, VerifyingKey};

fn main() {
    let mut sc = SigningKey::read_pkcs8_pem_file("../keys/ed25519_private.pem").unwrap();

    let message: &[u8; 32] = &[0; 32];

    println!("Message is: {:?}", message);

    let sig = sc.sign(message);

    println!("Sig: {:?}", sig.to_bytes());
}
