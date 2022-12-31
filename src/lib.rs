use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes128GcmSiv, Nonce,
};
use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret, ecdsa::{Signature, VerifyingKey, signature::Verifier}};
use rand::{SeedableRng, rngs::StdRng};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

mod utils;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn aes128gcm_siv_encrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], plaintext_slice: &[u8]) -> Vec<u8> {
    let cipher = Aes128GcmSiv::new_from_slice(key_slice).expect("key error");
    let nonce = Nonce::from_slice(nonce_slice);

    cipher.encrypt(nonce, Payload { msg: plaintext_slice, aad: aad_slice }).expect("encryption failure!")
}

#[wasm_bindgen]
pub fn aes128gcm_siv_decrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], ciphertext_slice: &[u8]) -> Vec<u8> {
    let cipher = Aes128GcmSiv::new_from_slice(key_slice).expect("key error");
    let nonce = Nonce::from_slice(nonce_slice);

    cipher.decrypt(nonce, Payload { msg: ciphertext_slice, aad: aad_slice }).expect("decryption failure!")
}

#[wasm_bindgen]
pub fn generate_secret(seed: &[u8], server_pk_bytes: &[u8], info: &[u8]) -> Vec<u8> {
    let server_pk = PublicKey::from_sec1_bytes(server_pk_bytes).unwrap();

    let mut rng = StdRng::from_seed(seed.try_into().unwrap());
    let client_secret = EphemeralSecret::random(&mut rng);
    let client_point = EncodedPoint::from(client_secret.public_key());

    let shared_secret = client_secret.diffie_hellman(&server_pk);
    let mut okm = [0u8; 16];
    shared_secret.extract::<Sha256>(None).expand(info, &mut okm).unwrap();
    [&mut okm, client_point.as_bytes()].concat()
}

#[wasm_bindgen]
pub fn verify(msg: &[u8], sign_der: &[u8]) -> bool {
    let verifying_key_bytes = [3, 113, 106, 151, 151, 175, 10, 112, 172, 240, 217, 41, 219, 93, 237, 150, 152, 249, 238, 67, 171, 110, 162, 90, 91, 168, 178, 75, 22, 243, 219, 65, 232];
    let verifying_key = VerifyingKey::from_sec1_bytes(&verifying_key_bytes).unwrap();
    let signature = Signature::from_der(sign_der).unwrap();
    verifying_key.verify(msg, &signature).is_ok()
}