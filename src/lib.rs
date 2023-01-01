use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes128GcmSiv, Nonce,
};
use p256::{ecdh::EphemeralSecret, ecdsa::{signature::{Signature, Verifier}, VerifyingKey}, elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, PublicKey};
use rand::{rngs::StdRng, SeedableRng};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn aes128gcm_siv_encrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], plaintext_slice: &[u8]) -> Vec<u8> {
    let cipher = Aes128GcmSiv::new_from_slice(key_slice).unwrap();
    let nonce = Nonce::from_slice(nonce_slice);

    cipher.encrypt(nonce, Payload { msg: plaintext_slice, aad: aad_slice }).unwrap()
}

#[wasm_bindgen]
pub fn aes128gcm_siv_decrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], ciphertext_slice: &[u8]) -> Vec<u8> {
    let cipher = Aes128GcmSiv::new_from_slice(key_slice).unwrap();
    let nonce = Nonce::from_slice(nonce_slice);

    cipher.decrypt(nonce, Payload { msg: ciphertext_slice, aad: aad_slice }).unwrap()
}

#[wasm_bindgen]
pub fn generate_key(seed: &[u8], x: &[u8], y: &[u8], kid: &[u8], sign: &[u8], info: &[u8]) -> Vec<u8> {
    let mut rng = StdRng::from_seed(seed.try_into().unwrap());

    let server_point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let msg = [server_point.as_bytes(), kid].concat();
    if !verify(&msg, sign) {
        return Vec::new();
    }
    let server_pk = PublicKey::from_encoded_point(&server_point).unwrap();

    let client_secret = EphemeralSecret::random(&mut rng);
    let client_point = EncodedPoint::from(client_secret.public_key());

    let shared_secret = client_secret.diffie_hellman(&server_pk);
    let mut okm = [0u8; 16];
    shared_secret.extract::<Sha256>(None).expand(info, &mut okm).unwrap();
    [&mut okm, client_point.compress().as_bytes()].concat()
}

const VERIFYING_KEY_BYTES: [u8; 33] = [2, 163, 219, 94, 18, 26, 5, 230, 207, 241, 159, 187, 184, 166, 85, 40, 133, 179, 229, 201, 41, 253, 31, 121, 77, 96, 131, 125, 220, 200, 41, 245, 11];

fn verify(msg: &[u8], sign: &[u8]) -> bool {
    let verifying_key = VerifyingKey::from_sec1_bytes(&VERIFYING_KEY_BYTES).unwrap();
    let signature = Signature::from_bytes(sign).unwrap();
    verifying_key.verify(msg, &signature).is_ok()
}
