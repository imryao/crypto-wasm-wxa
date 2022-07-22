use aes_gcm_siv::{Aes128GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead, Payload};
use wasm_bindgen::prelude::*;

mod utils;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn aes128gcm_siv_encrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], plaintext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes128GcmSiv::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    cipher.encrypt(nonce, Payload { msg: plaintext_slice, aad: aad_slice }).expect("encryption failure!")
}

#[wasm_bindgen]
pub fn aes128gcm_siv_decrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], ciphertext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes128GcmSiv::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    cipher.decrypt(nonce, Payload { msg: ciphertext_slice, aad: aad_slice }).expect("decryption failure!")
}
