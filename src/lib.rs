use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{AeadInPlace, NewAead};
use base64ct::{Base64, Encoding};
use wasm_bindgen::prelude::*;

mod utils;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const BUF_SIZE: usize = 1024;

#[wasm_bindgen]
pub fn base64encode(src: &[u8]) -> String {
    let mut enc_buf = [0u8; BUF_SIZE];
    Base64::encode(src, &mut enc_buf).unwrap().to_string()
}

#[wasm_bindgen]
pub fn base64decode(src: &str) -> Vec<u8> {
    let mut dec_buf = [0u8; BUF_SIZE];
    Base64::decode(src, &mut dec_buf).unwrap().to_vec()
}

#[wasm_bindgen]
pub fn aes128gcm_encrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], plaintext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    let mut buffer: aes_gcm::aead::heapless::Vec<u8, 128> = aes_gcm::aead::heapless::Vec::new();
    buffer.extend_from_slice(plaintext_slice);

    cipher.encrypt_in_place(nonce, aad_slice, &mut buffer).expect("encryption failure!");

    buffer.to_vec()
}

#[wasm_bindgen]
pub fn aes128gcm_decrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], ciphertext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    let mut buffer: aes_gcm::aead::heapless::Vec<u8, 128> = aes_gcm::aead::heapless::Vec::new();
    buffer.extend_from_slice(ciphertext_slice);

    cipher.decrypt_in_place(nonce, aad_slice, &mut buffer).expect("decryption failure!");

    buffer.to_vec()
}

#[wasm_bindgen]
pub fn aes256gcm_encrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], plaintext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    let mut buffer: aes_gcm::aead::heapless::Vec<u8, 128> = aes_gcm::aead::heapless::Vec::new();
    buffer.extend_from_slice(plaintext_slice);

    cipher.encrypt_in_place(nonce, aad_slice, &mut buffer).expect("encryption failure!");

    buffer.to_vec()
}

#[wasm_bindgen]
pub fn aes256gcm_decrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], ciphertext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    let mut buffer: aes_gcm::aead::heapless::Vec<u8, 128> = aes_gcm::aead::heapless::Vec::new();
    buffer.extend_from_slice(ciphertext_slice);

    cipher.decrypt_in_place(nonce, aad_slice, &mut buffer).expect("decryption failure!");

    buffer.to_vec()
}
