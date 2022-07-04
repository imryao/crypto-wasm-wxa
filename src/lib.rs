use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{AeadInPlace, NewAead};
use base64ct::{Base64, Base64Url, Encoding};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

mod utils;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

type HmacSha256 = Hmac<Sha256>;

const BUF_SIZE: usize = 1024;

#[wasm_bindgen]
pub fn base16_encode(src: &[u8]) -> String {
    let mut enc_buf = [0u8; BUF_SIZE];
    base16ct::lower::encode_str(src, &mut enc_buf).unwrap().to_string()
}

#[wasm_bindgen]
pub fn base16_decode(src: &str) -> Vec<u8> {
    let mut dec_buf = [0u8; BUF_SIZE];
    base16ct::lower::decode(src, &mut dec_buf).unwrap().to_vec()
}

#[wasm_bindgen]
pub fn base64_encode(src: &[u8]) -> String {
    let mut enc_buf = [0u8; BUF_SIZE];
    Base64::encode(src, &mut enc_buf).unwrap().to_string()
}

#[wasm_bindgen]
pub fn base64_decode(src: &str) -> Vec<u8> {
    let mut dec_buf = [0u8; BUF_SIZE];
    Base64::decode(src, &mut dec_buf).unwrap().to_vec()
}

#[wasm_bindgen]
pub fn base64url_encode(src: &[u8]) -> String {
    let mut enc_buf = [0u8; BUF_SIZE];
    Base64Url::encode(src, &mut enc_buf).unwrap().to_string()
}

#[wasm_bindgen]
pub fn base64url_decode(src: &str) -> Vec<u8> {
    let mut dec_buf = [0u8; BUF_SIZE];
    Base64Url::decode(src, &mut dec_buf).unwrap().to_vec()
}

#[wasm_bindgen]
pub fn aes128gcm_siv_encrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], plaintext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes128GcmSiv::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    let mut buffer: aes_gcm_siv::aead::heapless::Vec<u8, 128> = aes_gcm_siv::aead::heapless::Vec::new();
    buffer.extend_from_slice(plaintext_slice);

    cipher.encrypt_in_place(nonce, aad_slice, &mut buffer).expect("encryption failure!");

    buffer.to_vec()
}

#[wasm_bindgen]
pub fn aes128gcm_siv_decrypt(key_slice: &[u8], nonce_slice: &[u8], aad_slice: &[u8], ciphertext_slice: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key_slice);
    let cipher = Aes128GcmSiv::new(key);

    let nonce = Nonce::from_slice(nonce_slice);

    let mut buffer: aes_gcm_siv::aead::heapless::Vec<u8, 128> = aes_gcm_siv::aead::heapless::Vec::new();
    buffer.extend_from_slice(ciphertext_slice);

    cipher.decrypt_in_place(nonce, aad_slice, &mut buffer).expect("decryption failure!");

    buffer.to_vec()
}

#[wasm_bindgen]
pub fn sha256(data_slice: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data_slice);
    hasher.finalize().to_vec()
}

#[wasm_bindgen]
pub fn hmac_sha256_sign(key_slice: &[u8], data_slice: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key_slice)
        .expect("HMAC can take key of any size");
    mac.update(data_slice);
    mac.finalize().into_bytes().to_vec()
}

#[wasm_bindgen]
pub fn hmac_sha256_verify(key_slice: &[u8], data_slice: &[u8], signature_slice: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key_slice)
        .expect("HMAC can take key of any size");
    mac.update(data_slice);
    match mac.verify_slice(signature_slice) {
        Ok(_) => true,
        Err(_) => false,
    }
}
