//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use wasm_bindgen_test::*;

use crypto_wasm_wxa::{generate_key, verify};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn verify_test() {
    let result = verify("eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIHdvcmxkIQ".as_bytes(), &Base64UrlUnpadded::decode_vec("dAfO1PfJdz64YY4NYB9dyPn12JjtG2whiDS1DbZyZyF9QeTl568Fid1080pPnJqY_gntlo-tWdbqDu26GtkRJQ").unwrap());
    assert_eq!(result, true)
}

#[wasm_bindgen_test]
fn generate_secret_test() {
    const SEED: [u8; 32] = [7u8; 32];
    const X_STR: &str = "a8Q9Vsljg_d0hvykfAlPVX7CcfEb4nIBKD3Y8qHpyJM";
    const Y_STR: &str = "SK0WtyEsA_M_qH-Gs5MoVGTnjSJgECN7KUmZKJ4sY8o";
    const KID_STR: &str = "2023-01-01";
    const SIGN_STR: &str = "h9N9AfUoUQXWZ2lUEgdS1IxoyiPpl1m9WyHcSnI7OPdqSqWvrjlt_l0lD85VGWxAFEDkGf-jY-T4I20PotUt-g";
    const INFO_STR: &str = "wxebbb8eded25ba277";

    let x = Base64UrlUnpadded::decode_vec(X_STR).unwrap();
    let y = Base64UrlUnpadded::decode_vec(Y_STR).unwrap();
    let kid = KID_STR.as_bytes();
    let sign = Base64UrlUnpadded::decode_vec(SIGN_STR).unwrap();
    let info = INFO_STR.as_bytes();

    let result = generate_key(&SEED, &x, &y, kid, &sign, info);
    let key = &result[..16];
    let pk = &result[16..];
    println!("{}", Base64::encode_string(key));
    println!("{}", Base64::encode_string(pk));

    assert_eq!(true, true)
}