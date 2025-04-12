use wasm_bindgen::prelude::*;
use base64::prelude::*;

mod iue_impl;
use iue_impl::*;

#[wasm_bindgen]
pub fn decode(input: &str) -> Vec::<Item> {
    let input = BASE64_STANDARD.decode(input).expect("should decode");
    return decode_payload(input.as_slice());
}
