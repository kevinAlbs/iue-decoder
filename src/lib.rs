use wasm_bindgen::prelude::*;
use base64::{prelude::*};

mod iue_impl;
use iue_impl::*;

#[wasm_bindgen]
pub fn decode(input: &str) -> Result<Vec::<Item>, IUEError> {
    let input = BASE64_STANDARD.decode(input)?;
    return Ok(decode_payload(input.as_slice()));
}

#[wasm_bindgen]
pub fn decode_as_json(input: &str) -> Option<String> {
    let input = BASE64_STANDARD.decode(input).expect("should decode");
    return decode_payload_as_json(input.as_slice());
}
