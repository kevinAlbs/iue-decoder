use wasm_bindgen::prelude::*;

mod iue_impl;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}. foo() returned {}!", name, iue_impl::foo()));
}

