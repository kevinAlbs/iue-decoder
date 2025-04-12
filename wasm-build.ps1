
# Opt-in to getrandom back-end for WASM. See: https://docs.rs/getrandom/0.3.2/getrandom/index.html#opt-in-backends
$env:RUSTFLAGS='--cfg getrandom_backend="wasm_js"'
wasm-pack build --target web