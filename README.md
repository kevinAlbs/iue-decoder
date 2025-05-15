# Installation

To use the CLI:
```bash
# Install iue_decoder:
cargo install --git https://github.com/kevinAlbs/iue-decoder

# (Optional) add to PATH:
export PATH="$PATH:$HOME/.cargo/bin"

# Run:
iue_decoder AQAAAAAAAAAAAAAAAAAAAAACwj+3zkv2VM+aTfk60RqhXq6a/77WlLwu/BxXFkL7EppGsju/m8f0x5kBDD3EZTtGALGXlym5jnpZAoSIkswHoA==
```

Results in output like:

```
BlobSubtype : 1 (FLE1DeterministicEncryptedValue)
KeyUUID : 00000000000000000000000000000000
OriginalBsonType : 2
Ciphertext : c23fb7ce4bf654cf9a4df93ad11aa15eae9affbed694bc2efc1c571642fb129a46b23bbf9bc7f4c799010c3dc4653b4600b1979729b98e7a5902848892cc07a0
```

To build and serve website:

```
cargo install wasm-pack
./wasm-build.sh
./wasm-serve.sh
```
