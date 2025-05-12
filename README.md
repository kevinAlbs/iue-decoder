# Installation

To use the CLI:
```bash
# Install iue_decoder to $HOME/bin:
cargo install --git https://github.com/kevinAlbs/iue-decoder --root $HOME

# (Optional) add to PATH:
export PATH="$PATH:$HOME/bin"

# Run:
iue_decoder AQAAAAAAAAAAAAAAAAAAAAACwj+3zkv2VM+aTfk60RqhXq6a/77WlLwu/BxXFkL7EppGsju/m8f0x5kBDD3EZTtGALGXlym5jnpZAoSIkswHoA==
```

To build and serve website:

```
cargo install wasm-pack
./wasm-build.sh
./wasm-serve.sh
```
