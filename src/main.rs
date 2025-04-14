use base64::prelude::*;
mod iue_impl;

use iue_impl::*;

fn main() {
    let input = BASE64_STANDARD.decode(b"AQAAAAAAAAAAAAAAAAAAAAACwj+3zkv2VM+aTfk60RqhXq6a/77WlLwu/BxXFkL7EppGsju/m8f0x5kBDD3EZTtGALGXlym5jnpZAoSIkswHoA==").expect("should decode");

    let got: Vec<Item> = decode_payload(&input);
    for item in got.iter() {
        println!("{:?}", item);
    }
}
