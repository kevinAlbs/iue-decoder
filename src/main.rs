use base64::prelude::*;
mod iue_impl;

use iue_impl::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <base64>", args[0]);
        return;
    }

    let input = BASE64_STANDARD.decode(args[1].as_bytes()).expect("should decode");

    let got: Vec<Item> = decode_payload(&input);
    for item in got.iter() {
        print!("{} : {}", item.key(), item.val());
        if let Some(ejson) = item.ejson() {
            print!(" ({})", ejson);
        }
        println!();
    }
}
