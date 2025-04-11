use base64::prelude::*;
use bson::{Bson, Document};
use hex;
use std::fmt::Display;

#[derive(PartialEq, Debug, Clone, Copy)]
enum Id {
    BlobSubtype(u8),
    KeyUUID,
    Algorithm,
    Value,
}

#[derive(Debug)]
struct Item {
    start: usize,
    end: usize,
    id: Id,
    desc: String
}

fn bytes_to_ejson (el : &[u8]) -> String {
    // `el` is encoding of a BSON element. Includes type, key, and value.
    // Wrap in a temporary document to convert to extended JSON.
    let mut wrapper = Vec::<u8>::new();
    let total_len : i32 = 
        4 + // byte length
        el.len() as i32 + 
        1; // trailing NULL
    wrapper.append(&mut total_len.to_le_bytes().to_vec());
    wrapper.append(&mut el.to_vec());
    wrapper.push(0u8);

    println!("{:?}", wrapper);
    
    let reader = wrapper.as_slice();
    let doc = Document::from_reader(reader).expect("should read");
    let doc_bson : Bson = doc.into();
    let got = doc_bson.into_relaxed_extjson().to_string();
    return got[1..got.len() - 1].to_owned();
}

fn read_i32 (input: &[u8], off: usize) -> usize {
    let mut le_bytes = [0u8;4];
    le_bytes.copy_from_slice(&input[off..off+4]);
    
    return i32::from_le_bytes(le_bytes) as usize;
}

fn read_key (input: &[u8], mut off: usize) -> String {
    let key_start = off;
    // Find NULL byte to terminate key.
    while input[off] != 0 {
        off+=1;
    }
    return String::from_utf8(input[key_start..off].to_vec()).expect("should decode");
}

fn decode_payload (input: &[u8]) -> Vec<Item> {
    let mut ret = Vec::<Item>::new();
    let mut off = 0;
    let blob_subtype = Id::BlobSubtype(input[off]);

    ret.push(Item{
        start: off,
        end: off + 1,
        id: blob_subtype,
        desc: format!("{:?}", blob_subtype)
    });
    off += 1;

    // if blob_subtype == 0 {
    //     let key_uuid = &input[off..off+16];
    //     ret.push(Item{
    //         start: off,
    //         end: off+16,
    //         id: Id::KeyUUID,
    //         human: None,
    //         desc: hex::encode(key_uuid)
    //     });
    //     off += 16;
    // }

    // TODO: parse just enough BSON to iterate.

    let doclen = read_i32 (input, off);
    off+=4;

    loop {
        let el_start = off;
        let signed_byte = input[off];
        println!("signed_byte={}", signed_byte);
        off+=1;
        
        let keystr = read_key (input, off);
        off += keystr.len() + 1;
        println!("keystr={}", keystr);

        // Depending on signed_byte, determine length of value.
        let el_end;
        if signed_byte == 16u8 {
            off += 4;
            el_end = off;
        } else if signed_byte == 5u8 {
            let len = read_i32 (input, off);
            off += 4 + 1 + len;
            el_end = off;
        } else if signed_byte == 2u8 {
            let len = read_i32 (input, off);
            off += 4 + len;
            el_end = off;
        }
        else {
            panic!("do not know how to parse element with signed byte: {}", signed_byte);
        }
        println!("element bytes: {:?}", &input[el_start..el_end]);
        println!("element ejson: {}", bytes_to_ejson(&input[el_start..el_end]));
        if keystr == "a" {
            ret.push(Item { start: el_start, end: el_end, id: Id::Algorithm, desc: bytes_to_ejson(&input[el_start..el_end])})
        } else if keystr == "ki" {
            ret.push(Item { start: el_start, end: el_end, id: Id::KeyUUID, desc: bytes_to_ejson(&input[el_start..el_end])})
        } else if keystr == "v" {
            ret.push(Item { start: el_start, end: el_end, id: Id::Value, desc: bytes_to_ejson(&input[el_start..el_end])})
        } else {
            panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
        }

        if off == doclen {
            break;
        }
    }
    return ret;
}

#[test]
fn test_decode0() {
    let input= BASE64_STANDARD.decode(b"ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA").expect("should decode");
    let got = decode_payload(&input);

    println!("{:?}", got);

    let mut idx = 0;

    assert_eq!(got[idx].id, Id::BlobSubtype(0));
    assert_eq!(got[idx].desc, "BlobSubtype(0)".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::Algorithm);
    assert_eq!(got[idx].desc, r#""a":1"#.to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::KeyUUID);
    assert_eq!(got[idx].desc, r#""ki":{"$binary":{"base64":"YWFhYWFhYWFhYWFhYWFhYQ==","subType":"04"}}"#.to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::Value);
    assert_eq!(got[idx].desc, r#""v":"457-55-5462""#.to_owned());
}

#[test]
fn test_bytes_to_ejson() {
    let v : Vec<u8> = vec![
        16, // int32
        b'f', b'o', b'o', 0x00, // e_name
        0x2A, 0x00, 0x00, 0x00 // 42 in Little Endian.
    ];
    let got = bytes_to_ejson(&v);
    assert_eq!(got, r#""foo":42"#);
}

fn main() {
    println!("Hello, world!");
}
