use base64::prelude::*;
use bson::{Bson, Document};
use hex;

#[derive(PartialEq, Debug, Clone, Copy)]
enum Id {
    BlobSubtype,
    KeyUUID,
    Algorithm,
    Value,
    OriginalBsonType,
    Ciphertext 
}

#[derive(Debug)]
struct Item {
    id: Id,
    desc: String,
    start: usize,
    end: usize,
    ejson: Option<String>
}

fn bytes_to_bson (el : &[u8]) -> bson::Bson {
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

    let reader = wrapper.as_slice();
    let doc = Document::from_reader(reader).expect("should read");
    if let Some((_,v)) = doc.iter().next() {
        return v.clone();
    } else {
        panic!("could not iterate");
    }
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

struct BsonIter{
    off : usize,
    doclen: usize,
}

struct BsonElement {
    keystr: String,
    start: usize,
    end: usize,
}

impl BsonIter {
    fn new (input: &[u8], off: usize) -> BsonIter {
        return BsonIter { off: off + 4, doclen: read_i32(input, off)}
    }
    fn next_element (&mut self, input: &[u8]) -> Option<BsonElement> {
        if self.off == self.doclen {
            return None;
        }
        let start = self.off;
        let signed_byte = input[self.off];
        println!("signed_byte={}", signed_byte);
        self.off+=1;
        
        let keystr = read_key (input, self.off);
        self.off += keystr.len() + 1;
        println!("keystr={}", keystr);

        // Depending on signed_byte, determine length of value.
        let end;
        if signed_byte == 16u8 {
            self.off += 4;
            end = self.off;
        } else if signed_byte == 5u8 {
            let len = read_i32 (input, self.off);
            self.off += 4 + 1 + len;
            end = self.off;
        } else if signed_byte == 2u8 {
            let len = read_i32 (input, self.off);
            self.off += 4 + len;
            end = self.off;
        }
        else {
            panic!("do not know how to parse element with signed byte: {}", signed_byte);
        }
        return Some(BsonElement { keystr, start, end });
    }
}

fn decode_payload (input: &[u8]) -> Vec<Item> {
    let mut ret = Vec::<Item>::new();
    let mut off = 0;
    let blob_subtype = input[off];

    ret.push(Item{
        start: off,
        end: off + 1,
        id: Id::BlobSubtype,
        desc: format!("{:?}", blob_subtype),
        ejson: None
    });
    off += 1;

    if blob_subtype == 0 {
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));

            let desc = "".to_string();
            if keystr == "a" {
                let desc = match bson.as_i32().unwrap() {
                    0 => "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                    1 => "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                    _ => "Unknown",
                }.to_string();
                ret.push(Item { start, end, id: Id::Algorithm, ejson, desc })
            } else if keystr == "ki" {
                ret.push(Item { start, end, id: Id::KeyUUID, ejson, desc })
            } else if keystr == "v" {
                ret.push(Item { start, end, id: Id::Value, ejson, desc })
            } else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 1 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: Id::KeyUUID, desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: Id::OriginalBsonType, desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: Id::Ciphertext, desc: hex::encode(ciphertext), ejson: None});
        off += ciphertext.len();
    } else {
        panic!("unrecognized blob subtype: {:?}", blob_subtype);
    }

    if off < input.len() {
        panic!("unexpected extra data: {:?}", &input[off..]);
    }

    return ret;
}

#[test]
fn test_decode0() {
    let input= BASE64_STANDARD.decode(b"ADgAAAAQYQABAAAABWtpABAAAAAEYWFhYWFhYWFhYWFhYWFhYQJ2AAwAAAA0NTctNTUtNTQ2MgAA").expect("should decode");
    let got = decode_payload(&input);

    let mut idx = 0;

    assert_eq!(got[idx].id, Id::BlobSubtype);
    assert_eq!(got[idx].desc, "0".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::Algorithm);
    assert_eq!(got[idx].desc, r#""a":1"#.to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::KeyUUID);
    assert_eq!(got[idx].desc, r#""ki":{"$binary":{"base64":"YWFhYWFhYWFhYWFhYWFhYQ==","subType":"04"}}"#.to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::Value);
    assert_eq!(got[idx].desc, r#""v":"457-55-5462""#.to_owned());
    idx += 1;
    
    assert_eq!(idx, got.len());
}

#[test]
fn test_decode1() {
    let input= BASE64_STANDARD.decode(b"AQAAAAAAAAAAAAAAAAAAAAACwj+3zkv2VM+aTfk60RqhXq6a/77WlLwu/BxXFkL7EppGsju/m8f0x5kBDD3EZTtGALGXlym5jnpZAoSIkswHoA==").expect("should decode");
    let got = decode_payload(&input);
    
    let mut idx = 0;

    assert_eq!(got[idx].id, Id::BlobSubtype);
    assert_eq!(got[idx].desc, "1".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::KeyUUID);
    assert_eq!(got[idx].desc, "00000000000000000000000000000000".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::OriginalBsonType);
    assert_eq!(got[idx].desc, "2".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::Ciphertext);
    assert_eq!(got[idx].desc, "c23fb7ce4bf654cf9a4df93ad11aa15eae9affbed694bc2efc1c571642fb129a46b23bbf9bc7f4c799010c3dc4653b4600b1979729b98e7a5902848892cc07a0".to_owned());
    idx += 1;

    assert_eq!(idx, got.len());
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

#[test]
fn test_golden_files () {
    todo!();
}

mod iue_impl;
// use iue_decoder::foo;

fn main() {
    let input = BASE64_STANDARD.decode(b"AQAAAAAAAAAAAAAAAAAAAAACwj+3zkv2VM+aTfk60RqhXq6a/77WlLwu/BxXFkL7EppGsju/m8f0x5kBDD3EZTtGALGXlym5jnpZAoSIkswHoA==").expect("should decode");

    let got: Vec<Item> = decode_payload(&input);
    for item in got.iter() {
        println!("{:?}", item);
    }

    println!("foo returned {}", iue_impl::foo());
}
