use bson::{Binary, Bson, Document};
use hex;
use wasm_bindgen::prelude::*;
use base64::prelude::*;

#[derive(PartialEq, Debug, Clone, Copy)]

#[wasm_bindgen]
pub enum Id {
    BlobSubtype,
    KeyUUID,
    Algorithm,
    Value,
    OriginalBsonType,
    Ciphertext,
    FLE2EncryptionPlaceholder_Type,
    FLE2EncryptionPlaceholder_Algorithm,
    FLE2EncryptionPlaceholder_UserKeyId,
    FLE2EncryptionPlaceholder_IndexKeyId,
    FLE2EncryptionPlaceholder_Value,
    FLE2EncryptionPlaceholder_MaxContentionCounter,
    FLE2EncryptionPlaceholder_Sparsity
}

#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct Item {
    pub id: Id,
    desc: String,
    pub start: usize,
    pub end: usize,
    ejson: Option<String>
}

#[wasm_bindgen]
impl Item {
    #[wasm_bindgen(getter)]
    pub fn desc(&self) -> String {
        self.desc.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ejson(&self) -> Option<String> {
        self.ejson.clone()
    }
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
        } else if signed_byte == 18u8 {
            // int64
            self.off += 8;
            end = self.off;
        }
        else {
            panic!("do not know how to parse element with signed byte: {}", signed_byte);
        }
        return Some(BsonElement { keystr, start, end });
    }
}

pub fn decode_payload (input: &[u8]) -> Vec<Item> {
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
            if keystr == "a" {
                let desc = match bson.as_i32().unwrap() {
                    0 => "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                    1 => "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                    _ => "Unknown",
                }.to_string();
                ret.push(Item { start, end, id: Id::Algorithm, ejson, desc })
            } else if keystr == "ki" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    },
                    _ => panic!("Unexpected non-binary for 'ki")
                };

                ret.push(Item { start, end, id: Id::KeyUUID, ejson, desc })
            } else if keystr == "v" {
                let desc = bson.into_relaxed_extjson().to_string();
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
    } else if blob_subtype == 2 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: Id::KeyUUID, desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: Id::OriginalBsonType, desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: Id::Ciphertext, desc: hex::encode(ciphertext), ejson: None});
        off += ciphertext.len();
    } else if blob_subtype == 3 {
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));
            if keystr == "t" {
                let desc = match bson.as_i32().unwrap() {
                    1 => "Insert",
                    2 => "Find",
                    _ => "Unknown",
                }.to_string();
                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_Type, ejson, desc })
            } else if keystr == "a" {
                let desc = match bson.as_i32().unwrap() {
                    1 => "Unindexed",
                    2 => "Indexed Equality",
                    3 => "Indexed Range",
                    _ => "Unknown",
                }.to_string();

                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_Algorithm, ejson, desc })
            } else if keystr == "v" {
                let desc = bson.into_relaxed_extjson().to_string();
                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_Value, ejson, desc })
            } else if keystr == "cm" {
                let desc = format!("{}",bson.as_i64().unwrap());
                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_MaxContentionCounter, ejson, desc })
            } else if keystr == "ki" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    },
                    _ => panic!("Unexpected non-binary for 'ki")
                };

                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_IndexKeyId, ejson, desc })
            } else if keystr == "ku" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    },
                    _ => panic!("Unexpected non-binary for 'ku")
                };

                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_UserKeyId, ejson, desc })
            } else if keystr == "s" {
                let desc = format!("{}",bson.as_i64().unwrap());
                ret.push(Item { start, end, id: Id::FLE2EncryptionPlaceholder_Sparsity, ejson, desc })
            }
            else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else {
        panic!("unrecognized blob subtype: {:?}", blob_subtype);
    }

    if off < input.len() {
        panic!("unexpected extra data: {:?}", &input[off..]);
    }

    return ret;
}

fn dump_payload (input : &[u8]) -> String {
    let mut out = String::new();

    let items = decode_payload(&input);
    for item in items.iter() {
        out += format!("{:?}={}", item.id, item.desc).as_str();
        if let Some(ejson) = &item.ejson {
            out += format! (" ({})", ejson).as_str();
        }
        out += "\n";
    }

    return out;
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
    assert_eq!(got[idx].ejson, Some(r#""a":1"#.to_owned()));
    assert_eq!(got[idx].desc, "AEAD_AES_256_CBC_HMAC_SHA_512-Random");
    idx += 1;

    assert_eq!(got[idx].id, Id::KeyUUID);
    assert_eq!(got[idx].ejson, Some(r#""ki":{"$binary":{"base64":"YWFhYWFhYWFhYWFhYWFhYQ==","subType":"04"}}"#.to_owned()));
    idx += 1;

    assert_eq!(got[idx].id, Id::Value);
    assert_eq!(got[idx].ejson, Some(r#""v":"457-55-5462""#.to_owned()));
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
fn test_decode2() {
    let input= BASE64_STANDARD.decode(b"Am2IfShB4k/NqP8INteqCxUCEikm46tQNyXYxnUWcZ2J7mXfvZFHvSfQwQoXgUPt9I2Q1h3aN1K4mkgOOfk7jaOGZtPRW3iVjaeRjUh9Xw3M+Q==").expect("should decode");
    let got = decode_payload(&input);
    
    let mut idx = 0;

    assert_eq!(got[idx].id, Id::BlobSubtype);
    assert_eq!(got[idx].desc, "2".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::KeyUUID);
    assert_eq!(got[idx].desc, "6d887d2841e24fcda8ff0836d7aa0b15".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::OriginalBsonType);
    assert_eq!(got[idx].desc, "2".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, Id::Ciphertext);
    assert_eq!(got[idx].desc, "122926e3ab503725d8c67516719d89ee65dfbd9147bd27d0c10a178143edf48d90d61dda3752b89a480e39f93b8da38666d3d15b78958da7918d487d5f0dccf9".to_owned());
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
    let dir = std::fs::read_dir("testdata").unwrap();
    for entry in dir {
        let entry = entry.unwrap();
            let file = entry.file_name();
            if !file.to_str().unwrap().ends_with(".b64") {
                continue;
            }
            let file_b64 = file.to_str().unwrap();
            let without_ext = &file_b64[0..file_b64.len() - ".b64".len()];
            println!("testing {}", without_ext);
            let b64 = std::fs::read_to_string(format!("testdata/{}", file_b64)).unwrap();
            let golden = std::fs::read_to_string(format!("testdata/{}.golden", without_ext)).unwrap();
            let golden = golden.replace("\r\n", "\n").to_string();
            let input = BASE64_STANDARD.decode(b64).unwrap();
            let got = dump_payload(input.as_slice());
            if got != golden {
                println!("got:\n{}", got);
                println!("golden:\n{}", golden);
                assert_eq!(got, golden);
            }
            assert_eq!(got, golden);
    }
}


