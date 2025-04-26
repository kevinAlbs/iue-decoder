use bson::{Bson, Document};
use hex;
use wasm_bindgen::prelude::*;
use base64::prelude::*;

#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct Item {
    id: String,
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
    pub fn id(&self) -> String {
        self.id.clone()
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
    startoff: usize,
    doclen: usize,
    prev_signedbyte: u8,
    prev_off: usize,
}

struct BsonElement {
    keystr: String,
    start: usize,
    end: usize,
}

impl BsonIter {
    fn new (input: &[u8], off: usize) -> BsonIter {
        return BsonIter { off: off + 4, startoff: off, doclen: read_i32(input, off), prev_off: 0, prev_signedbyte: 0}
    }
    fn recurse (&self, input: &[u8]) -> BsonIter {
        // Depending on signed_byte, determine length of value.
        if self.prev_signedbyte == 3u8 {
            return BsonIter::new(input, self.prev_off);
        } else if self.prev_signedbyte == 4u8 {
            return BsonIter::new(input, self.prev_off);
        }
        else {
            panic!("do not know how to recurse element with signed byte: {}", self.prev_signedbyte);
        }
    }
    fn next_element (&mut self, input: &[u8]) -> Option<BsonElement> {
        println!("self.off={}, stop at: {}", self.off, self.doclen + self.startoff - 1);
        if self.off == self.startoff + self.doclen - 1 {
            return None;
        }
        let start = self.off;
        let signed_byte = input[self.off];
        println!("signed_byte={}", signed_byte);
        self.prev_signedbyte = signed_byte;
        self.off+=1;
        
        let keystr = read_key (input, self.off);
        self.off += keystr.len() + 1;
        self.prev_off = self.off;
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
        } else if signed_byte == 3u8 {
            let len = read_i32 (input, self.off);
            println!("doc len: {}", len);
            self.off += len;
            end = self.off;
        }  else if signed_byte == 4u8 {
            let len = read_i32 (input, self.off);
            println!("doc len: {}", len);
            self.off += len;
            end = self.off;
        }
        else {
            panic!("do not know how to parse element with signed byte: {}", signed_byte);
        }
        return Some(BsonElement { keystr, start, end });
    }
}

fn blob_subtype_to_string(blob_subtype: u8) -> &'static str {
    match blob_subtype {
        0 => "FLE1EncryptionPlaceholder",
        1 => "FLE1DeterministicEncryptedValue",
        2 => "FLE1RandomEncryptedValue",
        3 => "FLE2EncryptionPlaceholder",
        4 => "FLE2InsertUpdatePayload",
        5 => "FLE2FindEqualityPayload",
        6 => "FLE2UnindexedEncryptedValue",
        7 => "FLE2IndexedEqualityEncryptedValue",
        9 => "FLE2IndexedRangeEncryptedValue",
        10 => "FLE2FindRangePayload",
        11 => "FLE2InsertUpdatePayloadV2",
        12 => "FLE2FindEqualityPayloadV2",
        13 => "FLE2FindRangePayloadV2",
        14 => "FLE2EqualityIndexedValueV2",
        15 => "FLE2RangeIndexedValueV2",
        16 => "FLE2UnindexedEncryptedValueV2",
        17 => "FLE2IndexedTextEncryptedValue",
        _ => panic!("{} has no string name. Please add one.", blob_subtype),
    }
}

pub fn decode_payload (input: &[u8]) -> Vec<Item> {
    let mut ret = Vec::<Item>::new();
    let mut off = 0;
    let blob_subtype = input[off];

    ret.push(Item{
        start: off,
        end: off + 1,
        id: "BlobSubtype".to_string(),
        desc: format!("{:?} ({})", blob_subtype, blob_subtype_to_string(blob_subtype)),
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
                ret.push(Item { start, end, id: "Algorithm".to_string(), ejson, desc })
            } else if keystr == "ki" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    },
                    _ => panic!("Unexpected non-binary for 'ki")
                };

                ret.push(Item { start, end, id: "KeyUUID".to_string(), ejson, desc })
            } else if keystr == "v" {
                let desc = bson.into_relaxed_extjson().to_string();
                ret.push(Item { start, end, id: "Value".to_string(), ejson, desc })
            } else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 1 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: "KeyUUID".to_string(), desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: "OriginalBsonType".to_string(), desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: "Ciphertext".to_string(), desc: hex::encode(ciphertext), ejson: None});
        off += ciphertext.len();
    } else if blob_subtype == 2 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: "KeyUUID".to_string(), desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: "OriginalBsonType".to_string(), desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: "Ciphertext".to_string(), desc: hex::encode(ciphertext), ejson: None});
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
                ret.push(Item { start, end, id: "Type".to_string(), ejson, desc })
            } else if keystr == "a" {
                let desc = match bson.as_i32().unwrap() {
                    1 => "Unindexed",
                    2 => "Indexed Equality",
                    3 => "Indexed Range",
                    _ => "Unknown",
                }.to_string();

                ret.push(Item { start, end, id: "Algorithm".to_string(), ejson, desc })
            } else if keystr == "v" {
                let desc = bson.into_relaxed_extjson().to_string();
                ret.push(Item { start, end, id: "Value".to_string(), ejson, desc })
            } else if keystr == "cm" {
                let desc = format!("{}",bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "MaxContentionCounter".to_string(), ejson, desc })
            } else if keystr == "ki" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    },
                    _ => panic!("Unexpected non-binary for 'ki")
                };

                ret.push(Item { start, end, id: "IndexKeyId".to_string(), ejson, desc })
            } else if keystr == "ku" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    },
                    _ => panic!("Unexpected non-binary for 'ku")
                };

                ret.push(Item { start, end, id: "UserKeyId".to_string(), ejson, desc })
            } else if keystr == "s" {
                let desc = format!("{}",bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "Sparsity".to_string(), ejson, desc })
            }
            else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 4 {
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));
            if keystr == "d" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "EDCDerivedFromDataTokenAndCounter".to_string(), ejson, desc })
            }
            else if keystr == "s" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ESCDerivedFromDataTokenAndCounter".to_string(), ejson, desc })
            }
            else if keystr == "c" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ECCDerivedFromDataTokenAndCounter".to_string(), ejson, desc })
            }
            else if keystr == "p" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "Encrypted tokens".to_string(), ejson, desc })
            }
            else if keystr == "u" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "IndexKeyId".to_string(), ejson, desc })
            }
            else if keystr == "t" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "Encrypted Type".to_string(), ejson, desc })
            }
            else if keystr == "v" {
                let desc = bson.into_relaxed_extjson().to_string();
                ret.push(Item { start, end, id: "Value".to_string(), ejson, desc })
            }
            else if keystr == "e" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ServerDataEncryptionLevel1Token".to_string(), ejson, desc })
            }
            else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 5 {
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));
            if keystr == "d" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "EDCDerivedFromDataToken".to_string(), ejson, desc })
            }
            else if keystr == "s" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ESCDerivedFromDataToken".to_string(), ejson, desc })
            }
            else if keystr == "c" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ECCDerivedFromDataToken".to_string(), ejson, desc })
            }
            else if keystr == "cm" {
                let desc = format!("{}", bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "Encrypted tokens".to_string(), ejson, desc })
            }
            else if keystr == "e" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ServerDataEncryptionLevel1Token".to_string(), ejson, desc })
            }
            else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 6 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: "KeyUUID".to_string(), desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: "OriginalBsonType".to_string(), desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: "Ciphertext".to_string(), desc: hex::encode(ciphertext), ejson: None});
        off += ciphertext.len();
    } else if blob_subtype == 7 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: "S_KeyID".to_string(), desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: "OriginalBsonType".to_string(), desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: "InnerEncrypted".to_string(), desc: hex::encode(ciphertext), ejson: None});
        off += ciphertext.len();
    } else if blob_subtype == 9 {
        let keyuuid = &input[off..off+16];
        ret.push(Item { start: off, end: off+16, id: "key_uuid".to_string(), desc: hex::encode(keyuuid), ejson: None});
        off += 16;

        let original_bson_type = input[off];
        ret.push(Item { start: off, end: off+1, id: "OriginalBsonType".to_string(), desc: format!("{}", original_bson_type), ejson: None});
        off += 1;

        let ciphertext = &input[off..];
        ret.push(Item { start: off, end: off + ciphertext.len(), id: "InnerEncrypted".to_string(), desc: hex::encode(ciphertext), ejson: None});
        off += ciphertext.len();
    } else if blob_subtype == 10 {
        // https://github.com/mongodb/mongo/blob/8af29f897d967f540c60ca8fb6f38f65e6fc9620/src/mongo/crypto/fle_field_schema.idl#L317-L336
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));

            if keystr == "payload" {
                // Create a recursive iterator.
                println!("recursing payload ... begin");
                let mut payload_iter = iter.recurse(input);
                while let Some(el) = payload_iter.next_element(input) {
                    println!("on key {} ... begin", el.keystr);

                    let BsonElement{keystr, start, end} = el;
                    let bytes = &input[start..end];
                    let bson = bytes_to_bson(bytes);
                    let ejson = Some(bytes_to_ejson(bytes));
                    if keystr == "g" {
                        let mut g_iter = payload_iter.recurse(input);
                        while let Some(el) = g_iter.next_element(input) {
                            let idx = el.keystr;
                            let mut g_doc_iter = g_iter.recurse(input);
                            while let Some(el) = g_doc_iter.next_element(input) {
                                let BsonElement{keystr, start, end} = el;
                                let bytes = &input[start..end];
                                let bson = bytes_to_bson(bytes);
                                let ejson = Some(bytes_to_ejson(bytes));

                                if keystr == "d" {
                                    let desc = match bson {
                                        bson::Bson::Binary(b) => {
                                            hex::encode(b.bytes)
                                        },
                                        _ => panic!("Unexpected non-binary for g")
                                    };
                                    ret.push(Item { start, end, id: format!("payload edge [{}] EDCDerivedFromDataToken", idx), ejson, desc })
                                }
                                else if keystr == "s" {
                                    let desc = match bson {
                                        bson::Bson::Binary(b) => {
                                            hex::encode(b.bytes)
                                        },
                                        _ => panic!("Unexpected non-binary for g")
                                    };
                                    ret.push(Item { start, end, id: format!("payload edge [{}] ESCDerivedFromDataToken", idx), ejson, desc })
                                }
                                else if keystr == "c" {
                                    let desc = match bson {
                                        bson::Bson::Binary(b) => {
                                            hex::encode(b.bytes)
                                        },
                                        _ => panic!("Unexpected non-binary for g")
                                    };
                                    ret.push(Item { start, end, id: format!("payload edge [{}] ECCDerivedFromDataToken", idx), ejson, desc })
                                }
                            }
                        }
                    } else if keystr == "e" {
                        let desc = match bson {
                            bson::Bson::Binary(b) => {
                                hex::encode(b.bytes)
                            }
                            _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                        }.to_string();
                        ret.push(Item { start, end, id: "payload.ServerDataEncryptionLevel1Token".to_string(), ejson, desc })
                    }
                    else if keystr == "cm" {
                        let desc = format!("{}", bson.as_i64().unwrap());
                        ret.push(Item { start, end, id: "payload.Queryable Encryption max counter".to_string(), ejson, desc })
                    }
                    println!("on key ... end");
                }

                println!("recursing payload ... end");
            }
            else if keystr == "payloadId" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "payloadId".to_string(), ejson, desc })
            }
            else if keystr == "firstOperator" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "firstOperator".to_string(), ejson, desc })
            }
            else if keystr == "secondOperator" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "secondOperator".to_string(), ejson, desc })
            }
            else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 12 {
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));
            if keystr == "d" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "EDCDerivedFromDataToken".to_string(), ejson, desc })
            }
            else if keystr == "s" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ESCDerivedFromDataToken".to_string(), ejson, desc })
            }
            else if keystr == "l" {
                let desc = match bson {
                    bson::Bson::Binary(b) => {
                        hex::encode(b.bytes)
                    }
                    _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                }.to_string();
                ret.push(Item { start, end, id: "ServerDerivedFromDataToken".to_string(), ejson, desc })
            }
            else if keystr == "cm" {
                let desc = format!("{}", bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "Encrypted tokens".to_string(), ejson, desc })
            }
            else {
                panic!("unexpected field for {:?}: {}", blob_subtype, keystr);
            }
        }

        off += iter.doclen;
    } else if blob_subtype == 13 {
        // https://github.com/mongodb/mongo/blob/8af29f897d967f540c60ca8fb6f38f65e6fc9620/src/mongo/crypto/fle_field_schema.idl#L317-L336
        let mut iter = BsonIter::new(input, off);
        while let Some(el) = iter.next_element(input) {
            let BsonElement{keystr, start, end} = el;
            let bytes = &input[start..end];
            let bson = bytes_to_bson(bytes);
            let ejson = Some(bytes_to_ejson(bytes));

            if keystr == "payload" {
                // Create a recursive iterator.
                println!("recursing payload ... begin");
                let mut payload_iter = iter.recurse(input);
                while let Some(el) = payload_iter.next_element(input) {
                    println!("on key {} ... begin", el.keystr);

                    let BsonElement{keystr, start, end} = el;
                    let bytes = &input[start..end];
                    let bson = bytes_to_bson(bytes);
                    let ejson = Some(bytes_to_ejson(bytes));
                    if keystr == "g" {
                        let mut g_iter = payload_iter.recurse(input);
                        while let Some(el) = g_iter.next_element(input) {
                            let idx = el.keystr;
                            let mut g_doc_iter = g_iter.recurse(input);
                            while let Some(el) = g_doc_iter.next_element(input) {
                                let BsonElement{keystr, start, end} = el;
                                let bytes = &input[start..end];
                                let bson = bytes_to_bson(bytes);
                                let ejson = Some(bytes_to_ejson(bytes));

                                if keystr == "d" {
                                    let desc = match bson {
                                        bson::Bson::Binary(b) => {
                                            hex::encode(b.bytes)
                                        },
                                        _ => panic!("Unexpected non-binary for g")
                                    };
                                    ret.push(Item { start, end, id: format!("payload edge [{}] EDCDerivedFromDataToken", idx), ejson, desc })
                                }
                                else if keystr == "s" {
                                    let desc = match bson {
                                        bson::Bson::Binary(b) => {
                                            hex::encode(b.bytes)
                                        },
                                        _ => panic!("Unexpected non-binary for g")
                                    };
                                    ret.push(Item { start, end, id: format!("payload edge [{}] ESCDerivedFromDataToken", idx), ejson, desc })
                                }
                                else if keystr == "c" {
                                    let desc = match bson {
                                        bson::Bson::Binary(b) => {
                                            hex::encode(b.bytes)
                                        },
                                        _ => panic!("Unexpected non-binary for g")
                                    };
                                    ret.push(Item { start, end, id: format!("payload edge [{}] ECCDerivedFromDataToken", idx), ejson, desc })
                                }
                            }
                        }
                    } else if keystr == "e" {
                        let desc = match bson {
                            bson::Bson::Binary(b) => {
                                hex::encode(b.bytes)
                            }
                            _ => panic!("Unexpected non-binary for {}, {}", blob_subtype, keystr)
                        }.to_string();
                        ret.push(Item { start, end, id: "payload.ServerDataEncryptionLevel1Token".to_string(), ejson, desc })
                    }
                    println!("on key ... end");
                }

                println!("recursing payload ... end");
            }
            else if keystr == "payloadId" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "payloadId".to_string(), ejson, desc })
            }
            else if keystr == "firstOperator" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "firstOperator".to_string(), ejson, desc })
            }
            else if keystr == "secondOperator" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "secondOperator".to_string(), ejson, desc })
            } else if keystr == "cm" {
                let desc = format!("{}", bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "payload.Queryable Encryption max counter".to_string(), ejson, desc })
            } else if keystr == "sp" {
                let desc = format!("{}", bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "payload.Queryable Encryption sparsity".to_string(), ejson, desc })
            } else if keystr == "pn" {
                let desc = format!("{}", bson.as_i64().unwrap());
                ret.push(Item { start, end, id: "payload.Queryable Encryption precision".to_string(), ejson, desc })
            } else if keystr == "tf" {
                let desc = format!("{}", bson.as_i32().unwrap());
                ret.push(Item { start, end, id: "payload.Queryable Encryption trimFactor".to_string(), ejson, desc })
            } else if keystr == "mn" {
                ret.push(Item { start, end, id: "payload.Queryable Encryption indexMin".to_string(), ejson: ejson.clone(), desc: ejson.unwrap() })
            } else if keystr == "mx" {
                ret.push(Item { start, end, id: "payload.Queryable Encryption indexMax".to_string(), ejson: ejson.clone(), desc: ejson.unwrap() })
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
        out += format!("{}={}", item.id, item.desc).as_str();
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

    assert_eq!(got[idx].id, "BlobSubtype".to_string());
    assert_eq!(got[idx].desc, "0 (FLE1EncryptionPlaceholder)".to_owned());
    idx += 1;

    assert_eq!(got[idx].id, "Algorithm".to_string());
    assert_eq!(got[idx].ejson, Some(r#""a":1"#.to_owned()));
    assert_eq!(got[idx].desc, "AEAD_AES_256_CBC_HMAC_SHA_512-Random");
    idx += 1;

    assert_eq!(got[idx].id, "KeyUUID".to_string());
    assert_eq!(got[idx].ejson, Some(r#""ki":{"$binary":{"base64":"YWFhYWFhYWFhYWFhYWFhYQ==","subType":"04"}}"#.to_owned()));
    idx += 1;

    assert_eq!(got[idx].id, "Value".to_string());
    assert_eq!(got[idx].ejson, Some(r#""v":"457-55-5462""#.to_owned()));
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
fn test_bson_iter() {
    // bson.encode({"x": {"y": 1}, "z": 2}).hex()
    let v : Vec<u8> = hex::decode("1b0000000378000c0000001079000100000000107a000200000000").unwrap();
    let input = v.as_slice();
    let mut bson_iter = BsonIter::new(input, 0);

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "x");

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "z");

    let got = bson_iter.next_element(input);
    assert!(got.is_none());

    // bson.encode({"x": "y", "z": 2}).hex()
    let v : Vec<u8> = hex::decode("15000000027800020000007900107a000200000000").unwrap();
    let input = v.as_slice();
    let mut bson_iter = BsonIter::new(input, 0);

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "x");

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "z");

    let got = bson_iter.next_element(input);
    assert!(got.is_none());

    // bson.encode({"x": "y", "z": 2}).hex()
    let v : Vec<u8> = hex::decode("3800000010610001000000056b69001000000004616161616161616161616161616161610276000c0000003435372d35352d353436320000").unwrap();
    let input = v.as_slice();
    let mut bson_iter = BsonIter::new(input, 0);

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "a");

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "ki");

    let got = bson_iter.next_element(input);
    assert!(got.is_some());
    assert_eq!(got.unwrap().keystr, "v");

    let got = bson_iter.next_element(input);
    assert!(got.is_none());
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
            let file_golden = format!("testdata/{}.golden", without_ext);
            let golden = std::fs::read_to_string(file_golden.clone()).unwrap();
            let golden = golden.replace("\r\n", "\n").to_string();
            let input = BASE64_STANDARD.decode(b64).unwrap();
            let got = dump_payload(input.as_slice());
            if got != golden {
                if let Ok(env) = std::env::var("WRITE_GOLDEN") {
                    if env == "1".to_string() {
                        println!("Overwriting: {}", file_golden.clone());
                        std::fs::write(file_golden, got).expect("should overwrite");
                        continue;
                    }
                }
                println!("got:\n{}", got);
                println!("golden:\n{}", golden);
                assert_eq!(got, golden);
            }
            assert_eq!(got, golden);
    }
}



