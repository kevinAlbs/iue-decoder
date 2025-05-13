items = [
    {
        "FLE1EncryptionPlaceholder": 0,
        "Created By": "mongocryptd / crypt_shared",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md'>Spec</a>",
            "<a href='https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L134-L159'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mongocrypt-marking.c#L47-L143'>libmongocrypt</a>"
        ],
        "Server Versions": "Added in 4.2"
    },
    {
        "FLE1DeterministicEncryptedValue": 1,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md'>Spec</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mongocrypt-ciphertext-private.h#L24-L36'>libmongocrypt</a>"
        ],
        "Server Versions": "Added in 4.2"
    },
    {
        "FLE1RandomEncryptedValue": 2,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md'>Spec</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mongocrypt-ciphertext-private.h#L24-L36'>libmongocrypt</a>"
        ],
        "Server Versions": "Added in 4.2"
    },
    {
        "FLE2EncryptionPlaceholder": 3,
        "Created By": "mongocryptd / crypt_shared",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L161-L198'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-encryption-placeholder-private.h#L203-L228'>libmongocrypt</a>"
        ],
        "Server Versions": "Added in 4.2"
    },
    {
        "FLE2InsertUpdatePayload": 4,
        "Created By": "libmongocrypt",
        "Intended For": "mongocryptd / crypt_shared",
        "References": [
            "<a href='https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L161-L198'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-insert-update-payload-private.h#L27-L76'>libmongocrypt</a>"
        ],
        "Server Versions": "Added in 6.0. Removed in 7.0 (<a href='https://jira.mongodb.org/browse/SERVER-73303'>SERVER-73303</a>)"
    },
    {
        "FLE2FindEqualityPayload": 5,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2UnindexedEncryptedValue": 6,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2IndexedEqualityEncryptedValue": 7,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2IndexedRangeEncryptedValue": 9,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2FindRangePayload": 10,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2InsertUpdatePayloadV2": 11,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2FindEqualityPayloadV2": 12,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2FindRangePayloadV2": 13,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2EqualityIndexedValueV2": 14,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2RangeIndexedValueV2": 15,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2UnindexedEncryptedValueV2": 16,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2IndexedTextEncryptedValue": 17,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
    {
        "FLE2IndexedTextEncryptedValue": 18,
        "Created By": "TODO",
        "Intended For": "",
        "References": [],
    },
]

for item in items:
    if item["Intended For"] == "":
        continue
    subtype = next(iter(item.keys()))
    # print (subtype)
    print ("<h2>{} ({})</h2>".format(subtype, item[subtype]))
    print ("<table>")
    print ("<tr><td>Created by</td><td>{}</td></tr>".format(item["Created By"]))
    print ("<tr><td>Intended for</td><td>{}</td></tr>".format(item["Intended For"]))
    print ("<tr><td>References</td><td>{}</td></tr>".format(" ".join(item["References"])))
    if "Server Versions" in item:
        print ("<tr><td>Server Versions</td><td>{}</td></tr>".format(item["Server Versions"]))
    print ("</table>")
    
