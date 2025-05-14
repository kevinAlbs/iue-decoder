from pathlib import Path
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
        # "Server Versions": "Added in 4.2"
    },
    {
        "FLE1DeterministicEncryptedValue": 1,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md'>Spec</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mongocrypt-ciphertext-private.h#L24-L36'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 4.2"
    },
    {
        "FLE1RandomEncryptedValue": 2,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/specifications/blob/9d0d3f0042a8cf5faeb47ae7765716151bfca9ef/source/bson-binary-encrypted/binary-encrypted.md'>Spec</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mongocrypt-ciphertext-private.h#L24-L36'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 4.2"
    },
    {
        "FLE2EncryptionPlaceholder": 3,
        "Created By": "mongocryptd / crypt_shared",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/mongo/blob/6ec0bf4dd0c59fdfcacaaa36d3b7cb374da3e243/src/mongo/crypto/fle_field_schema.idl#L161-L198'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-encryption-placeholder-private.h#L203-L228'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 4.2"
    },
    {
        "FLE2InsertUpdatePayload": 4,
        "Created By": "libmongocrypt",
        "Intended For": "mongocryptd / crypt_shared",
        "References": [
            "<a href='https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L232-L272'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-insert-update-payload-private.h#L27-L76'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 6.0. Removed in 7.0 (<a href='https://jira.mongodb.org/browse/SERVER-73303'>SERVER-73303</a>)"
    },
    {
        "FLE2FindEqualityPayload": 5,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L334-L359'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-find-equality-payload-private.h#L24-L30'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 6.0. Removed in 7.0 (<a href='https://jira.mongodb.org/browse/SERVER-73303'>SERVER-73303</a>)"
    },
    {
        "FLE2UnindexedEncryptedValue": 6,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-uev-private.h#L24-L44'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 6.0. Removed in 7.0 (<a href='https://jira.mongodb.org/browse/SERVER-73303'>SERVER-73303</a>)"
    },
    {
        "FLE2IndexedEqualityEncryptedValue": 7,
        "Created By": "mongod / mongos",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-iev-private.h#L38-L66'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2IndexedRangeEncryptedValue": 9,
        "Created By": "mongod / mongos",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-iev-private.h#L68-L84'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2FindRangePayload": 10,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/mongo/blob/443b0594b28476e3f78e0c5923fcebf2c7abd19b/src/mongo/crypto/fle_field_schema.idl#L447-L466'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-find-range-payload-private.h#L38-L53'>libmongocrypt</a>"
        ],
        # "Server Versions": "Added in 6.2 (<a href='https://jira.mongodb.org/browse/SERVER-68695'>SERVER-68695</a>). Removed in 7.0 (<a href='https://jira.mongodb.org/browse/SERVER-73303'>SERVER-73303</a>)"
    },
    {
        "FLE2InsertUpdatePayloadV2": 11,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L326-L404'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-insert-update-payload-private-v2.h#L54-L94'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2FindEqualityPayloadV2": 12,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L406-L426'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-find-equality-payload-private-v2.h#L24-L29'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2FindRangePayloadV2": 13,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L458-L505'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-find-range-payload-private-v2.h#L36-L59'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2EqualityIndexedValueV2": 14,
        "Created By": "mongod / mongos",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-iev-private-v2.h#L42-L62'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2RangeIndexedValueV2": 15,
        "Created By": "mongod / mongos",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-iev-private-v2.h#L65-L74'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2UnindexedEncryptedValueV2": 16,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-uev-v2-private.h#L24-L44'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2IndexedTextEncryptedValue": 17,
        "Created By": "mongod / mongos",
        "Intended For": "libmongocrypt",
        "References": [
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-payload-iev-private-v2.h#L81-L102'>libmongocrypt</a>"
        ],
    },
    {
        "FLE2FindTextPayload": 18,
        "Created By": "libmongocrypt",
        "Intended For": "mongod / mongos",
        "References": [
            "<a href='https://github.com/10gen/mongo/blob/31715bfe7e87f2908670654745cbf2df3db1796e/src/mongo/crypto/fle_field_schema.idl#L815-L850'>Server IDL</a>",
            "<a href='https://github.com/mongodb/libmongocrypt/blob/4e42cc36f2ff0cc059d5d49ae010d88fb6a82064/src/mc-fle2-find-text-payload-private.h#L59-L91'>libmongocrypt</a>"
        ],
    },
]

print ("<div id='blob-reference'>")
for item in items:
    if item["Intended For"] == "":
        continue
    subtype = next(iter(item.keys()))
    print ("<h2>{} ({})</h2>".format(subtype, item[subtype]))
    example = Path("./testdata/payload{}.b64".format(item[subtype])).read_text()
    print ("<p><a href='#' data-load='{}'>Load Example</a></p>".format(example))
    print ("<table>")
    print ("<tr><td>Created by</td><td>{}</td></tr>".format(item["Created By"]))
    print ("<tr><td>Intended for</td><td>{}</td></tr>".format(item["Intended For"]))
    print ("<tr><td>References</td><td>{}</td></tr>".format(" ".join(item["References"])))
    if "Server Versions" in item:
        print ("<tr><td>Server Versions</td><td>{}</td></tr>".format(item["Server Versions"]))
    print ("</table>")
print ("</div> <!-- #blob-reference -->")
