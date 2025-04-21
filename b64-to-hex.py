import sys
import base64

as_b64 = base64.b64decode(sys.argv[1])
as_hex = as_b64.hex()
print(as_hex)