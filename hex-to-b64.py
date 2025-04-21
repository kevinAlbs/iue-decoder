import sys
import base64

as_bytes = bytes.fromhex(sys.argv[1])
as_b64 = base64.b64encode(as_bytes)
print(as_b64.decode("utf8"))