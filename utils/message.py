import base64
import time

message = {
    "header": {
        "crc": "val",
        "timestamp": int(time.time())
    },
    "message": base64.encodebytes(b"1"),
    "security": {
        "hmac": {
            "hmac_type": "val",
            "hmac_val": "val"
        },
        "enc_type": "val"
    }
}

print(message)
