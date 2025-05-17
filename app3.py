#pip install pycryptodome
#
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse
import base64
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import uuid
import os

app = FastAPI()

def derive_keys(media_key: bytes, media_type: str = 'audio'):
    info_str = f"WhatsApp {media_type.capitalize()} Keys".encode()

    def hkdf_expand(key_material, info, length=112):
        prk = HMAC.new(b'\x00' * 32, key_material, SHA256).digest()
        output = b""
        t = b""
        counter = 1
        while len(output) < length:
            t = HMAC.new(prk, t + info + bytes([counter]), SHA256).digest()
            output += t
            counter += 1
        return output[:length]

    expanded_key = hkdf_expand(media_key, info_str)
    return {
        "iv": expanded_key[0:16],
        "cipher_key": expanded_key[16:48],
        "mac_key": expanded_key[48:80]
    }

@app.post("/decrypt")
async def decrypt_opus(file: UploadFile, media_key_b64: str = Form(...)):
    file_bytes = await file.read()
    media_key = base64.b64decode(media_key_b64)

    keys = derive_keys(media_key)

    encrypted_data_trimmed = file_bytes[:-10]

    cipher = AES.new(keys['cipher_key'], AES.MODE_CBC, keys['iv'])
    decrypted_data = cipher.decrypt(encrypted_data_trimmed)

    output_filename = f"/tmp/{uuid.uuid4()}.opus"
    with open(output_filename, "wb") as f:
        f.write(decrypted_data)

    return FileResponse(output_filename, media_type="audio/ogg", filename="output.opus")
