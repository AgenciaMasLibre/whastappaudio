#pip install pycryptodome
#

from pathlib import Path
import base64
from Crypto.Cipher import AES
import io

# Ruta del archivo encriptado
encrypted_file_path = Path("data")

# Clave en base64 y decodificación
media_key_b64 = "mediakey"
media_key_bytes = base64.b64decode(media_key_b64)

# Información del archivo
file_info = {
    "encrypted_file_exists": encrypted_file_path.exists(),
    "encrypted_file_size_bytes": encrypted_file_path.stat().st_size,
    "media_key_length": len(media_key_bytes),
    "media_key_preview": media_key_bytes[:8].hex()  # primeros 8 bytes
}
print(file_info)

# Función para derivar claves desde media_key
def derive_keys(media_key: bytes, media_type: str = 'audio'):
    import hashlib
    from Crypto.Hash import HMAC, SHA256

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

# Derivar claves a partir de la mediaKey
keys = derive_keys(media_key_bytes)

# Leer archivo encriptado
with open(encrypted_file_path, "rb") as f:
    encrypted_data = f.read()

# Eliminar el MAC (últimos 10 bytes)
encrypted_data_trimmed = encrypted_data[:-10]

# Desencriptar con AES CBC
cipher = AES.new(keys['cipher_key'], AES.MODE_CBC, keys['iv'])
decrypted_data = cipher.decrypt(encrypted_data_trimmed)

# Guardar archivo desencriptado
decrypted_file_path = Path("decoded_audio.opus")
with open(decrypted_file_path, "wb") as out_file:
    out_file.write(decrypted_data)

print("Archivo desencriptado guardado como:", decrypted_file_path.name)
