"""Print public synthetic known-answer fixtures using Python cryptography.

Independent of Rust implementation and upstream client code. Never accepts real
credentials or endpoints. Optional argon2-cffi adds an Argon2id known answer.
"""
import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

b64 = lambda value: base64.b64encode(value).decode()
password = "PUBLIC-FIXTURE-password-not-for-real-use"
email = "reader@example.com"
iterations = 10000
master = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), iterations, 32)
auth = hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1, 32)
# One-block HKDF-Expand (32-byte output), not HKDF-Extract.
stretched = b"".join(hmac.new(master, info + b"\x01", hashlib.sha256).digest() for info in (b"enc", b"mac"))
user_key = bytes(range(64))
item_key = bytes(range(64, 128))

def encrypt(value, key, label):
    if isinstance(value, str):
        value = value.encode()
    iv = hashlib.sha256(("PUBLIC-FIXTURE/" + label).encode()).digest()[:16]
    padding = PKCS7(128).padder()
    padded = padding.update(value) + padding.finalize()
    operation = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    data = operation.update(padded) + operation.finalize()
    tag = hmac.new(key[32:], iv + data, hashlib.sha256).digest()
    return "2." + "|".join(map(b64, (iv, data, tag)))

wrapped = encrypt(user_key, stretched, "account-key")
records = [
    {"id": "login", "type": 1, "name": encrypt("Example login", user_key, "login-name"),
     "login": {"username": encrypt("reader@example.com", user_key, "username"),
               "password": encrypt("PUBLIC-fixture-login-password", user_key, "password"),
               "uris": [{"uri": encrypt("https://example.com", user_key, "uri")}],
               "totp": None, "fido2Credentials": []}},
    {"id": "note", "type": 2, "name": encrypt("Example note", item_key, "note-name"),
     "key": encrypt(item_key, user_key, "item-key"),
     "notes": encrypt("PUBLIC fixture secure note", item_key, "note-body")},
    {"id": "card", "type": 3, "name": encrypt("Example card", user_key, "card-name"),
     "card": {"number": encrypt("4111111111111111", user_key, "card-number"),
              "code": encrypt("123", user_key, "card-code")}},
    {"id": "identity", "type": 4, "name": encrypt("Example identity", user_key, "identity-name"),
     "identity": {"email": encrypt("person@example.org", user_key, "identity-email")}},
    {"id": "ssh", "type": 5, "name": encrypt("Example SSH", user_key, "ssh-name"),
     "sshKey": {"publicKey": encrypt("PUBLIC-FIXTURE-NOT-AN-SSH-KEY", user_key, "ssh-public")}},
    {"id": "org", "type": 1, "organizationId": "fixture-org"},
    {"id": "reprompt", "type": 1, "reprompt": 1},
    {"id": "unknown", "type": 999},
]
output = {
    "notice": "PUBLIC SYNTHETIC FIXTURE. Generated independently with Python cryptography. No real credentials.",
    "password": password, "email": email, "masterKey": b64(master), "authorizationHash": b64(auth),
    "userKey": b64(user_key), "itemKey": b64(item_key),
    "prelogin": {"kdf": 0, "kdfIterations": iterations},
    "tokens": {"access_token": "PUBLIC-fixture-access-token", "refresh_token": "PUBLIC-fixture-refresh-token", "Key": wrapped},
    "sync": {"profile": {"email": email, "key": wrapped}, "ciphers": records},
}
try:
    from argon2.low_level import hash_secret_raw, Type
    derived = hash_secret_raw(password.encode(), hashlib.sha256(email.encode()).digest(), 2, 16384, 1, 32, Type.ID, version=19)
    output["argon2"] = {"memoryMiB": 16, "iterations": 2, "parallelism": 1,
                         "masterKey": b64(derived),
                         "authorizationHash": b64(hashlib.pbkdf2_hmac("sha256", derived, password.encode(), 1, 32))}
except ImportError:
    pass
print(json.dumps(output, indent=2))
