"""Sample code for the pqc-scan code scanner tests. Not meant to be run."""

import hashlib
import hmac
import ssl
from hashlib import md5 as legacy_md5

import jwt
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA as PyRSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric import rsa as r
from cryptography.hazmat.primitives.ciphers import modes

KEY_BITS = 4096

weak = r.generate_private_key(public_exponent=65537, key_size=1024)
dynamic = r.generate_private_key(65537, KEY_BITS)
curve_key = ec.generate_private_key(ec.SECP384R1())
edwards = ed25519.Ed25519PrivateKey.generate()
digest = hashes.SHA1()
mode = modes.ECB()
fingerprint = legacy_md5(b"data").hexdigest()
by_name = hashlib.new("sha224")
unknown_name = hashlib.new(input())
mac = hmac.new(b"k", b"m", hashlib.sha1)
derived = hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 100_000)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
context.minimum_version = ssl.TLSVersion.TLSv1_1
legacy_rsa = PyRSA.generate(2048)
ecb_cipher = AES.new(b"0" * 16, AES.MODE_ECB)
triple = DES3.new(b"0" * 24, DES3.MODE_CBC)
token = jwt.encode({"a": 1}, "secret", algorithm="HS256")
# hashlib.md5() in a comment is not code
text = "hashlib.md5() inside a string is not code"
