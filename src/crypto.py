import binascii
import pure_pynacl as nacl
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encode(senderPriv:str, recipientPub:str, msg:str, isHexString:bool = False):
    # Processing
    iv = binascii.unhexlify(secrets.token_hex(12))
    if not isHexString:
        msg = msg.encode(encoding='utf8')
    else:
        msg = binascii.unhexlify(msg)
    encoded = _encode(binascii.unhexlify(senderPriv), binascii.unhexlify(recipientPub), msg, iv)
    # Result
    return encoded

def _encode(senderPriv:bytes, recipientPub:bytes, msg:bytes, iv:bytes):
    # Processing
    encKey = deriveSharedKey(senderPriv, recipientPub)
    aesgcm = AESGCM(encKey)
    cipher = aesgcm.encrypt(iv, msg, None)
    tag = cipher[-16:]
    # Result
    result = (tag.hex() + iv.hex() + cipher[0:-16].hex()).upper()
    return result

def decode(recipientPrivate:str, senderPublic:str, payload:str):
    # Processing
    binpayload = binascii.unhexlify(payload)
    payloadBuffer = binpayload[16+12:]
    tagAndIv = binpayload[0:16+12]
    try:
        decoded = _decode(binascii.unhexlify(recipientPrivate),binascii.unhexlify(senderPublic), payloadBuffer, tagAndIv)
        return decoded
    except Exception:
        #To return empty string rather than error throwing if authentication failed
        return ''

def _decode(recipientPrivate:bytes, senderPublic:bytes, payload:bytes, tagAndIv:bytes):
    encKey = deriveSharedKey(recipientPrivate, senderPublic)
    encIv = tagAndIv[16:]
    encTag = tagAndIv[0:16]
    aesgcm = AESGCM(encKey)
    res = aesgcm.decrypt(encIv, payload + encTag, None)
    # Result
    return res.decode(encoding='utf8')

def prepareForScalarMult(sk):
    hash =hashlib.sha512()
    hash.update(sk)
    d = bytearray(hash.digest()[0:32] + bytes(32))
    clamp(d)
    return d

def deriveSharedKey(privateKey, publicKey):
    backend = default_backend()
    sharedSecret = deriveSharedSecret(privateKey, publicKey)
    info = bytes(b'catapult')
    algorithm = hashes.SHA256()
    salt = bytes(32)
    length = 32
    hkdf = HKDF(algorithm=algorithm, length=length, salt=salt, info=info,
                backend=backend)
    return hkdf.derive(sharedSecret)

def deriveSharedSecret(privateKey, publicKey):
    d = prepareForScalarMult(privateKey)
    q = [nacl.gf(), nacl.gf(), nacl.gf(), nacl.gf()]
    p = [nacl.gf(), nacl.gf(), nacl.gf(), nacl.gf()]
    sharedSecret = bytearray(32)
    nacl.unpack(q, publicKey)
    nacl.scalarmult(p, q, d)
    nacl.pack(sharedSecret, p)
    return bytes(sharedSecret)

def clamp(d):
    d[0] &= 248
    d[31] &= 127
    d[31] |= 64
