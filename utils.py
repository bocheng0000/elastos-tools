# Copyright (c) 2020, Bocheng Zhang
# Copyright (c) 2018 Jimmy Song
# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import base58
import base64
import hashlib
import json
import jwt
from mnemonic import Mnemonic

import request


def get_bip39_seed_from_mnemonic(mnemonic: str, passphrase='') -> bytes:
    seed = Mnemonic.to_seed(mnemonic=mnemonic, passphrase=passphrase)
    return seed


def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def SHA256D(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()


def encode_base58_checksum(s, hash_fn=SHA256D):
    """Encodes a payload bytearray (which includes the version byte(s))
    into a Base58Check string."""
    return base58.b58encode(s + hash_fn(s)[:4]).decode('ascii')


def decode_check(txt, hash_fn=SHA256D):
    '''Decodes a Base58Check-encoded string to a payload.  The version
    prefixes it.'''
    be_bytes = base58.b58decode(txt)
    result, check = be_bytes[:-4], be_bytes[-4:]
    if check != hash_fn(result)[:4]:
        raise Exception('invalid base 58 checksum for {}'.format(txt))
    return result


def base64url_decode(content):
    if isinstance(content, str):
        content = content.encode('ascii')

    rem = len(content) % 4
    if rem > 0:
        content += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(content)


def base64url_encode(content):
    return base64.urlsafe_b64encode(content).replace(b'=', b'')


def get_did_document(did: str, net: str):
    _result = request.resolve_did(did=did, net=net)
    _did = _result["did"].replace("did:", "").replace("elastos:", "")
    _status = _result["status"]
    _tx = _result["transaction"]
    # TODO: check _status
    assert did == _did
    assert len(_tx) == 1
    _payload = _tx[0]["operation"]["payload"]
    return json.loads(base64url_decode(_payload))


def get_publickey_from_did(did: str, net="mainnet") -> str:
    if len(did) != 34:
        did = did.replace("did:", "").replace("elastos:", "")
    assert len(did) == 34
    _document = get_did_document(did, net)
    _pubKeys = _document["publicKey"]
    _pubKey = ""
    for _key in _pubKeys:
        if _key["id"] == "#primary":
            _pubKey = base58.b58decode(_key["publicKeyBase58"]).hex()
    return _pubKey


# decode jwt and verify the signature
class JWT:
    @staticmethod
    def encode(payload: dict, key: str, algorithm='ES256'):
        return jwt.encode(payload=payload, key=key, algorithm=algorithm)

    @staticmethod
    def decode(jwt_token: str, key='', verify=True, algorithms=None,
               audience=None):
        try:
            payload = jwt.decode(jwt=jwt_token, key=key, algorithms=algorithms,
                                 verify=verify, audience=audience)
            return payload
        except jwt.ExpiredSignatureError as e:
            print(f'Error:[{e}]')

    @staticmethod
    def get_header(jwt_token: str):
        return jwt.get_unverified_header(jwt_token)


def get_did_from_jwt(jwt_token):
    _payload = JWT.decode(jwt_token, verify=False)
    return _payload['iss']
