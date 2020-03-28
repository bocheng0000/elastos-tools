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

from ecdsa import SigningKey as EcdsaSigningKey, \
    VerifyingKey as EcdsaVerifyingKey, curves

from utils import hash160, encode_base58_checksum

Prefix = {
    'ela': b'\x21',
    'did': b'\x67',
    'btc': b'\x00'
}


class PublicKey(object):

    def __init__(self, key: EcdsaVerifyingKey, curve: str):
        self.verifying_key = key
        self.curve = curve

    @staticmethod
    def from_string(key_str: str, curve='r1'):
        assert len(key_str) == 66
        if curve == 'r1':
            _verifyKey = EcdsaVerifyingKey.from_string(bytes.fromhex(key_str),
                                                       curve=curves.NIST256p)
        else:
            _verifyKey = EcdsaVerifyingKey.from_string(bytes.fromhex(key_str),
                                                       curve=curves.SECP256k1)
        return PublicKey(_verifyKey, curve)

    @staticmethod
    def from_pem(pem: str):
        _verifyKey = EcdsaVerifyingKey.from_pem(string=pem)
        if _verifyKey.curve == curves.NIST256p:
            curve = 'r1'
        else:
            curve = 'k1'
        return PublicKey(_verifyKey, curve)

    def to_bytes(self, compressed=True):
        if compressed:
            return self.verifying_key.to_string(encoding='compressed')
        else:
            return self.verifying_key.to_string(encoding='uncompressed')

    def to_string(self, compressed=True):
        return self.to_bytes(compressed).hex()

    def to_pem(self):
        return self.verifying_key.to_pem().decode('ascii')

    def h160(self, coin='ela'):
        _pubkey = self.to_bytes()
        _redeemscript = _pubkey
        if coin == 'ela':
            _redeemscript = bytes([len(_pubkey)]) + _pubkey + bytes.fromhex(
                'ac')
        elif coin == 'did':
            _redeemscript = bytes([len(_pubkey)]) + _pubkey + bytes.fromhex(
                'ad')
        return hash160(_redeemscript)

    def address(self, coin='ela'):
        '''Returns the address string'''
        prefix = Prefix[coin]
        h160 = self.h160(coin)
        return encode_base58_checksum(prefix + h160)

    def did(self, coin='did'):
        '''Returns the did string'''
        prefix = Prefix[coin]
        h160 = self.h160(coin)
        return encode_base58_checksum(prefix + h160)


class PrivateKey(object):

    def __init__(self, key: EcdsaSigningKey, curve='r1'):
        self.signing_key = key
        self.curve = curve
        self.verifying_key = self.get_verifying_key()

    @staticmethod
    def from_string(key_str: str, curve='r1'):
        assert len(key_str) == 64
        if curve == 'r1':
            _signing_key = EcdsaSigningKey.from_string(bytes.fromhex(key_str),
                                                       curve=curves.NIST256p)
        else:
            _signing_key = EcdsaSigningKey.from_string(bytes.fromhex(key_str),
                                                       curve=curves.SECP256k1)
        return PrivateKey(_signing_key, curve)

    @staticmethod
    def from_pem(pem: str):
        _key = EcdsaSigningKey.from_pem(string=pem)
        if _key.curve == curves.NIST256p:
            curve = 'r1'
        else:
            curve = 'k1'
        return PrivateKey(_key, curve)

    def get_verifying_key(self):
        return PublicKey(self.signing_key.get_verifying_key(), self.curve)

    def get_address(self):
        return self.verifying_key.address()

    def get_did(self):
        return self.verifying_key.did()

    def to_bytes(self):
        return self.signing_key.to_string()

    def to_string(self):
        return self.to_bytes().hex()

    def to_pem(self):
        return self.signing_key.to_pem().decode('ascii')
