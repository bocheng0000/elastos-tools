# Copyright 2018 Jimmy Song
# Copyright 2020 Bocheng Zhang
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import requests

from binascii import unhexlify
from hashlib import sha512
from hmac import HMAC

from ecc import PrivateKey, N
from utils import (
    encode_base58_checksum,
    get_bip39_seed_from_mnemonic,
    hash160
)

PBKDF2_ROUNDS = 2048
p2pkh_prefixes = (b'\x00', b'\x6f')
p2sh_prefixes = (b'\x05', b'\xc4')


def get_private_key_from_mnemonic(mnemonic: str, passphrase='', num=10,
                                  account=None, change=None) -> list:
    private_keys = []
    seed = get_bip39_seed_from_mnemonic(mnemonic, passphrase)
    prvs = HDPrivateKey.bip44_private_from_seed(seed=seed, accounts=account,
                                                change=change, num=num)
    for prv in prvs:
        private_keys.append(prv.hex())
    return private_keys


class HDPrivateKey:

    def __init__(self, private_key, chain_code, depth, fingerprint,
                 child_number):
        self.private_key = private_key
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number
        self.testnet = self.private_key.testnet
        self.pub = HDPublicKey(
            point=self.private_key.point,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
            testnet=self.testnet,
        )

    def xprv(self):
        if self.testnet:
            version = unhexlify('04358394')
        else:
            version = unhexlify('0488ADE4')
        depth = bytes([self.depth])
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        prv = bytes([0]) + self.private_key.secret.to_bytes(32, 'big')
        return encode_base58_checksum(
            version + depth + fingerprint + child_number + chain_code + prv)

    def xpub(self):
        return self.pub.xpub()

    @classmethod
    def from_seed(cls, seed, path, testnet=False):
        raw = HMAC(key=b'Bitcoin seed', msg=seed, digestmod=sha512).digest()
        private_key = PrivateKey(
            secret=int.from_bytes(raw[:32], 'big'),
            testnet=testnet,
        )
        chain_code = raw[32:]
        root = cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=0,
            fingerprint=b'\x00\x00\x00\x00',
            child_number=0,
        )
        return root.traverse(path)

    @classmethod
    def bip44_address_from_seed(
            cls, seed, path=b'm/44\'/0\'', num=5):
        coin = cls.from_seed(seed, path)
        prefix = bytes(p2pkh_prefixes[0])
        addrs = []
        for account_num in range(5):
            account = coin.child(account_num, hardened=True)
            for chain in (0, 1):
                cur = account.child(chain)
                for index in range(num):
                    addrs.append(cur.child(index).address(prefix=prefix))
        return addrs

    @classmethod
    def bip44_private_from_seed(cls, seed, path=b'm/44\'/0\'', accounts=None,
                                change=None, num=20):
        if accounts is None:
            accounts = [0]
        if change is None:
            change = [0]
        coin = cls.from_seed(seed, path)
        private_keys = []
        for account_num in accounts:
            account = coin.child(account_num, hardened=True)
            for chain in change:
                cur = account.child(chain)
                for index in range(num):
                    private_keys.append(cur.child(index).private_key)
        return private_keys

    def get_private_keys(self, utxos):
        return [self.traverse(p).private_key for p in utxos]

    def get_active_paths(self, account_gap=1, gap_limit=20, segwit=False):
        account_num = 0
        paths = []
        empty_account_count = 0
        while empty_account_count <= account_gap:
            account = self.child(account_num, hardened=True)
            account_path = "{}'/".format(account_num).encode('ascii')
            sub_paths = account.pub.get_all_active_in_account(
                gap_limit, segwit)
            if len(sub_paths) == 0:
                empty_account_count += 1
            else:
                paths.extend([(account_path + path, addr)
                              for path, addr in sub_paths])
            account_num += 1
        return paths

    def traverse(self, path):
        current = self
        if path.startswith(b'm'):
            components = path.split(b'/')[1:]
        else:
            components = path.split(b'/')
        for child in components:
            if child.endswith(b"'"):
                hardened = True
                index = int(child[:-1].decode('ascii'))
            else:
                hardened = False
                index = int(child.decode('ascii'))
            current = current.child(index, hardened)
        return current

    def child(self, index, hardened=False):
        if index >= 0x80000000:
            raise ValueError('child number should always be less than 2^31')
        sec = self.private_key.point.sec()
        fingerprint = hash160(sec)[:4]
        if hardened:
            index += 0x80000000
            pk = self.private_key.secret.to_bytes(32, 'big')
            data = b'\x00' + pk + index.to_bytes(4, 'big')
            raw = HMAC(
                key=self.chain_code, msg=data, digestmod=sha512).digest()
        else:
            data = sec + index.to_bytes(4, 'big')
            raw = HMAC(
                key=self.chain_code, msg=data, digestmod=sha512).digest()
        secret = (int.from_bytes(raw[:32], 'big')
                  + self.private_key.secret) % N
        private_key = PrivateKey(
            secret=secret,
            compressed=True,
            testnet=self.testnet,
        )
        chain_code = raw[32:]
        depth = self.depth + 1
        child_number = index
        return HDPrivateKey(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )

    def wif(self, prefix=None):
        return self.private_key.wif(prefix=prefix)

    def address(self, prefix=None):
        return self.pub.address(prefix=prefix)

    def segwit_address(self, prefix=None):
        return self.pub.segwit_address(prefix=prefix)

    def h160(self):
        return self.pub.point.h160()


class HDPublicKey:

    def __init__(self, point, chain_code, depth, fingerprint,
                 child_number, testnet=False):
        self.point = point
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number
        self.testnet = testnet

    def xpub(self):
        if self.testnet:
            version = unhexlify('043587CF')
        else:
            version = unhexlify('0488B21E')
        depth = bytes([self.depth])
        fingerprint = self.fingerprint
        child_number = self.child_number.to_bytes(4, 'big')
        chain_code = self.chain_code
        sec = self.point.sec()
        return encode_base58_checksum(
            version + depth + fingerprint + child_number +
            chain_code + sec)

    def traverse(self, path):
        current = self
        for child in path.split(b'/')[1:]:
            current = current.child(int(child))
        return current

    def child(self, index):
        if index >= 0x80000000:
            raise ValueError('child number should always be less than 2^31')
        sec = self.point.sec()
        data = sec + index.to_bytes(4, 'big')
        raw = HMAC(key=self.chain_code, msg=data, digestmod=sha512).digest()
        point = PrivateKey(int.from_bytes(raw[:32], 'big')).point + self.point
        chain_code = raw[32:]
        depth = self.depth + 1
        fingerprint = hash160(sec)[:4]
        child_number = index
        return HDPublicKey(
            point=point,
            chain_code=chain_code,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_number,
        )

    def address(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\x6f'
            else:
                prefix = b'\x00'
        return self.point.address(prefix=prefix)

    def segwit_address(self, prefix=None):
        if prefix is None:
            if self.testnet:
                prefix = b'\xc4'
            else:
                prefix = b'\x05'
        return self.point.segwit_address(prefix=prefix)

    def get_all_active_in_account(self, gap_limit=20, segwit=False):
        '''Returns the paths of the addresses that have activity'''
        paths = []
        for sub_account_num in (0, 1):
            sub_account = self.child(sub_account_num)
            indices = sub_account.get_active_child_indices(gap_limit, segwit)
            paths.extend([
                ('{}/{}'.format(sub_account_num, i[0]).encode('ascii'), i[1])
                for i in indices])
        return paths

    def get_active_child_indices(self, gap_limit=20, segwit=False):
        """Return the child indices that have activity"""
        search = True
        batch = 0
        indices = []
        while search:
            batch_range = range(batch * gap_limit, (batch + 1) * gap_limit)
            addr_lookup = {}
            addrs = []
            for i in batch_range:
                if segwit:
                    addr = self.child(i).segwit_address()
                else:
                    addr = self.child(i).address()
                addr_lookup[addr] = i
                addrs.append(addr)
            data = requests.get(
                'http://blockchain.info/multiaddr?active={}'.format(
                    '|'.join(addrs))).json()
            current_received = 0
            for item in data['addresses']:
                received = item['total_received']
                if received != 0:
                    addr = item['address']
                    indices.append((addr_lookup[addr], addr))
                    current_received += received
            batch += 1
            search = current_received != 0
        return indices
