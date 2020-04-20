#!/usr/bin/env python
# encoding: utf-8

"""
@author: Bocheng.Zhang
@license: MIT
@contact: bocheng0000@gmail.com
@file: main
@time: 2020/3/16 17:58
"""
from lib import util, keys, hd

if __name__ == '__main__':
    print('Example-1: get DID from jwt-token')
    jwt_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZWxhc3RvczppWXBRTXdoZUR4eVNxaXZvY1NKYW9wcmNvRFRxUXNEWUF1IiwiY2FsbGJhY2t1cmwiOiJodHRwczovL3N0YWdpbmctYXBpLmN5YmVycmVwdWJsaWMub3JnL2FwaS91c2VyL2xvZ2luLWNhbGxiYWNrLWVsYSIsIm5vbmNlIjoiOWVkMzFlNzQtOTU5Mi00ZjFmLWE4MDctODkxZjI4NTg1NjYxIiwiY2xhaW1zIjp7fSwid2Vic2l0ZSI6eyJkb21haW4iOiJodHRwczovL3N0YWdpbmcuY3liZXJyZXB1YmxpYy5vcmciLCJsb2dvIjoiaHR0cHM6Ly9zdGFnaW5nLmN5YmVycmVwdWJsaWMub3JnL2Fzc2V0cy9pbWFnZXMvbG9nby5zdmcifSwiaWF0IjoxNTg0Nzk5NzU0LCJleHAiOjE1ODU0MDQ1NTR9.2W5CSuDgm60eJYvSi_ekujfAb84OIvau7OKCvXM6ZRPWAmrk3f4AaFULr2Syxtd9GH9P_4-_QyJXo-TAADLAUw'
    did = util.get_did_from_jwt(jwt_token)
    print(f'DID:\n{did}')

    print('\nExample-2: get public key from DID')
    public_key_str = util.get_publickey_from_did(did=did, net='regtest')
    print(f'Compressed Public Key:\n{public_key_str}')

    # Import Public Key from compressesed public key string
    pubKey = keys.PublicKey.from_string(public_key_str)
    # Export PEM Format
    public_key_pem = pubKey.to_pem()
    # Export uncompressed public key string
    public_key_str_uncompressed = pubKey.to_string(compressed=False)
    print(f'Pem:\n{public_key_pem}')
    print(f'Uncompressed PublicKey:\n{public_key_str_uncompressed}')
    print(f"Public Key'x:[{hex(pubKey.verifying_key.pubkey.point.x())}]")
    print(f"Public Key'y:[{hex(pubKey.verifying_key.pubkey.point.y())}]")

    # Verify JWT-Token
    jwt_decode = util.JWT.decode(jwt_token=jwt_token, key=public_key_pem,
                                 verify=True)
    print(f'JWT-Payload:\n{jwt_decode}')

    print(
        f'\nExample-3: get DID, address, private key, public key from mnemonic word')
    mnemonic_word = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    passphrase = ''
    private_keys = hd.get_private_key_from_mnemonic(mnemonic=mnemonic_word,
                                                    change=[0, 1], num=20)
    title = f'{"Index":6}{"DID":36}{"Private Key":66}{"Public Key":68}{"Address":36}{"Script":42}'
    print(title)
    print('=' * len(title))
    for i in range(len(private_keys)):
        _prv = private_keys[i]
        _p = keys.PrivateKey.from_string(_prv)
        _pub = _p.verifying_key.to_string()
        _did = _p.get_did()
        _address = _p.get_address()
        _script = _p.verifying_key.script().hex()
        print(f'{i:5} {_did:36}{_prv:66}{_pub:68}{_address:36}{_script}')
