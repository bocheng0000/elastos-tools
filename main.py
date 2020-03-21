#!/usr/bin/env python
# encoding: utf-8

"""
@author: Bocheng.Zhang
@license: MIT
@contact: bocheng0000@gmail.com
@file: main
@time: 2020/3/16 17:58
"""

import keys
from utils import *

if __name__ == '__main__':
    # Function-1: get DID from jwt-token
    jwt_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZWxhc3RvczppWXBRTXdoZUR4eVNxaXZvY1NKYW9wcmNvRFRxUXNEWUF1IiwiY2FsbGJhY2t1cmwiOiJodHRwczovL3N0YWdpbmctYXBpLmN5YmVycmVwdWJsaWMub3JnL2FwaS91c2VyL2xvZ2luLWNhbGxiYWNrLWVsYSIsIm5vbmNlIjoiOWVkMzFlNzQtOTU5Mi00ZjFmLWE4MDctODkxZjI4NTg1NjYxIiwiY2xhaW1zIjp7fSwid2Vic2l0ZSI6eyJkb21haW4iOiJodHRwczovL3N0YWdpbmcuY3liZXJyZXB1YmxpYy5vcmciLCJsb2dvIjoiaHR0cHM6Ly9zdGFnaW5nLmN5YmVycmVwdWJsaWMub3JnL2Fzc2V0cy9pbWFnZXMvbG9nby5zdmcifSwiaWF0IjoxNTg0Nzk5NzU0LCJleHAiOjE1ODU0MDQ1NTR9.2W5CSuDgm60eJYvSi_ekujfAb84OIvau7OKCvXM6ZRPWAmrk3f4AaFULr2Syxtd9GH9P_4-_QyJXo-TAADLAUw'
    did = get_did_from_jwt(jwt_token)
    print(f'DID:\n{did}')

    # Function-2: get public key from DID
    public_key_str = get_publickey_from_did(did=did, net='regtest')
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
    jwt_decode = JWT.decode(jwt_token=jwt_token, key=public_key_pem,
                            verify=True)
    print(f'JWT-Payload:\n{jwt_decode}')
