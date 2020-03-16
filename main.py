#!/usr/bin/env python
# encoding: utf-8

"""
@author: Bocheng.Zhang
@license: MIT
@contact: bocheng0000@gmail.com
@file: main
@time: 2020/3/16 17:58
"""

from utils import *

if __name__ == '__main__':
    jwt_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6ZWxhc3RvczppWXBRTXdoZUR4eVNxaXZvY1NKYW9wcmNvRFRxUXNEWUF1IiwiY2FsbGJhY2t1cmwiOiJodHRwczovL3N0YWdpbmctYXBpLmN5YmVycmVwdWJsaWMub3JnL2FwaS91c2VyL2xvZ2luLWNhbGxiYWNrLWVsYSIsIm5vbmNlIjoiYWU1MGZlMWQtM2FjNC00ZmY2LTliYzctNGU3NDk1MTMzNDA3IiwiY2xhaW1zIjp7fSwid2Vic2l0ZSI6eyJkb21haW4iOiJodHRwczovL3N0YWdpbmcuY3liZXJyZXB1YmxpYy5vcmciLCJsb2dvIjoiaHR0cHM6Ly9zdGFnaW5nLmN5YmVycmVwdWJsaWMub3JnL2Fzc2V0cy9pbWFnZXMvbG9nby5zdmcifSwiaWF0IjoxNTg0MDY5ODkyLCJleHAiOjE1ODQ2NzQ2OTJ9.id_XvCs3swrHHaYgPN7mDoe52EDHE0wvGPqdZseRJrzQ4nDfDWKZoNv5BvFknZ_fG0lwttVue6Yiv_jWaOaDFA'
    did = get_did_from_jwt(jwt_token)
    print(f'DID:\n{did}')
    public_key = get_publickey_from_did(did=did, net='regtest')
    print(f'Public Key:\n{public_key}')
