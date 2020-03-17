#!/usr/bin/env python
# encoding: utf-8

"""
@author: Bocheng.Zhang
@license: MIT
@contact: bocheng0000@gmail.com
@file: request.py
@time: 2020/2/14 19:15
"""

import requests
from retrying import retry

resolver = {
    "mainnet": "http://api.elastos.io:20606",
    "testnet": "http://api.elastos.io:21606",
    "regtest": "http://api.elastos.io:22606"
}


def post_request(url: str, method, params={}, user="", password=""):
    try:
        resp = requests.post(url, json={"method": method, "params": params},
                             headers={"content-type": "application/json"},
                             auth=requests.auth.HTTPBasicAuth(user, password))
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"Warning[RPC]:[{resp.status_code}]")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Warning[RPC]:[{e.__str__()}]")
        return None


@retry(stop_max_attempt_number=5)
def resolve_did(did, net="mainnet", all=False, user="", password=""):
    url = resolver[net]
    resp = post_request(url, "resolvedid", params={"did": did, "all": all},
                        user=user, password=password)
    if resp is not None:
        return resp["result"]
    else:
        return resp
