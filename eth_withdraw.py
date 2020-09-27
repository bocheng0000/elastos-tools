#!/usr/bin/env python
# encoding: utf-8

"""
@author: Bocheng.Zhang
@license: MIT
@contact: bocheng0000@gmail.com
@file: eth_withdraw
@time: 2020/9/27 12:30
"""

import sys
from web3 import Web3, HTTPProvider, exceptions

import config as c
from lib.util import CsvReader


class WithdrawELA(object):
    def __init__(self, api_endpoint, contract_address, abi):
        self.web3 = Web3(HTTPProvider(api_endpoint))
        self.contract = self.web3.eth.contract(address=contract_address,
                                               abi=abi)

    def transfer(self, private_key, source_addr, target_addr, amount,
                 gas_price):
        """
        Function to transfer amount to the given address
        :param private_key:
        :param source_addr:
        :param target_addr:
        :param amount:
        :param gas_price:
        :return:
        """
        try:
            # validate address
            Web3.isAddress(source_addr)
        except exceptions.InvalidAddress as e:
            print(e)
            return
        source_addr = self.web3.toChecksumAddress(source_addr)
        print(f"Withdraw {amount} ELA from {source_addr} to {target_addr} ")
        tx_value = Web3.toWei(amount, 'ether')

        data = self.contract.encodeABI(fn_name="receivePayload",
                                       args=[target_addr, tx_value,
                                             c.withdraw_fee])

        # Get Nonce
        nonce = self.web3.eth.getTransactionCount(source_addr, "pending")
        print("Current Nonce:{}".format(nonce))
        tx = {
            "from": source_addr,
            "to": self.contract.address,
            "value": tx_value,
            "data": data,
            "gas": c.withdraw_gas,
            "gasPrice": Web3.toWei(gas_price, "gwei"),
            "nonce": nonce
        }

        signed_txn_body = self.web3.eth.account.signTransaction(tx,
                                                                private_key=private_key)
        print(f"RawTransaction: {signed_txn_body.rawTransaction.hex()}")
        txid = self.web3.eth.sendRawTransaction(signed_txn_body.rawTransaction)
        print(f"Txid: {txid.hex()}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ")
        print("python3 main.py [CSV_FILE_PATH]")
        print("Example: ")
        print("python3 main.py test.csv")
        exit(0)

    else:
        print("Start sending TXs.")
        batch_list = CsvReader(sys.argv[1]).parse()
        handler = WithdrawELA(api_endpoint=c.API_ENDPOINT,
                              contract_address=c.withdraw_contract_address_test,
                              abi=c.withdraw_contract_abi)
        for add in batch_list:
            _private_key = add[0]
            _source_add = add[1]
            _target_add = add[2]
            _amount = add[3]

            handler.transfer(_private_key, _source_add, _target_add, _amount,
                             c.gas_price)
        print("All TX Sent.")
