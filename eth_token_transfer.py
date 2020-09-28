#!/usr/bin/env python
# encoding: utf-8

"""
@author: Bocheng.Zhang
@license: MIT
@contact: bocheng0000@gmail.com
@file: eth_token_transfer
@time: 2020/9/28 06:04
"""

from decimal import Decimal
from ethtoken.abi import EIP20_ABI
import sys
from web3 import Web3, HTTPProvider, exceptions

import config as c
from lib.util import CsvReader


class TokenTransfer(object):
    def __init__(self, api_endpoint, contract_address, private_key,
                 source_addr):
        self.web3 = Web3(HTTPProvider(api_endpoint))
        self.token = self.web3.eth.contract(address=contract_address,
                                            abi=EIP20_ABI)
        self.token_symbol = self.token.functions.symbol().call()
        self.private_key = private_key
        self.source_addr = self.web3.toChecksumAddress(source_addr)
        self.nonce = -1

    def transfer(self, address, amount, gas_price):
        """
        Function to transfer amount to the given address
        :param address:
        :param amount:
        :param gas_price:
        :return:
        """

        address = self.web3.toChecksumAddress(address)
        print(f"Transfer {amount} '{self.token_symbol}' "
              f"from {self.source_addr} to {address}")
        try:
            # validate address
            Web3.isAddress(address)
        except exceptions.InvalidAddress as e:
            print(e)
            return

        # Get Nonce
        nonce = self.web3.eth.getTransactionCount(self.source_addr, "pending")
        print("Current Nonce:{}".format(nonce))
        # Update Nonce if needed
        if self.nonce < nonce:
            self.nonce = nonce
        else:
            # Probably in batch mode, need to auto add nonce.
            self.nonce += 1
        print("Fixed Nonce:{}".format(self.nonce))

        # Get Decimals
        dec = self.token.functions.decimals().call()
        print(f"Token's Decimal is {dec}")
        # Get Balance
        balance = self.token.functions.balanceOf(self.source_addr).call()
        print(f"balance is: {balance / pow(10, dec)}")
        tx_value = int(Decimal(amount) * pow(10, dec))
        print(f"Transfer Amount is {tx_value}")

        if tx_value < balance:
            print("Enough Balance")

            data = self.token.encodeABI(fn_name="transfer",
                                        args=[address, tx_value])
            print(f"Data is {data}")
            tx = {
                "from": self.source_addr,
                "to": self.token.address,
                "value": 0,
                "data": data,
                "gas": c.gas,
                "gasPrice": Web3.toWei(gas_price, "gwei"),
                "nonce": nonce
            }

            signed_txn_body = self.web3.eth.account.signTransaction(tx,
                                                                    private_key=self.private_key)
            print(f"RawTransaction: {signed_txn_body.rawTransaction.hex()}")
            txid = self.web3.eth.sendRawTransaction(
                signed_txn_body.rawTransaction)
            print(f"Txid: {txid.hex()}")

        else:
            print('Balance is not enough！')
            raise Exception("Not Enough Balance for transfer!")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: ")
        print("python3 main.py [CSV_FILE_PATH]")
        print("Example: ")
        print("python3 main.py test.csv")
        exit(0)

    else:
        print("Start sending TXs.")
        batch_list = CsvReader(sys.argv[1], 2).parse()
        handler = TokenTransfer(api_endpoint=c.API_ENDPOINT,
                                contract_address=c.token_contract_address_mainnet,
                                private_key=c.private_key,
                                source_addr=c.source_addr
                                )

        for add in batch_list:
            _target_add = add[0]
            _amount = add[1]
            handler.transfer(_target_add, _amount, c.gas_price)
        print("All TX Sent.")
