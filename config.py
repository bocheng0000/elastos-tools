import json

API_ENDPOINT = "http://api.elastos.io:21636"

private_key = "69b2a5a82f012e29262d1e8705f193ac376fd8c588c2a38feda6098c30d33f9d"
source_addr = "0x16d39f268A05745aE1B7693cA21FcBD905e702B8"
gas_price = 10

withdraw_contract_abi = json.loads(
    '[{"constant":false,"inputs":[{"name":"_addr","type":"string"},{"name":"_amount","type":"uint256"},{"name":"_fee","type":"uint256"}],"name":"receivePayload","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_addr","type":"string"},{"indexed":false,"name":"_amount","type":"uint256"},{"indexed":false,"name":"_crosschainamount","type":"uint256"},{"indexed":true,"name":"_sender","type":"address"}],"name":"PayloadReceived","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_sender","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"},{"indexed":true,"name":"_black","type":"address"}],"name":"EtherDeposited","type":"event"}]')
withdraw_contract_address_test = "0x491bC043672B9286fA02FA7e0d6A3E5A0384A31A"
withdraw_contract_address_mainnet = "0xC445f9487bF570fF508eA9Ac320b59730e81e503"
withdraw_fee = 100000000000000
withdraw_gas = 3000000
