#!/usr/bin/env python
"""
/*******************************************************************************
*   Taras Shchybovyk
*   (c) 2018 Taras Shchybovyk
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
"""

import os
import json
import struct
import argparse

from binascii import hexlify, unhexlify
from ledgerblue.comm import getDongle

from steemBase import Transaction

from beem import Steem
from beembase.signedtransactions import Signed_Transaction
from beemgraphenebase.base58 import Base58
from beem.account import PrivateKey

def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    result = ""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to retrieve")
parser.add_argument('--file', help="Transaction in JSON format")
args = parser.parse_args()

if args.path is None:
    args.path = "44'/135'/0'/0/0"

if args.file is None:
    args.file = 'steem_transaction_vote.json'
    # args.file = 'steem_transaction_transfer.json'

donglePath = parse_bip32_path(args.path)
pathSize = len(donglePath) / 4

with file(args.file) as f:
    obj = json.load(f)

    tx = Transaction.parse(obj)
    tx_raw = tx.encode()
    signData = tx_raw
    # print hexlify(tx_raw)

    dongle = getDongle(True)
    offset = 0
    first = True
    signSize = len(signData)
    while offset != signSize:
        if signSize - offset > 200:
            chunk = signData[offset: offset + 200]
        else:
            chunk = signData[offset:]

        if first:
            totalSize = len(donglePath) + 1 + len(chunk)
            apdu = "87040000".decode('hex') + chr(totalSize) + chr(pathSize) + donglePath + chunk
            first = False
        else:
            totalSize = len(chunk)
            apdu = "87048000".decode('hex') + chr(totalSize) + chunk

        offset += len(chunk)
        # result = dongle.exchange(bytes(apdu))
        print hexlify(apdu)

# tx = {
#   "ref_block_num": 23196,
#   "ref_block_prefix": 114668414,
#   "expiration": "2018-12-18T05:11:12",
#   "operations": [[
#       "vote",{
#         "voter": "nettybot",
#         "author": "the4thmusketeer",
#         "permlink": "influencers-in-crypto",
#         "weight": 10000
#       }
#     ]
#   ],
#   "extensions": [],
#   "signatures": [hexlify(result)]
# }


# print(hexlify(result))

#stm = Steem(nodes=["https://api.steemit.com"])
# command = "curl -s --data '{\"id\":10,\"jsonrpc\":\"2.0\",\"method\":\"call\",\"params\":[\"network_broadcast_api\",\"broadcast_transaction_synchronous\",[{\"ref_block_num\": 23196,\"ref_block_prefix\": 114668414,\"expiration\": \"2018-12-18T05:11:12\",\"operations\": [[\"vote\",{\"voter\": \"nettybot\",\"author\": \"the4thmusketeer\",\"permlink\": \"influencers-in-crypto\",\"weight\": 10000    }  ]],\"extensions\": [],\"signatures\": [\"2058c8ddec40c0e203ecf84097d75ffe10be0afa7fa492aa2b25754ef3a685ec132443e3db48d7c751b4cf48e84f523ac6a0c84b2151e16996975bc255d712b1e1\"]}]]}' https://api.steemit.com"
#print(os.system(command))

