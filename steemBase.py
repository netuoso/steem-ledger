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

import time
import hashlib
from calendar import timegm
from asn1 import Encoder, Numbers
import struct
from binascii import hexlify, unhexlify
from base58 import b58decode 
from operation_ids import operations

class Transaction:
    def __init__(self):
        pass

    @staticmethod
    def char_to_symbol(c):
        if c >= 'a' and c <= 'z':
            return ord(c) - ord('a') + 6
        if c >= '1' and c <= '5':
            return ord(c) - ord('1') + 1
        return 0

    @staticmethod
    def name_to_number(name):
        length = len(name)
        value = 0

        for i in range(0, 13):
            c = 0
            if i < length and i < 13:
                c = Transaction.char_to_symbol(name[i])

            if i < 12:
                c &= 0x1f
                c <<= 64 - 5 * (i + 1)
            else:
                c &= 0x0f

            value |= c

        return struct.pack('Q', value)

    @staticmethod
    def symbol_from_string(p, name):
        length = len(name)
        result = 0
        for i in range(0, length):
            result |= ord(name[i]) << (8 *(i+1))

        result |= p
        return result

    @staticmethod
    def symbol_precision(sym):
        return pow(10, (sym & 0xff))

    @staticmethod
    def asset_to_number(asset):
        amount_str, symbol_str = asset.split(' ')
        dot_pos = amount_str.find('.')

        # parse symbol
        if dot_pos != -1:
            precision_digit = len(amount_str) - dot_pos - 1
        else:
            precision_digit = 0

        sym = Transaction.symbol_from_string(precision_digit, symbol_str)

        # parse amount
        if dot_pos != -1:
            int_part = int(amount_str[:dot_pos])
            fract_part = int(amount_str[dot_pos+1:])
            if int_part < 0:
                fract_part *= -1
        else:
            int_part = int(amount_str)

        amount = int_part
        amount *= Transaction.symbol_precision(sym)
        amount += fract_part

        data = struct.pack('Q', amount)
        data += struct.pack('Q', sym)
        return data

    @staticmethod
    def parse_vote(data):
        parameters = Transaction.pack_fc_uint(len(data["voter"])) + bytes(data["voter"])
        parameters += Transaction.pack_fc_uint(len(data["author"])) + bytes(data["author"])
        parameters += Transaction.pack_fc_uint(len(data["permlink"])) + bytes(data["permlink"])
        parameters += struct.pack("<h", int(data["weight"]))

        return parameters

    @staticmethod
    def parse_transfer(data):
        parameters = Transaction.name_to_number(data['from'])
        parameters += Transaction.name_to_number(data['to'])
        parameters += Transaction.asset_to_number(data['amount'])
        memo = data['memo']
        parameters += Transaction.pack_fc_uint(len(memo))
        if len(memo) > 0:
            parameters += struct.pack(str(len(memo)) + 's', str(data['memo']))

        return parameters

    @staticmethod
    def pack_fc_uint(value):
        out = ''
        i = 0
        val = value
        while True:
            b = val & 0x7f
            val >>= 7
            b |= ((val > 0) << 7)
            i += 1
            out += chr(b)

            if val == 0:
                break

        return out

    @staticmethod
    def unpack_fc_uint(buffer):
        i = 0
        v = 0
        b = 0
        by = 0

        k = 0
        while True:
            b = ord(buffer[k])
            k += 1
            i += 1
            v |= (b & 0x7f) << by
            by += 7

            if (b & 0x80) == 0 or by >= 32:
                break

        return v

    @staticmethod
    def parse_vote_producer(data):
        parameters = Transaction.name_to_number(data['account'])
        parameters += Transaction.name_to_number(data['proxy'])
        length = len(data['producers'])
        parameters += struct.pack('B', length)
        for producer in data['producers']:
            parameters += Transaction.name_to_number(producer)

        return parameters

    @staticmethod
    def parse_buy_ram(data):
        parameters = Transaction.name_to_number(data['buyer'])
        parameters += Transaction.name_to_number(data['receiver'])
        parameters += Transaction.asset_to_number(data['tokens'])
        return parameters

    @staticmethod
    def parse_buy_rambytes(data):
        parameters = Transaction.name_to_number(data['buyer'])
        parameters += Transaction.name_to_number(data['receiver'])
        parameters += struct.pack('I', data['bytes'])
        return parameters

    @staticmethod
    def parse_sell_ram(data):
        parameters = Transaction.name_to_number(data['receiver'])
        parameters += struct.pack('Q', data['bytes'])
        return parameters

    @staticmethod
    def parse_public_key(data):
        data = str(data[3:])
        decoded = b58decode(data)
        decoded = decoded[:-4]
        parameters = struct.pack('B', 0)
        parameters += decoded
        return parameters

    @staticmethod
    def parse_auth(data):
        parameters = struct.pack('I', data['threshold'])
        key_number = len(data['keys'])
        parameters += struct.pack('B', key_number)
        for key in data['keys']:
            parameters += Transaction.parse_public_key(key['key'])
            parameters += struct.pack('H', key['weight'])
        parameters += struct.pack('B', len(data['accounts']))
        for account in data['accounts']:
            parameters += Transaction.name_to_number(account['authorization']['actor'])
            parameters += Transaction.name_to_number(account['authorization']['permission'])
            parameters += struct.pack('H', account['weight'])
        parameters += struct.pack('B', len(data['waits']))
        for wait in data['waits']:
            parameters += struct.pack('I', wait['wait'])
            parameters += struct.pack('H', wait['weight'])
        return parameters
    
    @staticmethod
    def parse_update_auth(data):
        parameters = Transaction.name_to_number(data['account'])
        parameters += Transaction.name_to_number(data['permission'])
        parameters += Transaction.name_to_number(data['parent'])
        parameters += Transaction.parse_auth(data['auth'])
        return parameters

    @staticmethod
    def parse_delete_auth(data):
        parameters = Transaction.name_to_number(data['account'])
        parameters += Transaction.name_to_number(data['permission'])
        return parameters

    @staticmethod
    def parse_refund(data):
        return Transaction.name_to_number(data['account'])

    @staticmethod
    def parse_link_auth(data):
        parameters = Transaction.name_to_number(data['account'])
        parameters += Transaction.name_to_number(data['contract'])
        parameters += Transaction.name_to_number(data['action'])
        parameters += Transaction.name_to_number(data['permission'])
        return parameters

    @staticmethod
    def parse_unlink_auth(data):
        parameters = Transaction.name_to_number(data['account'])
        parameters += Transaction.name_to_number(data['contract'])
        parameters += Transaction.name_to_number(data['action'])
        return parameters

    @staticmethod
    def parse_unknown(data):
        data = data * 1000
        parameters = struct.pack(str(len(data)) + 's', str(data))
        return parameters

    @staticmethod
    def parse(json):
        tx = Transaction()
        tx.json = json

        tx.chain_id = unhexlify("00" * 32)

        tx.ref_block_num = struct.pack('<H', json['ref_block_num'])
        tx.expiration = struct.pack("<I", timegm(time.strptime((json["expiration"] + "UTC"), '%Y-%m-%dT%H:%M:%S%Z')))
        tx.ref_block_prefix = struct.pack('<I', json['ref_block_prefix'])

        # prefex operations with length
        tx.op_data = Transaction.pack_fc_uint(len(json['operations']))
        for op in json['operations']:
            tx.op_data += Transaction.pack_fc_uint(operations[op[0]])
            if op[0] == 'transfer':
                tx.op_data += Transaction.parse_transfer(op[1])
            elif op[0] == 'vote':
                tx.op_data += Transaction.parse_vote(op[1])
            else:
                tx.op_data += Transaction.parse_unknown(op[1])

        # prefix extensions with length
        tx.ex_data = Transaction.pack_fc_uint(len(json['extensions']))
        for ext in json['extensions']:
            print ext
            # TODO: Implement
            # tx.ex_data += ext

        sha = hashlib.sha256()
        sha.update(tx.op_data)
        print 'Argument checksum ' +  sha.hexdigest()

        return tx

    def encode(self):
        encoder = Encoder()
        encoder.start()
        encoder.write(self.chain_id)
        encoder.write(self.ref_block_num, Numbers.OctetString)
        encoder.write(self.ref_block_prefix, Numbers.OctetString)
        encoder.write(self.expiration, Numbers.OctetString)
        encoder.write(self.op_data, Numbers.OctetString)
        encoder.write(self.ex_data, Numbers.OctetString)

        return encoder.output()
