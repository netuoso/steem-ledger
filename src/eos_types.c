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

#include "eos_types.h"
#include "eos_utils.h"
#include "os.h"
#include <stdbool.h>
#include "string.h"

static const char* charmap = ".12345abcdefghijklmnopqrstuvwxyz";

name_t buffer_to_name_type(uint8_t *in, uint32_t size) {
    if (size < 8) {
        THROW(EXCEPTION_OVERFLOW);
    }

    name_t value;
    os_memmove(&value, in, 8);

    return value;
}

uint8_t name_to_string(name_t value, char *out, uint32_t size) {
    if (size < 13) {
        PRINTF("types: name_to_string underflow");
        THROW(EXCEPTION_OVERFLOW);
    }

    uint32_t i = 0;
    uint32_t actual_size = 13;
    uint64_t tmp = value;
    char str[13] = {'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};

    for (i = 0; i <= 12; ++i) {
        char c = charmap[tmp & (i == 0 ? 0x0f : 0x1f)];
        str[12 - i] = c;
        tmp >>= (i == 0 ? 4 : 5);
    }

    while (actual_size != 0 && str[actual_size-1] == '.'){
        actual_size--;
    }

    os_memmove(out, str, actual_size);
    return actual_size;
}

bool is_valid_symbol(symbol_t sym) {
    sym >>= 8;
    for( int i = 0; i < 7; ++i ) {
        char c = (char)(sym & 0xff);
        if( !('A' <= c && c <= 'Z')  ) return false;
        sym >>= 8;
        if( !(sym & 0xff) ) {
            do {
                sym >>= 8;
                if( (sym & 0xff) ) return false;
                ++i;
            } while( i < 7 );
        }
    }
    return true;
}

uint32_t symbol_length(symbol_t tmp) {
    tmp >>= 8; /// skip precision
    uint32_t length = 0;
    while( tmp & 0xff && length <= 7) {
        ++length;
        tmp >>= 8;
    }

    return length;
}

uint64_t symbol_precision(symbol_t sym) {
    return sym & 0xff;
}

uint8_t symbol_to_string(symbol_t sym, char *out, uint32_t size) {
    sym >>= 8;

    if (size < 8) {
        THROW(EXCEPTION_OVERFLOW);
    }

    uint8_t i = 0;
    char tmp[8] = { 0 };

    for (i = 0; i < 7; ++i) {
        char c = (char)(sym & 0xff);
        if (!c) break;
        tmp[i] = c;
        sym >>= 8;
    }

    os_memmove(out, tmp, i);
    return i;
}

uint8_t asset_to_string(asset_t *asset, char *out, uint32_t size) {
    PRINTF("types: entering asset");
    if (asset == NULL) {
        THROW(INVALID_PARAMETER);
    }

    int64_t p = (int64_t)symbol_precision(asset->symbol);
    int64_t p10 = 1;
    while (p > 0) {
        p10 *= 10; --p;
    }

    p = (int64_t)symbol_precision(asset->symbol);

    char fraction[p+1];
    fraction[p] = 0;
    int64_t change = asset->amount % p10;

    for (int64_t i = p - 1; i >= 0; --i) {
        fraction[i] = (change % 10) + '0';
        change /= 10;
    }
    char symbol[9];
    os_memset(symbol, 0, sizeof(symbol));
    symbol_to_string(asset->symbol, symbol, 8);

    char tmp[64];
    os_memset(tmp, 0, sizeof(tmp));
    i64toa(asset->amount / p10, tmp);
    uint32_t assetTextLength = strlen(tmp);
    tmp[assetTextLength++] = '.';
    os_memmove(tmp + assetTextLength, fraction, strlen(fraction));
    assetTextLength = strlen(tmp);
    tmp[assetTextLength++] = ' ';
    os_memmove(tmp + assetTextLength, symbol, strlen(symbol));
    assetTextLength = strlen(tmp);
    
    os_memmove(out, tmp, assetTextLength);

    return assetTextLength;
}

uint32_t unpack_variant32(uint8_t *in, uint32_t length, variant32_t *value) {
    uint32_t i = 0;
    uint64_t v = 0; char b = 0; uint8_t by = 0;
    do {
        b = *in; ++in; ++i;
        v |= (uint32_t)((uint8_t)b & 0x7f) << by;
        by += 7;
    } while( ((uint8_t)b) & 0x80 && by < 32 );
    
    *value = v;
    return i;
}

uint32_t public_key_to_wif(uint8_t *publicKey, uint32_t keyLength, char *out, uint32_t outLength) {
    if (publicKey == NULL || keyLength < 33) {
        THROW(INVALID_PARAMETER);
    }
    if (outLength < 40) {
        THROW(EXCEPTION_OVERFLOW);
    }

    uint8_t temp[33];
    // is even?
    temp[0] = (publicKey[64] & 0x1) ? 0x03 : 0x02;
    os_memmove(temp + 1, publicKey + 1, 32);
    return compressed_public_key_to_wif(temp, sizeof(temp), out, outLength);
}

uint32_t compressed_public_key_to_wif(uint8_t *publicKey, uint32_t keyLength, char *out, uint32_t outLength) {
    if (keyLength < 33) {
        THROW(INVALID_PARAMETER);
    }
    if (outLength < 40) {
        THROW(EXCEPTION_OVERFLOW);
    }
    
    uint8_t temp[37];
    os_memset(temp, 0, sizeof(temp));
    os_memmove(temp, publicKey, 33);
    
    uint8_t check[20];
    cx_ripemd160_t riprip;
    cx_ripemd160_init(&riprip);
    cx_hash(&riprip.header, CX_LAST, temp, 33, check);
    os_memmove(temp + 33, check, 4);
    
    os_memset(out, 0, outLength);
    out[0] = 'S';
    out[1] = 'T';
    out[2] = 'M';
    uint32_t addressLen = outLength - 3;
    b58enc(temp, sizeof(temp), out + 3, &addressLen);
    if (addressLen + 3 >= outLength) {
        THROW(EXCEPTION_OVERFLOW);
    }
    return addressLen + 3;
}
