/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


/*
 File Format
 
 [4 bytes]          per file magic 0xF9, 0xAA, 0x03, 0xBA
 [int32_t/4 bytes]  version number
 [int32_t/4 bytes]  version flags
 [varint]           *hashlength* = length of hash used in file (shorten sha256, max 32 bytes, 8 by default)
 ---- records
 [4 bytes]          static per record magic 0x88, 0x61, 0xAD, 0xFC
 [hashlength]       partial sha256 hash of the record body
 [body]
   [1 byte]         record type (0 = write | 1 = erase)
   [varint]         length of the key
   [variable]       key data
   [varint]         length of the value
   [variable]       value data
 [hashlength]       partial sha256 of *all data* up to this point in logdb
 ---- more records
*/

#ifndef __LIBBTC_LOGDB_H__
#define __LIBBTC_LOGDB_H__

#include "btc.h"
#include "hash.h"
#include "sha2.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/** record types */
enum btc_logdb_record_type {
    RECORD_TYPE_WRITE = 0,
    RECORD_TYPE_ERASE = 1
};

/** error types */
enum btc_logdb_error {
    LOGDB_SUCCESS = 0,
    LOGDB_ERROR_UNKNOWN = 100,
    LOGDB_ERROR_FOPEN_FAILED = 200,
    LOGDB_ERROR_WRONG_FILE_FORMAT = 300,
    LOGDB_ERROR_DATASTREAM_ERROR = 400,
    LOGDB_ERROR_CHECKSUM = 500,
    LOGDB_ERROR_FILE_ALREADY_OPEN = 600,
};

/** single key/value record */
typedef struct btc_logdb_record {
    cstring* key;
    cstring* value;
    struct btc_logdb_record* next;
    struct btc_logdb_record* prev;
    btc_bool written;
    uint8_t mode;
} btc_logdb_record;

/** logdb handle */
typedef struct btc_log_db {
    FILE *file;
    uint256 ctx_state;
    btc_logdb_record *head;
    SHA256_CTX hashctx;
    uint8_t hashlen;
    uint32_t version;
    uint32_t support_flags;
} btc_log_db;

/////////// RECORD HANDLING
//////////////////////////////////
/** creates new logdb key/value record */
LIBBTC_API btc_logdb_record* btc_logdb_record_new();

/** free record including containing key/value data */
LIBBTC_API void btc_logdb_record_free(btc_logdb_record* rec);

/** sets key value (binary buffer copy) */
LIBBTC_API void btc_logdb_record_set(btc_logdb_record* rec, struct buffer *key, struct buffer *val);

/** copy database record */
LIBBTC_API btc_logdb_record* btc_logdb_record_copy(btc_logdb_record* b_rec);

/** serialize a record into a cstring */
void btc_logdb_record_ser(btc_logdb_record* rec, cstring *buf);

/////////// DB HANDLING
//////////////////////////////////
/** creates new logdb handle, sets default values */
LIBBTC_API btc_log_db* btc_logdb_new();
/** frees database and all in-memory records, closes file if open */
LIBBTC_API void btc_logdb_free(btc_log_db* db);

/** loads given file as database (memory mapping) */
LIBBTC_API btc_bool btc_logdb_load(btc_log_db* handle, const char *file_path, btc_bool create, enum btc_logdb_error *error);

/** flushes database: writes down new records */
LIBBTC_API btc_bool btc_logdb_flush(btc_log_db* db);

/** deletes record with key */
LIBBTC_API void btc_logdb_delete(btc_log_db* db, struct buffer *key);

/** appends record to the logdb */
LIBBTC_API void btc_logdb_append(btc_log_db* db, struct buffer *key, struct buffer *value);

/** find and get value from key */
LIBBTC_API cstring * btc_logdb_get(btc_log_db* db, struct buffer *key);

/** get the amount of in-memory-records */
LIBBTC_API size_t btc_logdb_size(btc_log_db* db);

/** writes down single record, internal */
void btc_logdb_write_record(btc_log_db* db, btc_logdb_record *rec);

/** deserializes next logdb record from file */
btc_bool btc_logdb_record_deser_from_file(btc_logdb_record* rec, btc_log_db *db, enum btc_logdb_error *error);

/** remove records with given key (to keep memory clean) */
btc_bool btc_logdb_remove_existing_records(btc_logdb_record *usehead, cstring *key);
#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_LOGDB_H__
