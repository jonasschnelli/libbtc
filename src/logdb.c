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

#include "btc/logdb.h"
#include "serialize.h"

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* reduce sha256 hash to 8 bytes for checksum */
#define kLOGDB_DEFAULT_HASH_LEN 8

#define kLOGDB_DEFAULT_VERSION 1

static const unsigned char file_hdr_magic[4] = {0xF9, 0xAA, 0x03, 0xBA}; //header magic
static const unsigned char record_magic[4] = {0x88, 0x61, 0xAD, 0xFC}; //record magic

btc_logdb_record* btc_logdb_record_new()
{
    btc_logdb_record* record;
    record = calloc(1, sizeof(*record));
    record->key = cstr_new_sz(32);
    record->value = cstr_new_sz(128);
    record->written = false;
    record->mode = RECORD_TYPE_WRITE;
    return record;
}

void btc_logdb_record_free(btc_logdb_record* rec)
{
    if (!rec)
        return;

    cstr_free(rec->key, true);
    cstr_free(rec->value, true);
    rec->next = NULL;
    rec->prev = NULL;

    free(rec);
}

void btc_logdb_record_set(btc_logdb_record* rec, struct buffer *key, struct buffer *val)
{
    if (key == NULL)
        return;

    cstr_append_buf(rec->key, key->p, key->len);
    if (val)
    {
        cstr_append_buf(rec->value, val->p, val->len);
        rec->mode = RECORD_TYPE_WRITE;
    }
    else
        rec->mode = RECORD_TYPE_ERASE;
}

btc_logdb_record* btc_logdb_record_copy(btc_logdb_record* b_rec)
{
    btc_logdb_record* a_rec = btc_logdb_record_new();
    cstr_append_cstr(a_rec->key, b_rec->key);
    cstr_append_cstr(a_rec->value, b_rec->value);
    a_rec->written = b_rec->written;
    a_rec->mode = b_rec->mode;
    return a_rec;
}

void btc_logdb_record_ser(btc_logdb_record* rec, cstring *buf)
{
    ser_bytes(buf, &rec->mode, 1);
    ser_varlen(buf, rec->key->len);
    ser_bytes(buf, rec->key->str, rec->key->len);

    //write value for a WRITE operation
    if (rec->mode == RECORD_TYPE_WRITE)
    {
        ser_varlen(buf, rec->value->len);
        ser_bytes(buf, rec->value->str, rec->value->len);
    }
}

btc_log_db* btc_logdb_new()
{
    btc_log_db* db;
    db = calloc(1, sizeof(*db));
    db->head = NULL;
    sha256_Init(&db->hashctx);
    db->hashlen = kLOGDB_DEFAULT_HASH_LEN;
    db->version = kLOGDB_DEFAULT_VERSION;
    db->support_flags = 0; //reserved for future changes
    return db;
}

void btc_logdb_free(btc_log_db* db)
{
    if (!db)
        return;

    if (db->file)
    {
        fclose(db->file);
        db->file = NULL;
    }

    btc_logdb_record *rec = db->head;
    while (rec)
    {
        btc_logdb_record *prev_rec = rec->prev;
        btc_logdb_record_free(rec);
        rec = prev_rec;
    }

    free(db);
}

btc_bool btc_logdb_load(btc_log_db* handle, const char *file_path, btc_bool create, enum btc_logdb_error *error)
{
    handle->file = fopen(file_path, create ? "a+b" : "r+b");
    if (handle->file == NULL)
    {
        if (error != NULL)
            *error = LOGDB_ERROR_FOPEN_FAILED;
        return false;
    }

    //write header magic
    if (create)
    {
        //write header magic, version & support flags
        fwrite(file_hdr_magic, 4, 1, handle->file);
        uint32_t v = htole32(handle->version);
        fwrite(&v, sizeof(v), 1, handle->file); //uint32_t, LE
        v = htole32(handle->support_flags);
        fwrite(&v, sizeof(v), 1, handle->file); //uint32_t, LE

        // write hash len
        fwrite(&handle->hashlen, 1, 1, handle->file); //uint8_t
    }
    else
    {
        //read file magic, version, etc.
        unsigned char buf[4];
        if (fread(buf, 4, 1, handle->file) != 1 || memcmp(buf, file_hdr_magic, 4) != 0)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }

        // read and set version
        uint32_t v = 0;
        if (fread(&v, sizeof(v), 1, handle->file) != 1)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }
        handle->version = le32toh(v);

        // read and set support flags
        if (fread(&v, sizeof(v), 1, handle->file) != 1)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }
        handle->support_flags = le32toh(v);

        // read hashlen
        if (fread(&handle->hashlen, 1, 1, handle->file) != 1)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }
    }

    btc_logdb_record *rec = btc_logdb_record_new();

    enum btc_logdb_error record_error;
    while (btc_logdb_record_deser_from_file(rec, handle, &record_error))
    {
        if (record_error != LOGDB_SUCCESS)
            break;

        rec->written = true;
        btc_logdb_record *old_head = handle->head;
        handle->head = btc_logdb_record_copy(rec);

        //re-link the chain
        if(old_head)
        {
            handle->head->prev = old_head;
            old_head->next = handle->head;
        }

        //remove old keys
        btc_logdb_remove_existing_records(old_head, rec->key);
    }
    btc_logdb_record_free(rec);

    if (record_error != LOGDB_SUCCESS)
    {
        *error = record_error;
        return false;
    }

    return true;
}

btc_bool btc_logdb_flush(btc_log_db* db)
{
    if (!db->file)
        return false;

    btc_logdb_record *flush_rec = db->head;

    while (flush_rec != NULL)
    {
        if (flush_rec->written == true)
        {
            flush_rec = flush_rec->next;
            break;
        }

        if (flush_rec->prev != NULL)
            flush_rec = flush_rec->prev;
        else
            break;
    }
    while (flush_rec != NULL)
    {
        btc_logdb_write_record(db, flush_rec);
        flush_rec->written = true;
        flush_rec = flush_rec->next;
    }

    return true;
}

void btc_logdb_delete(btc_log_db* db, struct buffer *key)
{
    if (key == NULL)
        return;

    btc_logdb_append(db, key, NULL);
}

void btc_logdb_append(btc_log_db* db, struct buffer *key, struct buffer *val)
{
    if (key == NULL)
        return;
    
    btc_logdb_record *rec = btc_logdb_record_new();
    btc_logdb_record_set(rec, key, val);
    btc_logdb_record *current_head = db->head;

    if (current_head != NULL)
    {
        current_head->next = rec;
    }

    rec->prev = current_head;
    db->head = rec;

    //remove old keys
    btc_logdb_remove_existing_records(current_head, rec->key);
}

cstring * btc_logdb_get(btc_log_db* db, struct buffer *key)
{
    cstring *found_value = NULL;
    if (key == NULL)
        return NULL;

    cstring *keycstr = cstr_new_buf(key->p, key->len);
    btc_logdb_record *rec = db->head;
    while (rec)
    {
        if (cstr_equal(rec->key, keycstr))
        {
            //found
            found_value = rec->value;

            //found, but deleted
            if (rec->mode == RECORD_TYPE_ERASE)
                found_value = NULL;

            break;
        }
        rec = rec->prev;
    }
    cstr_free(keycstr, true);
    return found_value;
}

size_t btc_logdb_size(btc_log_db* db)
{
    size_t cnt = 0;
    btc_logdb_record *rec_loop = db->head;
    while (rec_loop)
    {
        if (rec_loop->mode == RECORD_TYPE_WRITE)
            cnt++;

        rec_loop = rec_loop->prev;
    }

    return cnt;
}

void btc_logdb_write_record(btc_log_db* db, btc_logdb_record *rec)
{
    SHA256_CTX ctx = db->hashctx;

    //serialize record to buffer
    cstring *serbuf = cstr_new_sz(1024);
    btc_logdb_record_ser(rec, serbuf);

    //create hash of the body
    uint8_t hash_rec[SHA256_DIGEST_LENGTH];
    sha256_Raw((const uint8_t*)serbuf->str, serbuf->len, hash_rec);

    //write record header
    assert(fwrite(record_magic, 4, 1, db->file) == 1);
    sha256_Update(&ctx, record_magic, 4);

    //write partial hash as body checksum&indicator (body start)
    assert(fwrite(hash_rec, db->hashlen, 1, db->file) == 1);
    sha256_Update(&ctx, hash_rec, db->hashlen);

    //write the body
    fwrite(serbuf->str, serbuf->len, 1, db->file);
    sha256_Update(&ctx, (uint8_t *)serbuf->str, serbuf->len);

    //write partial hash as body checksum&indicator (body end)
    assert(fwrite(hash_rec, db->hashlen, 1, db->file) == 1);
    sha256_Update(&ctx, hash_rec, db->hashlen);
    
    cstr_free(serbuf, true);

    SHA256_CTX ctx_final = ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Final(hash, &ctx_final);
    assert(fwrite(hash, db->hashlen, 1, db->file) == 1);
    db->hashctx = ctx;
}

btc_bool btc_logdb_record_deser_from_file(btc_logdb_record* rec, btc_log_db *db, enum btc_logdb_error *error)
{
    uint32_t len = 0;

    *error = LOGDB_SUCCESS;
    //prepare a copy of context that allows rollback
    SHA256_CTX ctx = db->hashctx;

    //read record magic
    uint8_t magic_buf[4];
    if (fread(magic_buf, 4, 1, db->file) != 1)
    {
        // very likely end of file reached
        return false;
    }
    sha256_Update(&ctx, magic_buf, 4);

    //read start hash/magic per record
    uint8_t hashcheck[db->hashlen];
    if (fread(hashcheck, db->hashlen, 1, db->file) != 1)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }
    sha256_Update(&ctx, hashcheck, db->hashlen);

    //read record mode (write / delete)
    if (fread(&rec->mode, 1, 1, db->file) != 1)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    sha256_Update(&ctx, (const uint8_t *)&rec->mode, 1);

    //prepate a buffer for the varint data (max 4 bytes)
    size_t buflen = sizeof(uint32_t);
    uint8_t readbuf[buflen];

    //key
    if (!deser_varlen_file(&len, db->file, readbuf, &buflen))
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    sha256_Update(&ctx, readbuf, buflen);

    cstr_resize(rec->key, len);
    if (fread(rec->key->str, 1, len, db->file) != len)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    sha256_Update(&ctx, (const uint8_t *)rec->key->str, len);

    if (rec->mode == RECORD_TYPE_WRITE)
    {
        //read value (not for delete mode)
        buflen = sizeof(uint32_t);
        if (!deser_varlen_file(&len, db->file, readbuf, &buflen))
        {
            *error = LOGDB_ERROR_DATASTREAM_ERROR;
            return false;
        }

        sha256_Update(&ctx, readbuf, buflen);

        cstr_resize(rec->value, len);
        if (fread(rec->value->str, 1, len, db->file) != len)
        {
            *error = LOGDB_ERROR_DATASTREAM_ERROR;
            return false;
        }

        sha256_Update(&ctx, (const uint8_t *)rec->value->str, len);
    }

    //read start hash/magic per record
    if (fread(hashcheck, db->hashlen, 1, db->file) != 1)
    {
        // very likely end of file reached
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }
    sha256_Update(&ctx, hashcheck, db->hashlen);

    //generate final checksum in a context copy
    SHA256_CTX ctx_final = ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Final(hash, &ctx_final);

    //read checksum from file, compare
    unsigned char check[db->hashlen];
    if (fread(check, 1, db->hashlen, db->file) != db->hashlen)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    if (memcmp(hash,check,(size_t)db->hashlen) != 0)
    {
        *error = LOGDB_ERROR_CHECKSUM;
        return false;
    }
    
    db->hashctx = ctx;
    return true;
}

btc_bool btc_logdb_remove_existing_records(btc_logdb_record *usehead, cstring *key)
{
    btc_bool found = false;
    //remove old records with same key
    btc_logdb_record *rec_loop = usehead;
    while (rec_loop)
    {
        btc_logdb_record *prev_rec = rec_loop->prev;
        if (cstr_equal(rec_loop->key, key))
        {
            //remove from linked list
            if (rec_loop->prev)
                rec_loop->prev->next = rec_loop->next;

            if (rec_loop->next && rec_loop->next->prev)
                rec_loop->next->prev = rec_loop->prev;

            btc_logdb_record_free(rec_loop);

            //found an already existing key, remove
            found = true;
        }

        rec_loop = prev_rec;
    }
    return found;
}
