/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

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

#include "script.h"

#include "buffer.h"
#include "serialize.h"

bool lbc_script_copy_without_op_codeseperator(const cstring *script_in, cstring *script_out)
{
    if (script_in->len == 0)
        return false;			/* EOF */

    struct const_buffer buf = {script_in->str, script_in->len};
    int pos = 0;
    unsigned char opcode;
    while(buf.len > 0)
    {
        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        uint32_t data_len;

        if (opcode == OP_CODESEPARATOR)
            continue;
        
        else if (opcode == OP_PUSHDATA1) {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            data_len = v8;
        }
        else if (opcode == OP_PUSHDATA2) {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            data_len = v16;
        }
        else if (opcode == OP_PUSHDATA4) {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            data_len = v32;
        } else {
            cstr_append_buf(script_out, &opcode, 1);
            continue;
        }

        cstr_append_buf(script_out, buf.p, data_len);
        if (!deser_skip(&buf, data_len))
            goto err_out;
    }
    
err_out:
    return false;
}