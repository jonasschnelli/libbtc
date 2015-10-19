/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "buffer.h"

void test_buffer()
{
    struct const_buffer buf0 = { "data", 4 };
    struct const_buffer buf1 = { "data", 4 };

    assert(buffer_equal(&buf0.p, &buf1.p) == true);

    struct buffer *buf2 = buffer_copy(&buf0.p, buf0.len);
    buffer_free(buf2);
}
