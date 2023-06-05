/* $NetBSD: test-helpers.h,v 1.0 2023/06/06 16:12:53 cyphar Exp $ */

/*-
 * Copyright (c) 2023 Aleksa Sarai <cyphar@cyphar.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <nbcompat/vis.h>

#define DEFINE_TEST_FUNC(name, DigestDataFunc)                                              \
    int test_ ## name(const char *data, size_t len, const char *expected_digest)            \
    {                                                                                       \
        int err = 0;                                                                        \
        char buffer[BUFSIZ];                                                                \
        memset(buffer, 0, sizeof(buffer));                                                  \
        char *digest = DigestDataFunc((const unsigned char *)data, len, (void *)buffer);    \
        if ((err = strcmp(digest, expected_digest) != 0)) {                                 \
            char *encoded = malloc(len*4 + 1);                                              \
            memset(encoded, '\0', len*4 + 1);                                               \
            strvisx(encoded, data, len, VIS_TAB | VIS_NL);                                  \
            fprintf(stderr, #name "(%s) = %s != %s\n", encoded, digest, expected_digest);   \
            free(encoded);                                                                  \
        }                                                                                   \
        return err;                                                                         \
    }                                                                                       \
                                                                                            \
    int test_ ## name ## _str(const char *data, const char *expected_digest)                \
    {                                                                                       \
        return test_ ## name(data, strlen(data), expected_digest);                          \
    }
