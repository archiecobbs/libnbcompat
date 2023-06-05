/* $NetBSD: rmd160-test.c,v 1.0 2023/06/06 16:12:53 cyphar Exp $ */

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

#include <nbcompat.h>
#include <nbcompat/stdio.h>
#include <nbcompat/rmd160.h>

#include "private/test-helpers.h"

DEFINE_TEST_FUNC(ripemd160, RMD160Data)

#define VECTOR8_PART "1234567890"
#define VECTOR8	\
	VECTOR8_PART VECTOR8_PART VECTOR8_PART VECTOR8_PART \
	VECTOR8_PART VECTOR8_PART VECTOR8_PART VECTOR8_PART

char *vector9(void)
{
	char *vector = malloc(1000 * 1000 + 1);
	memset(vector, 'a', 1000*1000);
	vector[1000*1000] = '\0';
	return vector;
}

int main(void)
{
	int err = 0;

	/* Test vectors from <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html>. */
	err |= test_ripemd160_str("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
	err |= test_ripemd160_str("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
	err |= test_ripemd160_str("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
	err |= test_ripemd160_str("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
	err |= test_ripemd160_str("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
	err |= test_ripemd160_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
	err |= test_ripemd160_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189");
	err |= test_ripemd160_str(VECTOR8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
	err |= test_ripemd160_str(vector9(), "52783243c1697bdbe16d37f97f68f08325dc1528");

	return err;
}
