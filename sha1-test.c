/* $NetBSD: sha1-test.c,v 1.0 2023/06/06 16:12:53 cyphar Exp $ */

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
#include <nbcompat/sha1.h>

#include "private/test-helpers.h"

/*
 * All of these test vectors are the "short message" vectors provided by NIST
 * as part of the Cryptographic Algorithm Validation Program.
 * <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program>
 *
 * The script to generate these functions is in private/cavs2c.awk.
 */

DEFINE_TEST_FUNC(sha1, SHA1Data);

int sha1(void)
{
	int err = 0;

	size_t len1 = 0;
	const char vector1[] = {'\x00',};
	const char *digest1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
	err |= test_sha1(vector1, len1, digest1);

	size_t len2 = 1;
	const char vector2[] = {'\x36',};
	const char *digest2 = "c1dfd96eea8cc2b62785275bca38ac261256e278";
	err |= test_sha1(vector2, len2, digest2);

	size_t len3 = 2;
	const char vector3[] = {'\x19','\x5a',};
	const char *digest3 = "0a1c2d555bbe431ad6288af5a54f93e0449c9232";
	err |= test_sha1(vector3, len3, digest3);

	size_t len4 = 3;
	const char vector4[] = {'\xdf','\x4b','\xd2',};
	const char *digest4 = "bf36ed5d74727dfd5d7854ec6b1d49468d8ee8aa";
	err |= test_sha1(vector4, len4, digest4);

	size_t len5 = 4;
	const char vector5[] = {'\x54','\x9e','\x95','\x9e',};
	const char *digest5 = "b78bae6d14338ffccfd5d5b5674a275f6ef9c717";
	err |= test_sha1(vector5, len5, digest5);

	size_t len6 = 5;
	const char vector6[] = {'\xf7','\xfb','\x1b','\xe2','\x05',};
	const char *digest6 = "60b7d5bb560a1acf6fa45721bd0abb419a841a89";
	err |= test_sha1(vector6, len6, digest6);

	size_t len7 = 6;
	const char vector7[] = {'\xc0','\xe5','\xab','\xea','\xea','\x63',};
	const char *digest7 = "a6d338459780c08363090fd8fc7d28dc80e8e01f";
	err |= test_sha1(vector7, len7, digest7);

	size_t len8 = 7;
	const char vector8[] = {'\x63','\xbf','\xc1','\xed','\x7f','\x78','\xab',};
	const char *digest8 = "860328d80509500c1783169ebf0ba0c4b94da5e5";
	err |= test_sha1(vector8, len8, digest8);

	size_t len9 = 8;
	const char vector9[] = {'\x7e','\x3d','\x7b','\x3e','\xad','\xa9','\x88','\x66',};
	const char *digest9 = "24a2c34b976305277ce58c2f42d5092031572520";
	err |= test_sha1(vector9, len9, digest9);

	size_t len10 = 9;
	const char vector10[] = {'\x9e','\x61','\xe5','\x5d','\x9e','\xd3','\x7b','\x1c','\x20',};
	const char *digest10 = "411ccee1f6e3677df12698411eb09d3ff580af97";
	err |= test_sha1(vector10, len10, digest10);

	size_t len11 = 10;
	const char vector11[] = {'\x97','\x77','\xcf','\x90','\xdd','\x7c','\x7e','\x86','\x35','\x06',};
	const char *digest11 = "05c915b5ed4e4c4afffc202961f3174371e90b5c";
	err |= test_sha1(vector11, len11, digest11);

	size_t len12 = 11;
	const char vector12[] = {'\x4e','\xb0','\x8c','\x9e','\x68','\x3c','\x94','\xbe','\xa0','\x0d','\xfa',};
	const char *digest12 = "af320b42d7785ca6c8dd220463be23a2d2cb5afc";
	err |= test_sha1(vector12, len12, digest12);

	size_t len13 = 12;
	const char vector13[] = {'\x09','\x38','\xf2','\xe2','\xeb','\xb6','\x4f','\x8a','\xf8','\xbb','\xfc','\x91',};
	const char *digest13 = "9f4e66b6ceea40dcf4b9166c28f1c88474141da9";
	err |= test_sha1(vector13, len13, digest13);

	size_t len14 = 13;
	const char vector14[] = {'\x74','\xc9','\x99','\x6d','\x14','\xe8','\x7d','\x3e','\x6c','\xbe','\xa7','\x02','\x9d',};
	const char *digest14 = "e6c4363c0852951991057f40de27ec0890466f01";
	err |= test_sha1(vector14, len14, digest14);

	size_t len15 = 14;
	const char vector15[] = {'\x51','\xdc','\xa5','\xc0','\xf8','\xe5','\xd4','\x95','\x96','\xf3','\x2d','\x3e','\xb8','\x74',};
	const char *digest15 = "046a7b396c01379a684a894558779b07d8c7da20";
	err |= test_sha1(vector15, len15, digest15);

	size_t len16 = 15;
	const char vector16[] = {'\x3a','\x36','\xea','\x49','\x68','\x48','\x20','\xa2','\xad','\xc7','\xfc','\x41','\x75','\xba','\x78',};
	const char *digest16 = "d58a262ee7b6577c07228e71ae9b3e04c8abcda9";
	err |= test_sha1(vector16, len16, digest16);

	size_t len17 = 16;
	const char vector17[] = {'\x35','\x52','\x69','\x4c','\xdf','\x66','\x3f','\xd9','\x4b','\x22','\x47','\x47','\xac','\x40','\x6a','\xaf',};
	const char *digest17 = "a150de927454202d94e656de4c7c0ca691de955d";
	err |= test_sha1(vector17, len17, digest17);

	size_t len18 = 17;
	const char vector18[] = {'\xf2','\x16','\xa1','\xcb','\xde','\x24','\x46','\xb1','\xed','\xf4','\x1e','\x93','\x48','\x1d','\x33','\xe2','\xed',};
	const char *digest18 = "35a4b39fef560e7ea61246676e1b7e13d587be30";
	err |= test_sha1(vector18, len18, digest18);

	size_t len19 = 18;
	const char vector19[] = {'\xa3','\xcf','\x71','\x4b','\xf1','\x12','\x64','\x7e','\x72','\x7e','\x8c','\xfd','\x46','\x49','\x9a','\xcd','\x35','\xa6',};
	const char *digest19 = "7ce69b1acdce52ea7dbd382531fa1a83df13cae7";
	err |= test_sha1(vector19, len19, digest19);

	size_t len20 = 19;
	const char vector20[] = {'\x14','\x8d','\xe6','\x40','\xf3','\xc1','\x15','\x91','\xa6','\xf8','\xc5','\xc4','\x86','\x32','\xc5','\xfb','\x79','\xd3','\xb7',};
	const char *digest20 = "b47be2c64124fa9a124a887af9551a74354ca411";
	err |= test_sha1(vector20, len20, digest20);

	size_t len21 = 20;
	const char vector21[] = {'\x63','\xa3','\xcc','\x83','\xfd','\x1e','\xc1','\xb6','\x68','\x0e','\x99','\x74','\xa0','\x51','\x4e','\x1a','\x9e','\xce','\xbb','\x6a',};
	const char *digest21 = "8bb8c0d815a9c68a1d2910f39d942603d807fbcc";
	err |= test_sha1(vector21, len21, digest21);

	size_t len22 = 21;
	const char vector22[] = {'\x87','\x5a','\x90','\x90','\x9a','\x8a','\xfc','\x92','\xfb','\x70','\x70','\x04','\x7e','\x9d','\x08','\x1e','\xc9','\x2f','\x3d','\x08','\xb8',};
	const char *digest22 = "b486f87fb833ebf0328393128646a6f6e660fcb1";
	err |= test_sha1(vector22, len22, digest22);

	size_t len23 = 22;
	const char vector23[] = {'\x44','\x4b','\x25','\xf9','\xc9','\x25','\x9d','\xc2','\x17','\x77','\x2c','\xc4','\x47','\x8c','\x44','\xb6','\xfe','\xff','\x62','\x35','\x36','\x73',};
	const char *digest23 = "76159368f99dece30aadcfb9b7b41dab33688858";
	err |= test_sha1(vector23, len23, digest23);

	size_t len24 = 23;
	const char vector24[] = {'\x48','\x73','\x51','\xc8','\xa5','\xf4','\x40','\xe4','\xd0','\x33','\x86','\x48','\x3d','\x5f','\xe7','\xbb','\x66','\x9d','\x41','\xad','\xcb','\xfd','\xb7',};
	const char *digest24 = "dbc1cb575ce6aeb9dc4ebf0f843ba8aeb1451e89";
	err |= test_sha1(vector24, len24, digest24);

	size_t len25 = 24;
	const char vector25[] = {'\x46','\xb0','\x61','\xef','\x13','\x2b','\x87','\xf6','\xd3','\xb0','\xee','\x24','\x62','\xf6','\x7d','\x91','\x09','\x77','\xda','\x20','\xae','\xd1','\x37','\x05',};
	const char *digest25 = "d7a98289679005eb930ab75efd8f650f991ee952";
	err |= test_sha1(vector25, len25, digest25);

	size_t len26 = 25;
	const char vector26[] = {'\x38','\x42','\xb6','\x13','\x7b','\xb9','\xd2','\x7f','\x3c','\xa5','\xba','\xfe','\x5b','\xbb','\x62','\x85','\x83','\x44','\xfe','\x4b','\xa5','\xc4','\x15','\x89','\xa5',};
	const char *digest26 = "fda26fa9b4874ab701ed0bb64d134f89b9c4cc50";
	err |= test_sha1(vector26, len26, digest26);

	size_t len27 = 26;
	const char vector27[] = {'\x44','\xd9','\x1d','\x3d','\x46','\x5a','\x41','\x11','\x46','\x2b','\xa0','\xc7','\xec','\x22','\x3d','\xa6','\x73','\x5f','\x4f','\x52','\x00','\x45','\x3c','\xf1','\x32','\xc3',};
	const char *digest27 = "c2ff7ccde143c8f0601f6974b1903eb8d5741b6e";
	err |= test_sha1(vector27, len27, digest27);

	size_t len28 = 27;
	const char vector28[] = {'\xcc','\xe7','\x3f','\x2e','\xab','\xcb','\x52','\xf7','\x85','\xd5','\xa6','\xdf','\x63','\xc0','\xa1','\x05','\xf3','\x4a','\x91','\xca','\x23','\x7f','\xe5','\x34','\xee','\x39','\x9d',};
	const char *digest28 = "643c9dc20a929608f6caa9709d843ca6fa7a76f4";
	err |= test_sha1(vector28, len28, digest28);

	size_t len29 = 28;
	const char vector29[] = {'\x66','\x4e','\x6e','\x79','\x46','\x83','\x92','\x03','\x03','\x7a','\x65','\xa1','\x21','\x74','\xb2','\x44','\xde','\x8c','\xbc','\x6e','\xc3','\xf5','\x78','\x96','\x7a','\x84','\xf9','\xce',};
	const char *digest29 = "509ef787343d5b5a269229b961b96241864a3d74";
	err |= test_sha1(vector29, len29, digest29);

	size_t len30 = 29;
	const char vector30[] = {'\x95','\x97','\xf7','\x14','\xb2','\xe4','\x5e','\x33','\x99','\xa7','\xf0','\x2a','\xec','\x44','\x92','\x1b','\xd7','\x8b','\xe0','\xfe','\xfe','\xe0','\xc5','\xe9','\xb4','\x99','\x48','\x8f','\x6e',};
	const char *digest30 = "b61ce538f1a1e6c90432b233d7af5b6524ebfbe3";
	err |= test_sha1(vector30, len30, digest30);

	size_t len31 = 30;
	const char vector31[] = {'\x75','\xc5','\xad','\x1f','\x3c','\xbd','\x22','\xe8','\xa9','\x5f','\xc3','\xb0','\x89','\x52','\x67','\x88','\xfb','\x4e','\xbc','\xee','\xd3','\xe7','\xd4','\x44','\x3d','\xa6','\xe0','\x81','\xa3','\x5e',};
	const char *digest31 = "5b7b94076b2fc20d6adb82479e6b28d07c902b75";
	err |= test_sha1(vector31, len31, digest31);

	size_t len32 = 31;
	const char vector32[] = {'\xdd','\x24','\x5b','\xff','\xe6','\xa6','\x38','\x80','\x66','\x67','\x76','\x83','\x60','\xa9','\x5d','\x05','\x74','\xe1','\xa0','\xbd','\x0d','\x18','\x32','\x9f','\xdb','\x91','\x5c','\xa4','\x84','\xac','\x0d',};
	const char *digest32 = "6066db99fc358952cf7fb0ec4d89cb0158ed91d7";
	err |= test_sha1(vector32, len32, digest32);

	size_t len33 = 32;
	const char vector33[] = {'\x03','\x21','\x79','\x4b','\x73','\x94','\x18','\xc2','\x4e','\x7c','\x2e','\x56','\x52','\x74','\x79','\x1c','\x4b','\xe7','\x49','\x75','\x2a','\xd2','\x34','\xed','\x56','\xcb','\x0a','\x63','\x47','\x43','\x0c','\x6b',};
	const char *digest33 = "b89962c94d60f6a332fd60f6f07d4f032a586b76";
	err |= test_sha1(vector33, len33, digest33);

	size_t len34 = 33;
	const char vector34[] = {'\x4c','\x3d','\xcf','\x95','\xc2','\xf0','\xb5','\x25','\x8c','\x65','\x1f','\xcd','\x1d','\x51','\xbd','\x10','\x42','\x5d','\x62','\x03','\x06','\x7d','\x07','\x48','\xd3','\x7d','\x13','\x40','\xd9','\xdd','\xda','\x7d','\xb3',};
	const char *digest34 = "17bda899c13d35413d2546212bcd8a93ceb0657b";
	err |= test_sha1(vector34, len34, digest34);

	size_t len35 = 34;
	const char vector35[] = {'\xb8','\xd1','\x25','\x82','\xd2','\x5b','\x45','\x29','\x0a','\x6e','\x1b','\xb9','\x5d','\xa4','\x29','\xbe','\xfc','\xfd','\xbf','\x5b','\x4d','\xd4','\x1c','\xdf','\x33','\x11','\xd6','\x98','\x8f','\xa1','\x7c','\xec','\x07','\x23',};
	const char *digest35 = "badcdd53fdc144b8bf2cc1e64d10f676eebe66ed";
	err |= test_sha1(vector35, len35, digest35);

	size_t len36 = 35;
	const char vector36[] = {'\x6f','\xda','\x97','\x52','\x7a','\x66','\x25','\x52','\xbe','\x15','\xef','\xae','\xba','\x32','\xa3','\xae','\xa4','\xed','\x44','\x9a','\xbb','\x5c','\x1e','\xd8','\xd9','\xbf','\xff','\x54','\x47','\x08','\xa4','\x25','\xd6','\x9b','\x72',};
	const char *digest36 = "01b4646180f1f6d2e06bbe22c20e50030322673a";
	err |= test_sha1(vector36, len36, digest36);

	size_t len37 = 36;
	const char vector37[] = {'\x09','\xfa','\x27','\x92','\xac','\xbb','\x24','\x17','\xe8','\xed','\x26','\x90','\x41','\xcc','\x03','\xc7','\x70','\x06','\x46','\x6e','\x6e','\x7a','\xe0','\x02','\xcf','\x3f','\x1a','\xf5','\x51','\xe8','\xce','\x0b','\xb5','\x06','\xd7','\x05',};
	const char *digest37 = "10016dc3a2719f9034ffcc689426d28292c42fc9";
	err |= test_sha1(vector37, len37, digest37);

	size_t len38 = 37;
	const char vector38[] = {'\x5e','\xfa','\x29','\x87','\xda','\x0b','\xaf','\x0a','\x54','\xd8','\xd7','\x28','\x79','\x2b','\xcf','\xa7','\x07','\xa1','\x57','\x98','\xdc','\x66','\x74','\x37','\x54','\x40','\x69','\x14','\xd1','\xcf','\xe3','\x70','\x9b','\x13','\x74','\xea','\xeb',};
	const char *digest38 = "9f42fa2bce6ef021d93c6b2d902273797e426535";
	err |= test_sha1(vector38, len38, digest38);

	size_t len39 = 38;
	const char vector39[] = {'\x28','\x36','\xde','\x99','\xc0','\xf6','\x41','\xcd','\x55','\xe8','\x9f','\x5a','\xf7','\x66','\x38','\x94','\x7b','\x82','\x27','\x37','\x7e','\xf8','\x8b','\xfb','\xa6','\x62','\xe5','\x68','\x2b','\xab','\xc1','\xec','\x96','\xc6','\x99','\x2b','\xc9','\xa0',};
	const char *digest39 = "cdf48bacbff6f6152515323f9b43a286e0cb8113";
	err |= test_sha1(vector39, len39, digest39);

	size_t len40 = 39;
	const char vector40[] = {'\x42','\x14','\x3a','\x2b','\x9e','\x1d','\x0b','\x35','\x4d','\xf3','\x26','\x4d','\x08','\xf7','\xb6','\x02','\xf5','\x4a','\xad','\x92','\x2a','\x3d','\x63','\x00','\x6d','\x09','\x7f','\x68','\x3d','\xc1','\x1b','\x90','\x17','\x84','\x23','\xbf','\xf2','\xf7','\xfe',};
	const char *digest40 = "b88fb75274b9b0fd57c0045988cfcef6c3ce6554";
	err |= test_sha1(vector40, len40, digest40);

	size_t len41 = 40;
	const char vector41[] = {'\xeb','\x60','\xc2','\x8a','\xd8','\xae','\xda','\x80','\x7d','\x69','\xeb','\xc8','\x75','\x52','\x02','\x4a','\xd8','\xac','\xa6','\x82','\x04','\xf1','\xbc','\xd2','\x9d','\xc5','\xa8','\x1d','\xd2','\x28','\xb5','\x91','\xe2','\xef','\xb7','\xc4','\xdf','\x75','\xef','\x03',};
	const char *digest41 = "c06d3a6a12d9e8db62e8cff40ca23820d61d8aa7";
	err |= test_sha1(vector41, len41, digest41);

	size_t len42 = 41;
	const char vector42[] = {'\x7d','\xe4','\xba','\x85','\xec','\x54','\x74','\x7c','\xdc','\x42','\xb1','\xf2','\x35','\x46','\xb7','\xe4','\x90','\xe3','\x12','\x80','\xf0','\x66','\xe5','\x2f','\xac','\x11','\x7f','\xd3','\xb0','\x79','\x2e','\x4d','\xe6','\x2d','\x58','\x43','\xee','\x98','\xc7','\x20','\x15',};
	const char *digest42 = "6e40f9e83a4be93874bc97cdebb8da6889ae2c7a";
	err |= test_sha1(vector42, len42, digest42);

	size_t len43 = 42;
	const char vector43[] = {'\xe7','\x06','\x53','\x63','\x7b','\xc5','\xe3','\x88','\xcc','\xd8','\xdc','\x44','\xe5','\xea','\xce','\x36','\xf7','\x39','\x8f','\x2b','\xac','\x99','\x30','\x42','\xb9','\xbc','\x2f','\x4f','\xb3','\xb0','\xee','\x7e','\x23','\xa9','\x64','\x39','\xdc','\x01','\x13','\x4b','\x8c','\x7d',};
	const char *digest43 = "3efc940c312ef0dfd4e1143812248db89542f6a5";
	err |= test_sha1(vector43, len43, digest43);

	size_t len44 = 43;
	const char vector44[] = {'\xdd','\x37','\xbc','\x9f','\x0b','\x3a','\x47','\x88','\xf9','\xb5','\x49','\x66','\xf2','\x52','\x17','\x4c','\x8c','\xe4','\x87','\xcb','\xe5','\x9c','\x53','\xc2','\x2b','\x81','\xbf','\x77','\x62','\x1a','\x7c','\xe7','\x61','\x6d','\xcb','\x5b','\x1e','\x2e','\xe6','\x3c','\x2c','\x30','\x9b',};
	const char *digest44 = "a0cf03f7badd0c3c3c4ea3717f5a4fb7e67b2e56";
	err |= test_sha1(vector44, len44, digest44);

	size_t len45 = 44;
	const char vector45[] = {'\x5f','\x48','\x5c','\x63','\x7a','\xe3','\x0b','\x1e','\x30','\x49','\x7f','\x0f','\xb7','\xec','\x36','\x4e','\x13','\xc9','\x06','\xe2','\x81','\x3d','\xaa','\x34','\x16','\x1b','\x7a','\xc4','\xa4','\xfd','\x7a','\x1b','\xdd','\xd7','\x96','\x01','\xbb','\xd2','\x2c','\xef','\x1f','\x57','\xcb','\xc7',};
	const char *digest45 = "a544e06f1a07ceb175a51d6d9c0111b3e15e9859";
	err |= test_sha1(vector45, len45, digest45);

	size_t len46 = 45;
	const char vector46[] = {'\xf6','\xc2','\x37','\xfb','\x3c','\xfe','\x95','\xec','\x84','\x14','\xcc','\x16','\xd2','\x03','\xb4','\x87','\x4e','\x64','\x4c','\xc9','\xa5','\x43','\x46','\x5c','\xad','\x2d','\xc5','\x63','\x48','\x8a','\x65','\x9e','\x8a','\x2e','\x7c','\x98','\x1e','\x2a','\x9f','\x22','\xe5','\xe8','\x68','\xff','\xe1',};
	const char *digest46 = "199d986ed991b99a071f450c6b1121a727e8c735";
	err |= test_sha1(vector46, len46, digest46);

	size_t len47 = 46;
	const char vector47[] = {'\xda','\x7a','\xb3','\x29','\x15','\x53','\xc6','\x59','\x87','\x3c','\x95','\x91','\x37','\x68','\x95','\x3c','\x6e','\x52','\x6d','\x3a','\x26','\x59','\x08','\x98','\xc0','\xad','\xe8','\x9f','\xf5','\x6f','\xbd','\x11','\x0f','\x14','\x36','\xaf','\x59','\x0b','\x17','\xfe','\xd4','\x9f','\x8c','\x4b','\x2b','\x1e',};
	const char *digest47 = "33bac6104b0ad6128d091b5d5e2999099c9f05de";
	err |= test_sha1(vector47, len47, digest47);

	size_t len48 = 47;
	const char vector48[] = {'\x8c','\xfa','\x5f','\xd5','\x6e','\xe2','\x39','\xca','\x47','\x73','\x75','\x91','\xcb','\xa1','\x03','\xe4','\x1a','\x18','\xac','\xf8','\xe8','\xd2','\x57','\xb0','\xdb','\xe8','\x85','\x11','\x34','\xa8','\x1f','\xf6','\xb2','\xe9','\x71','\x04','\xb3','\x9b','\x76','\xe1','\x9d','\xa2','\x56','\xa1','\x7c','\xe5','\x2d',};
	const char *digest48 = "76d7db6e18c1f4ae225ce8ccc93c8f9a0dfeb969";
	err |= test_sha1(vector48, len48, digest48);

	size_t len49 = 48;
	const char vector49[] = {'\x57','\xe8','\x96','\x59','\xd8','\x78','\xf3','\x60','\xaf','\x6d','\xe4','\x5a','\x9a','\x5e','\x37','\x2e','\xf4','\x0c','\x38','\x49','\x88','\xe8','\x26','\x40','\xa3','\xd5','\xe4','\xb7','\x6d','\x2e','\xf1','\x81','\x78','\x0b','\x9a','\x09','\x9a','\xc0','\x6e','\xf0','\xf8','\xa7','\xf3','\xf7','\x64','\x20','\x97','\x20',};
	const char *digest49 = "f652f3b1549f16710c7402895911e2b86a9b2aee";
	err |= test_sha1(vector49, len49, digest49);

	size_t len50 = 49;
	const char vector50[] = {'\xb9','\x1e','\x64','\x23','\x5d','\xbd','\x23','\x4e','\xea','\x2a','\xe1','\x4a','\x92','\xa1','\x73','\xeb','\xe8','\x35','\x34','\x72','\x39','\xcf','\xf8','\xb0','\x20','\x74','\x41','\x6f','\x55','\xc6','\xb6','\x0d','\xc6','\xce','\xd0','\x6a','\xe9','\xf8','\xd7','\x05','\x50','\x5f','\x0d','\x61','\x7e','\x4b','\x29','\xae','\xf9',};
	const char *digest50 = "63faebb807f32be708cf00fc35519991dc4e7f68";
	err |= test_sha1(vector50, len50, digest50);

	size_t len51 = 50;
	const char vector51[] = {'\xe4','\x2a','\x67','\x36','\x2a','\x58','\x1e','\x8c','\xf3','\xd8','\x47','\x50','\x22','\x15','\x75','\x5d','\x7a','\xd4','\x25','\xca','\x03','\x0c','\x43','\x60','\xb0','\xf7','\xef','\x51','\x3e','\x69','\x80','\x26','\x5f','\x61','\xc9','\xfa','\x18','\xdd','\x9c','\xe6','\x68','\xf3','\x8d','\xbc','\x2a','\x1e','\xf8','\xf8','\x3c','\xd6',};
	const char *digest51 = "0e6730bc4a0e9322ea205f4edfff1fffda26af0a";
	err |= test_sha1(vector51, len51, digest51);

	size_t len52 = 51;
	const char vector52[] = {'\x63','\x4d','\xb9','\x2c','\x22','\x01','\x0e','\x1c','\xbf','\x1e','\x16','\x23','\x92','\x31','\x80','\x40','\x6c','\x51','\x52','\x72','\x20','\x9a','\x8a','\xcc','\x42','\xde','\x05','\xcc','\x2e','\x96','\xa1','\xe9','\x4c','\x1f','\x9f','\x6b','\x93','\x23','\x4b','\x7f','\x4c','\x55','\xde','\x8b','\x19','\x61','\xa3','\xbf','\x35','\x22','\x59',};
	const char *digest52 = "b61a3a6f42e8e6604b93196c43c9e84d5359e6fe";
	err |= test_sha1(vector52, len52, digest52);

	size_t len53 = 52;
	const char vector53[] = {'\xcc','\x6c','\xa3','\xa8','\xcb','\x39','\x1c','\xd8','\xa5','\xaf','\xf1','\xfa','\xa7','\xb3','\xff','\xbd','\xd2','\x1a','\x5a','\x3c','\xe6','\x6c','\xfa','\xdd','\xbf','\xe8','\xb1','\x79','\xe4','\xc8','\x60','\xbe','\x5e','\xc6','\x6b','\xd2','\xc6','\xde','\x6a','\x39','\xa2','\x56','\x22','\xf9','\xf2','\xfc','\xb3','\xfc','\x05','\xaf','\x12','\xb5',};
	const char *digest53 = "32d979ca1b3ed0ed8c890d99ec6dd85e6c16abf4";
	err |= test_sha1(vector53, len53, digest53);

	size_t len54 = 53;
	const char vector54[] = {'\x7c','\x0e','\x6a','\x0d','\x35','\xf8','\xac','\x85','\x4c','\x72','\x45','\xeb','\xc7','\x36','\x93','\x73','\x1b','\xbb','\xc3','\xe6','\xfa','\xb6','\x44','\x46','\x6d','\xe2','\x7b','\xb5','\x22','\xfc','\xb9','\x93','\x07','\x12','\x6a','\xe7','\x18','\xfe','\x8f','\x00','\x74','\x2e','\x6e','\x5c','\xb7','\xa6','\x87','\xc8','\x84','\x47','\xcb','\xc9','\x61',};
	const char *digest54 = "6f18190bd2d02fc93bce64756575cea36d08b1c3";
	err |= test_sha1(vector54, len54, digest54);

	size_t len55 = 54;
	const char vector55[] = {'\xc5','\x58','\x1d','\x40','\xb3','\x31','\xe2','\x40','\x03','\x90','\x1b','\xd6','\xbf','\x24','\x4a','\xca','\x9e','\x96','\x01','\xb9','\xd8','\x12','\x52','\xbb','\x38','\x04','\x86','\x42','\x73','\x1f','\x11','\x46','\xb8','\xa4','\xc6','\x9f','\x88','\xe1','\x48','\xb2','\xc8','\xf8','\xc1','\x4f','\x15','\xe1','\xd6','\xda','\x57','\xb2','\xda','\xa9','\x99','\x1e',};
	const char *digest55 = "68f525feea1d8dbe0117e417ca46708d18d7629a";
	err |= test_sha1(vector55, len55, digest55);

	size_t len56 = 55;
	const char vector56[] = {'\xec','\x6b','\x4a','\x88','\x71','\x3d','\xf2','\x7c','\x0f','\x2d','\x02','\xe7','\x38','\xb6','\x9d','\xb4','\x3a','\xbd','\xa3','\x92','\x13','\x17','\x25','\x9c','\x86','\x4c','\x1c','\x38','\x6e','\x9a','\x5a','\x3f','\x53','\x3d','\xc0','\x5f','\x3b','\xee','\xb2','\xbe','\xc2','\xaa','\xc8','\xe0','\x6d','\xb4','\xc6','\xcb','\x3c','\xdd','\xcf','\x69','\x7e','\x03','\xd5',};
	const char *digest56 = "a7272e2308622ff7a339460adc61efd0ea8dabdc";
	err |= test_sha1(vector56, len56, digest56);

	size_t len57 = 56;
	const char vector57[] = {'\x03','\x21','\x73','\x6b','\xeb','\xa5','\x78','\xe9','\x0a','\xbc','\x1a','\x90','\xaa','\x56','\x15','\x7d','\x87','\x16','\x18','\xf6','\xde','\x0d','\x76','\x4c','\xc8','\xc9','\x1e','\x06','\xc6','\x8e','\xcd','\x3b','\x9d','\xe3','\x82','\x40','\x64','\x50','\x33','\x84','\xdb','\x67','\xbe','\xb7','\xfe','\x01','\x22','\x32','\xda','\xca','\xef','\x93','\xa0','\x00','\xfb','\xa7',};
	const char *digest57 = "aef843b86916c16f66c84d83a6005d23fd005c9e";
	err |= test_sha1(vector57, len57, digest57);

	size_t len58 = 57;
	const char vector58[] = {'\xd0','\xa2','\x49','\xa9','\x7b','\x5f','\x14','\x86','\x72','\x1a','\x50','\xd4','\xc4','\xab','\x3f','\x5d','\x67','\x4a','\x0e','\x29','\x92','\x5d','\x5b','\xf2','\x67','\x8e','\xf6','\xd8','\xd5','\x21','\xe4','\x56','\xbd','\x84','\xaa','\x75','\x53','\x28','\xc8','\x3f','\xc8','\x90','\x83','\x77','\x26','\xa8','\xe7','\x87','\x7b','\x57','\x0d','\xba','\x39','\x57','\x9a','\xab','\xdd',};
	const char *digest58 = "be2cd6f380969be59cde2dff5e848a44e7880bd6";
	err |= test_sha1(vector58, len58, digest58);

	size_t len59 = 58;
	const char vector59[] = {'\xc3','\x21','\x38','\x53','\x11','\x18','\xf0','\x8c','\x7d','\xcc','\x29','\x24','\x28','\xad','\x20','\xb4','\x5a','\xb2','\x7d','\x95','\x17','\xa1','\x84','\x45','\xf3','\x8b','\x8f','\x0c','\x27','\x95','\xbc','\xdf','\xe3','\xff','\xe3','\x84','\xe6','\x5e','\xcb','\xf7','\x4d','\x2c','\x9d','\x0d','\xa8','\x83','\x98','\x57','\x53','\x26','\x07','\x49','\x04','\xc1','\x70','\x9b','\xa0','\x72',};
	const char *digest59 = "e5eb4543deee8f6a5287845af8b593a95a9749a1";
	err |= test_sha1(vector59, len59, digest59);

	size_t len60 = 59;
	const char vector60[] = {'\xb0','\xf4','\xcf','\xb9','\x39','\xea','\x78','\x5e','\xab','\xb7','\xe7','\xca','\x7c','\x47','\x6c','\xdd','\x9b','\x22','\x7f','\x01','\x5d','\x90','\x53','\x68','\xba','\x00','\xae','\x96','\xb9','\xaa','\xf7','\x20','\x29','\x74','\x91','\xb3','\x92','\x12','\x67','\x57','\x6b','\x72','\xc8','\xf5','\x8d','\x57','\x76','\x17','\xe8','\x44','\xf9','\xf0','\x75','\x9b','\x39','\x9c','\x6b','\x06','\x4c',};
	const char *digest60 = "534c850448dd486787b62bdec2d4a0b140a1b170";
	err |= test_sha1(vector60, len60, digest60);

	size_t len61 = 60;
	const char vector61[] = {'\xbd','\x02','\xe5','\x1b','\x0c','\xf2','\xc2','\xb8','\xd2','\x04','\xa0','\x26','\xb4','\x1a','\x66','\xfb','\xfc','\x2a','\xc3','\x7e','\xe9','\x41','\x1f','\xc4','\x49','\xc8','\xd1','\x19','\x4a','\x07','\x92','\xa2','\x8e','\xe7','\x31','\x40','\x7d','\xfc','\x89','\xb6','\xdf','\xc2','\xb1','\x0f','\xaa','\x27','\x72','\x3a','\x18','\x4a','\xfe','\xf8','\xfd','\x83','\xde','\xf8','\x58','\xa3','\x2d','\x3f',};
	const char *digest61 = "6fbfa6e4edce4cc85a845bf0d228dc39acefc2fa";
	err |= test_sha1(vector61, len61, digest61);

	size_t len62 = 61;
	const char vector62[] = {'\xe3','\x31','\x46','\xb8','\x3e','\x4b','\xb6','\x71','\x39','\x22','\x18','\xda','\x9a','\x77','\xf8','\xd9','\xf5','\x97','\x41','\x47','\x18','\x2f','\xb9','\x5b','\xa6','\x62','\xcb','\x66','\x01','\x19','\x89','\xc1','\x6d','\x9a','\xf1','\x04','\x73','\x5d','\x6f','\x79','\x84','\x1a','\xa4','\xd1','\xdf','\x27','\x66','\x15','\xb5','\x01','\x08','\xdf','\x8a','\x29','\xdb','\xc9','\xde','\x31','\xf4','\x26','\x0d',};
	const char *digest62 = "018872691d9b04e8220e09187df5bc5fa6257cd9";
	err |= test_sha1(vector62, len62, digest62);

	size_t len63 = 62;
	const char vector63[] = {'\x41','\x1c','\x13','\xc7','\x50','\x73','\xc1','\xe2','\xd4','\xb1','\xec','\xf1','\x31','\x39','\xba','\x96','\x56','\xcd','\x35','\xc1','\x42','\x01','\xf1','\xc7','\xc6','\xf0','\xee','\xb5','\x8d','\x2d','\xbf','\xe3','\x5b','\xfd','\xec','\xcc','\x92','\xc3','\x96','\x1c','\xfa','\xbb','\x59','\x0b','\xc1','\xeb','\x77','\xea','\xc1','\x57','\x32','\xfb','\x02','\x75','\x79','\x86','\x80','\xe0','\xc7','\x29','\x2e','\x50',};
	const char *digest63 = "d98d512a35572f8bd20de62e9510cc21145c5bf4";
	err |= test_sha1(vector63, len63, digest63);

	size_t len64 = 63;
	const char vector64[] = {'\xf2','\xc7','\x6e','\xf6','\x17','\xfa','\x2b','\xfc','\x8a','\x4d','\x6b','\xcb','\xb1','\x5f','\xe8','\x84','\x36','\xfd','\xc2','\x16','\x5d','\x30','\x74','\x62','\x95','\x79','\x07','\x9d','\x4d','\x5b','\x86','\xf5','\x08','\x1a','\xb1','\x77','\xb4','\xc3','\xf5','\x30','\x37','\x6c','\x9c','\x92','\x4c','\xbd','\x42','\x1a','\x8d','\xaf','\x88','\x30','\xd0','\x94','\x0c','\x4f','\xb7','\x58','\x98','\x65','\x83','\x06','\x99',};
	const char *digest64 = "9f3ea255f6af95c5454e55d7354cabb45352ea0b";
	err |= test_sha1(vector64, len64, digest64);

	size_t len65 = 64;
	const char vector65[] = {'\x45','\x92','\x7e','\x32','\xdd','\xf8','\x01','\xca','\xf3','\x5e','\x18','\xe7','\xb5','\x07','\x8b','\x7f','\x54','\x35','\x27','\x82','\x12','\xec','\x6b','\xb9','\x9d','\xf8','\x84','\xf4','\x9b','\x32','\x7c','\x64','\x86','\xfe','\xae','\x46','\xba','\x18','\x7d','\xc1','\xcc','\x91','\x45','\x12','\x1e','\x14','\x92','\xe6','\xb0','\x6e','\x90','\x07','\x39','\x4d','\xc3','\x3b','\x77','\x48','\xf8','\x6a','\xc3','\x20','\x7c','\xfe',};
	const char *digest65 = "a70cfbfe7563dd0e665c7c6715a96a8d756950c0";
	err |= test_sha1(vector65, len65, digest65);

	return err;
}

int main(void)
{
	return sha1();
}
