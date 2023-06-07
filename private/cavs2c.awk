#!/usr/bin/awk -f
# $NetBSD: cavs2c.awk,v 1.0 2023/06/06 16:12:53 cyphar Exp $

# Copyright (c) 2023 Aleksa Sarai <cyphar@cyphar.com>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# cavs2c - convert a NIST CAVS .rsp file into test vectors to be used in this project
#
# usage: ./cavs2c.awk -v name=digestname < sha-test-vectors/DigestFooBar.rsp
#
# You can download the set of sha test vectors from the NIST website:
#  <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program>
# This script was only tested with the CAVS 11.0 files.

BEGIN {
	print "int " name "(void)"
	print "{"
	print "\tint err = 0;"
	print ""
}

/^Len =/ {
	printf("\tsize_t len%d = %d;\n", ++vecnum, $3 / 8)
}

/^Msg =/ {
	printf("\tconst char vector%d[] = {%s};\n", vecnum, gensub(/([0-9a-f]{2})/, "'\\\\x\\1',", "g", $3))
}

/^MD =/ {
	printf("\tconst char *digest%d = \"%s\";\n", vecnum, $3)
	printf("\terr |= test_%s(vector%d, len%d, digest%d);\n", name, vecnum, vecnum, vecnum)
	print ""
}

END {
	print "\treturn err;"
	print "}"
}
