#!/bin/bash

# Bail on error
set -e

# Clean up
echo ">>> cleaning up..." 1>&2
if test -d libnbcompat-[0-9].[0-9].[0-9]; then
    chmod -R u+w libnbcompat-[0-9].[0-9].[0-9]
fi
find . -type d -name .deps -print0 | xargs -0 rm -fr
rm -rf  \
    aclocal.m4 \
    autom4te.cache \
    btree \
    config/* \
    config.guess \
    config.log \
    config.status \
    config.sub \
    configure \
    hash \
    libnbcompat-[0-9].[0-9].[0-9] \
    libnbcompat-[0-9].[0-9].[0-9].tar.gz \
    libnbcompat.la \
    .libs \
    libtool \
    *.lo \
    m4/libtool.m4 \
    m4/lt~obsolete.m4 \
    m4/ltoptions.m4 \
    m4/ltsugar.m4 \
    m4/ltversion.m4 \
    Makefile \
    Makefile.in \
    mpool \
    nbcompat/nbconfig.h* \
    nbcompat/stamp-h1 \
    *.o \
    recno

if [ "$1" = '-n' ]; then
    exit 0
fi

# Regnenerate
echo ">>> applying autotools..." 1>&2
autoreconf -vfi -I .

if [ "$1" != '-c' ]; then
    exit 0
fi

# Reconfigure
echo ">>> running ./configure script..." 1>&2
./configure --libdir=/usr/lib64
