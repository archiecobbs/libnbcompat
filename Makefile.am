# vim: noet:sw=8:ts=8:

# This avoids "#include <pwd.h>" including nbcompat/pwd.h, etc.
# See https://stackoverflow.com/a/57418328/263801
DEFAULT_INCLUDES=		-I.@am__isrc@

EXTRA_DIST=			README

lib_LTLIBRARIES=		libnbcompat.la

libnbcompat_la_LDFLAGS=		-version-info $(LIBNBCOMPAT_LT_CURRENT):$(LIBNBCOMPAT_LT_REVISION):$(LIBNBCOMPAT_LT_AGE)

AM_CFLAGS=			-Wall
ACLOCAL_AMFLAGS=		-I m4

EXTRA_libnbcompat_la_DEPENDENCIES:	$(LTLIBOBJS)

# Which files to compile is determined at configure time (see AC_LIBOBJ() invocations in configure.ac)
libnbcompat_la_SOURCES=

# It's bad form to install your "config.h", so we tweak it to make it less harmful
install-data-hook:
	find $(DESTDIR)$(includedir)/nbcompat.h $(DESTDIR)$(includedir)/nbcompat -name '*.h' -print | while read HDRFILE; do \
		echo "fixing up $${HDRFILE}..."; \
		$(SED)	-e '/^#define PACKAGE/d' \
			-e '/^#define VERSION/d' \
			-e 's/HAVE_\([A-Z_]*\)/LIBNBCOMPAT_HAVE_\1/g' \
			< "$${HDRFILE}" > "$${HDRFILE}.new"; \
		mv "$${HDRFILE}.new" "$${HDRFILE}"; \
	done

# This ensures that ALL sources are packages up
EXTRA_libnbcompat_la_SOURCES=	__fts13.c  \
				__glob13.c \
				__unsetenv13.c \
				asprintf.c \
				engine.c \
				err.c \
				fgetln.c \
				findenv.c \
				fnmatch.c \
				fparseln.c \
				fts.c \
				getaddrinfo.c \
				getdelim.c \
				getenv.c \
				getline.c \
				getopt.c \
				getopt_long.c \
				gettemp.c \
				glob.c \
				isblank.c \
				lchflags.c \
				lchmod.c \
				lchown.c \
				lutimes.c \
				md5c.c \
				md5hl.c \
				mdXhl.c \
				mkdtemp.c \
				mkstemp.c \
				poll.c \
				pwcache.c \
				regcomp.c \
				regerror.c \
				regexec.c \
				regfree.c \
				rmd160.c \
				rmd160hl.c \
				setenv.c \
				setgroupent.c \
				setmode.c \
				setpassent.c \
				setprogname.c \
				sha1.c \
				sha1hl.c \
				sha2.c \
				sha2hl.c \
				shquote.c \
				snprintf.c \
				statvfs.c \
				strdup.c \
				strerror.c \
				strlcat.c \
				strlcpy.c \
				strmode.c \
				strnlen.c \
				strsep.c \
				strtoll.c \
				timegm.c \
				unsetenv.c \
				unvis.c \
				usleep.c \
				utimes.c \
				vis.c \
				warn.c

nobase_include_HEADERS=		nbcompat.h \
				nbcompat/assert.h \
				nbcompat/cdefs.h \
				nbcompat/ctype.h \
				nbcompat/dirent.h \
				nbcompat/endian.h \
				nbcompat/err.h \
				nbcompat/fnmatch.h \
				nbcompat/fts.h \
				nbcompat/getopt.h \
				nbcompat/glob.h \
				nbcompat/grp.h \
				nbcompat/limits.h \
				nbcompat/md5.h \
				nbcompat/nbconfig.h \
				nbcompat/netdb.h \
				nbcompat/param.h \
				nbcompat/paths.h \
				nbcompat/poll.h \
				nbcompat/pwd.h \
				nbcompat/queue.h \
				nbcompat/regex.h \
				nbcompat/rmd160.h \
				nbcompat/sha1.h \
				nbcompat/sha2.h \
				nbcompat/stat.h \
				nbcompat/statvfs.h \
				nbcompat/stdbool.h \
				nbcompat/stdio.h \
				nbcompat/stdlib.h \
				nbcompat/string.h \
				nbcompat/termcap.h \
				nbcompat/time.h \
				nbcompat/types.h \
				nbcompat/tzfile.h \
				nbcompat/unistd.h \
				nbcompat/util.h \
				nbcompat/vis.h

noinst_HEADERS=			private/cclass.h \
				private/cname.h \
				private/pwcache.h \
				private/regex2.h \
				private/utils.h

if WITH_DB

libnbcompat_la_SOURCES+=	db/btree/bt_close.c \
				db/btree/bt_conv.c \
				db/btree/bt_debug.c \
				db/btree/bt_delete.c \
				db/btree/bt_get.c \
				db/btree/bt_open.c \
				db/btree/bt_overflow.c \
				db/btree/bt_page.c \
				db/btree/bt_put.c \
				db/btree/bt_search.c \
				db/btree/bt_seq.c \
				db/btree/bt_split.c \
				db/btree/bt_utils.c \
				db/db/db.c \
				db/hash/hash_bigkey.c \
				db/hash/hash_buf.c \
				db/hash/hash.c \
				db/hash/hash_func.c \
				db/hash/hash_log2.c \
				db/hash/hash_page.c \
				db/hash/ndbm.c \
				db/hash/ndbmdatum.c \
				db/mpool/mpool.c \
				db/recno/rec_close.c \
				db/recno/rec_delete.c \
				db/recno/rec_get.c \
				db/recno/rec_open.c \
				db/recno/rec_put.c \
				db/recno/rec_search.c \
				db/recno/rec_seq.c \
				db/recno/rec_utils.c

nobase_include_HEADERS+=	nbcompat/db.h

AM_CFLAGS+=			-D__DBINTERFACE_PRIVATE

endif
