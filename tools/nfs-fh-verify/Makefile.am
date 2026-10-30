## Process this file with automake to produce Makefile.in

sbin_PROGRAMS = nfs-fh-verify
nfs_fh_verify_SOURCES = main.c
nfs_fh_verify_LDADD = ../../support/nfs/libnfs.la

man8_MANS = nfs-fh-verify.man
EXTRA_DIST = $(man8_MANS)

MAINTAINERCLEANFILES = Makefile.in
