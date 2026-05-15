/*
 * Copyright (c) 2025 Benjamin Coddington <bcodding@hammerspace.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <uuid/uuid.h>

#include "nfslib.h"

#define HASH_BLOCKSIZE  256
int hash_fh_key_file(const char *fh_key_file, uuid_t uuid)
{
	const char seed_s[] = "8fc57f1b-1a6f-482f-af92-d2e007c1ae58";
	FILE *sfile = NULL;
	char buf[HASH_BLOCKSIZE];
	int ret = 0;
	size_t sread;

	sfile = fopen(fh_key_file, "r");
	if (!sfile) {
		ret = errno;
		xlog(L_ERROR, "Unable to read fh-key-file %s: %s", fh_key_file, strerror(errno));
		return ret;
	}

	uuid_parse(seed_s, uuid);

	// Read until EOF or error
	while ((sread = fread(buf, 1, HASH_BLOCKSIZE, sfile)) > 0) {
		uuid_generate_sha1(uuid, uuid, buf, sread);
	}

	if (ferror(sfile)) {
		ret = errno ? errno : EIO; // Ensure we return a real error code
		xlog(L_ERROR, "Error reading fh-key-file %s: %s", fh_key_file, strerror(ret));
	}

	fclose(sfile);
	return ret;
}
