/*
 * nfs-fh-verify - Verify NFS filehandle signatures produced by knfsd.
 *
 * Reads filehandles in ASCII hex from stdin (one per line) and, using a
 * filehandle signing key file, reports whether the trailing 8-byte
 * SipHash-2-4 MAC verifies under that key.
 *
 * Mirrors the kernel signing layout in fs/nfsd/nfsfh.c (commit 2a83ffc55750)
 * and the key derivation in support/nfs/fh_key_file.c.
 */
#include "config.h"

#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <uuid/uuid.h>

#include "nfslib.h"
#include "xlog.h"

#define FH_MAC_LEN	8
#define FH_MAX_LEN	128	/* NFSv3=64, NFSv4=128 */

/*
 * SipHash-2-4. Matches lib/siphash.c in the kernel byte-for-byte:
 * 2 compression rounds per 64-bit block, 4 finalization rounds, length
 * in the high byte of the final word, output v0^v1^v2^v3.
 */
static inline uint64_t rotl64(uint64_t x, int b)
{
	return (x << b) | (x >> (64 - b));
}

#define SIPROUND do {							\
	v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);	\
	v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;			\
	v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;			\
	v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);	\
} while (0)

static uint64_t load_le64(const uint8_t *p)
{
	return  (uint64_t)p[0]        | ((uint64_t)p[1] <<  8) |
	       ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static uint64_t siphash24(const uint8_t *data, size_t len,
			  uint64_t k0, uint64_t k1)
{
	uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
	uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
	uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
	uint64_t v3 = 0x7465646279746573ULL ^ k1;
	uint64_t b = ((uint64_t)len) << 56;
	const uint8_t *end = data + (len & ~(size_t)7);
	size_t left = len & 7;
	uint64_t m;

	for (; data != end; data += 8) {
		m = load_le64(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}

	switch (left) {
	case 7: b |= ((uint64_t)data[6]) << 48; /* fallthrough */
	case 6: b |= ((uint64_t)data[5]) << 40; /* fallthrough */
	case 5: b |= ((uint64_t)data[4]) << 32; /* fallthrough */
	case 4: b |= ((uint64_t)data[3]) << 24; /* fallthrough */
	case 3: b |= ((uint64_t)data[2]) << 16; /* fallthrough */
	case 2: b |= ((uint64_t)data[1]) <<  8; /* fallthrough */
	case 1: b |= ((uint64_t)data[0]);
		break;
	case 0:
		break;
	}

	v3 ^= b;
	SIPROUND;
	SIPROUND;
	v0 ^= b;
	v2 ^= 0xff;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	return v0 ^ v1 ^ v2 ^ v3;
}

/*
 * Two well-known SipHash-2-4 reference vectors (Aumasson/Bernstein) with
 * key = bytes 0x00..0x0f. Verifies the embedded implementation at startup;
 * if this fails we refuse to run rather than emit wrong verdicts.
 */
static int siphash_self_test(void)
{
	static const uint8_t key[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	static const uint8_t msg15[15] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	};
	uint64_t k0 = load_le64(key);
	uint64_t k1 = load_le64(key + 8);
	uint64_t got;

	got = siphash24(NULL, 0, k0, k1);
	if (got != 0x726fdb47dd0e0e31ULL) {
		fprintf(stderr,
			"nfs-fh-verify: siphash self-test failed (len=0): %016lx\n",
			(unsigned long)got);
		return -1;
	}
	got = siphash24(msg15, sizeof(msg15), k0, k1);
	if (got != 0xa129ca6149be45e5ULL) {
		fprintf(stderr,
			"nfs-fh-verify: siphash self-test failed (len=15): %016lx\n",
			(unsigned long)got);
		return -1;
	}
	return 0;
}

/*
 * Parse one filehandle line into a byte buffer.
 *
 * Accepts: optional "0x" prefix; hex pairs optionally separated by ':' or
 * whitespace; '#' starts a comment; blank lines yield len=0.
 *
 * Returns 0 on success and sets *len, or -1 with errno set on bad input.
 */
static int parse_hex_fh(const char *line, uint8_t *out, size_t max,
			size_t *len)
{
	const char *p = line;
	size_t n = 0;
	int hi = -1;

	while (*p && isspace((unsigned char)*p))
		p++;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;

	for (; *p; p++) {
		unsigned char c = (unsigned char)*p;
		int v;

		if (c == '#' || c == '\n' || c == '\r')
			break;
		if (isspace(c) || c == ':')
			continue;

		if (c >= '0' && c <= '9')
			v = c - '0';
		else if (c >= 'a' && c <= 'f')
			v = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			v = c - 'A' + 10;
		else {
			errno = EINVAL;
			return -1;
		}

		if (hi < 0) {
			hi = v;
		} else {
			if (n >= max) {
				errno = E2BIG;
				return -1;
			}
			out[n++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
	}

	if (hi >= 0) {
		errno = EINVAL;	/* odd nibble count */
		return -1;
	}
	*len = n;
	return 0;
}

static void print_hex(FILE *f, const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		fprintf(f, "%02x", buf[i]);
}

static void usage(FILE *f, const char *prog)
{
	fprintf(f,
"Usage: %s -k <fh-key-file> [-q] [-v]\n"
"\n"
"  Reads NFS filehandles in ASCII hex from stdin, one per line, and\n"
"  reports whether each filehandle's trailing 8-byte SipHash-2-4 MAC\n"
"  verifies under the key derived from <fh-key-file>.\n"
"\n"
"Options:\n"
"  -k FILE   Filehandle signing key file (same file passed to nfsdctl).\n"
"  -q        Quiet: print just OK/BAD/MALFORMED per line.\n"
"  -v        Verbose: also print computed MAC and trailing MAC bytes.\n"
"  -h        Show this help.\n"
"\n"
"Input format:\n"
"  Hex chars per filehandle, one filehandle per line. Optional \"0x\"\n"
"  prefix; ':' and whitespace between hex pairs ignored; '#' starts a\n"
"  comment; blank lines are skipped.\n"
"\n"
"Exit status:\n"
"  0  every parsed filehandle verified OK\n"
"  1  any BAD or MALFORMED verdict\n"
"  2  setup error (key file unreadable, bad usage, etc.)\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *keyfile = NULL;
	bool quiet = false;
	bool verbose = false;
	uuid_t key_uuid;
	uint64_t k0, k1;
	char *line = NULL;
	size_t cap = 0;
	ssize_t nread;
	int rc, opt;
	int saw_bad = 0;

	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open("nfs-fh-verify");

	while ((opt = getopt(argc, argv, "k:qvh")) != -1) {
		switch (opt) {
		case 'k': keyfile = optarg; break;
		case 'q': quiet = true; break;
		case 'v': verbose = true; break;
		case 'h': usage(stdout, argv[0]); return 0;
		default:  usage(stderr, argv[0]); return 2;
		}
	}
	if (!keyfile) {
		fprintf(stderr, "nfs-fh-verify: -k <fh-key-file> is required\n");
		usage(stderr, argv[0]);
		return 2;
	}
	if (optind != argc) {
		fprintf(stderr, "nfs-fh-verify: unexpected positional argument\n");
		return 2;
	}

	if (siphash_self_test() != 0)
		return 2;

	rc = hash_fh_key_file(keyfile, key_uuid);
	if (rc != 0) {
		/* hash_fh_key_file() already logged via xlog */
		return 2;
	}

	k0 = load_le64(key_uuid);
	k1 = load_le64(key_uuid + 8);

	if (verbose) {
		char ustr[37];
		uuid_unparse(key_uuid, ustr);
		fprintf(stderr, "key uuid: %s  k0=%016lx k1=%016lx\n",
			ustr, (unsigned long)k0, (unsigned long)k1);
	}

	while ((nread = getline(&line, &cap, stdin)) != -1) {
		uint8_t fh[FH_MAX_LEN];
		size_t fh_len = 0;
		const char *verdict;
		uint64_t mac, trailing;

		if (parse_hex_fh(line, fh, sizeof(fh), &fh_len) != 0) {
			saw_bad = 1;
			if (!quiet)
				fputs(line, stdout);
			printf("MALFORMED (%s)\n",
			       errno == E2BIG ? "filehandle too long"
					      : "bad hex");
			continue;
		}
		if (fh_len == 0)
			continue;	/* blank/comment line */
		if (fh_len <= FH_MAC_LEN) {
			saw_bad = 1;
			if (!quiet) {
				print_hex(stdout, fh, fh_len);
				putchar(' ');
			}
			printf("MALFORMED (too short for MAC)\n");
			continue;
		}

		mac = siphash24(fh, fh_len - FH_MAC_LEN, k0, k1);
		trailing = load_le64(fh + fh_len - FH_MAC_LEN);
		verdict = (mac == trailing) ? "OK" : "BAD";
		if (verdict[0] == 'B')
			saw_bad = 1;

		if (!quiet) {
			print_hex(stdout, fh, fh_len);
			putchar(' ');
		}
		fputs(verdict, stdout);
		if (verbose)
			printf(" expected=%016lx got=%016lx",
			       (unsigned long)mac, (unsigned long)trailing);
		putchar('\n');
	}

	free(line);
	if (ferror(stdin)) {
		fprintf(stderr, "nfs-fh-verify: error reading stdin: %s\n",
			strerror(errno));
		return 2;
	}
	return saw_bad ? 1 : 0;
}
