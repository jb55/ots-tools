
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "ots.h"
#include "mini.h"
#include "short_types.h"
#include "base58.h"
#include "util.h"
#include "varint.h"
#include "print.h"

#define streq(a, b) strcmp(a, b) == 0

static u8 buf[32768];
static char strbuf[4096];

static void fail(int err, const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(err);
}

static FILE *encode_fd;

void usage()
{
	printf("usage: otsmini [--upgraded,--keep-filehash] <proof.ots>\n");
	exit(1);
}

static const char *mini_err_msg(enum mini_res res)
{
	switch (res) {
	case MINI_OK:
		return NULL;
	case MINI_ERR_OTS_PARSE_FAILED:
		return decoder_errmsg;
	case MINI_ERR_PENDING_NOT_FOUND:
		return "pending attestation not found";
	case MINI_ERR_UPGRADED_NOT_FOUND:
		return "upgraded attestation not found";
	}

	return NULL;
}

static void print_cb(struct token *token) {
	print_token(token);
}

static int handle_decode(const char *mini)
{
	size_t written;
	int res;
	res = wally_base58_to_bytes(mini, 0, buf, sizeof(buf), &written);
	if (res != WALLY_OK)
		fail(1, "base58 decode failed");

	return parse_ots_mini(buf, written, print_cb, NULL);
}

static int handle_encode(struct mini_options *options, const u8 *proof,
			 int prooflen)
{
	int outlen;

	enum mini_res res =
		encode_ots_mini(options, proof, prooflen, buf, sizeof(buf), &outlen);

	if (res != MINI_OK)
		fail(res, mini_err_msg(res));

	char *out;
	int ok =
		wally_base58_from_bytes(buf, outlen, 0, &out);

	if (ok != WALLY_OK)
		fail(5, "base58 encode failed");

	printf("%s\n", out);
	free(out);

	return res;
}

static void assertok(enum decoder_state res)
{
	if (res != DECODER_PARSE_OK) {
		printf("error: %s, %s\n", describe_parse_state(res),
		       decoder_errmsg);
		exit(1);
	}
}


int main(int argc, char *argv[])
{
	char *filename = NULL;
	bool decode = false;
	size_t len;
	int res;
	struct mini_options options = {
		.upgraded = false,
		.strip_filehash = true,
	};

	if (argc < 2)
		usage();

	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--upgraded"))
			options.upgraded = true;
		else if (streq(argv[i], "--keep-filehash"))
			options.strip_filehash = false;
		else if (streq(argv[i], "-d") || streq(argv[i], "--decode"))
			decode = true;
		else
			filename = argv[i];
	}


	encode_fd = stdout;

	if (decode) {
		res = read_file_or_stdin(filename, (u8*)strbuf, sizeof(strbuf), &len);
		strbuf[len-1] = 0;

		if (res == 0)
			fail(1, "input too large");

		res = handle_decode(strbuf);
		assertok(res);
	}
	else {
		res = read_file_or_stdin(filename, buf, sizeof(buf), &len);

		if (res == 0)
			fail(1, "input too large");

		handle_encode(&options, buf, len);
	}

	return 0;
}
