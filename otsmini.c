
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "ots.h"
#include "mini.h"
#include "short_types.h"
#include "base58.h"
#include "util.h"
#include "varint.h"
#include "compiler.h"
#include "print.h"
#include "encoder.h"

#define streq(a, b) strcmp(a, b) == 0

static u8 buf[32768];
static u8 buf2[32768];
static char strbuf[4096];

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

UNUSED static void print_cb(struct token *token)
{
	print_token(token, stderr);
}

static void ots_encode_cb(struct token *token)
{
	struct encoder *e =
		(struct encoder *)token->user_data;

	print_token(token, stderr);

	switch (token->type) {
	case TOK_VERSION:
		writebuf(e, ots_proof_magic, sizeof(ots_proof_magic));
		break;
	case TOK_FILEHASH:
		break;
	case TOK_TIMESTAMP:
		break;
	case TOK_OP:
		break;
	case TOK_ATTESTATION:
		break;
	}
}	

static int handle_decode(const char *mini, FILE *encode_fd)
{
	size_t written;
	int res;

	res = wally_base58_to_bytes(mini, 0, buf, sizeof(buf), &written);
	if (res != WALLY_OK)
		fail(1, "base58 decode failed");

	struct encoder encoder = {
		.buf = buf2,
		.buflen = sizeof(buf2),
		.cursor = buf2,
	};

	res = parse_ots_mini(buf, written, ots_encode_cb, &encoder);
	if (res != DECODER_PARSE_OK)
		fail(2, "otsmini decode failed");

	written = encoder.cursor - encoder.buf;
	debug("written: %zu\n", written);
	fwrite(encoder.buf, written, 1, encode_fd);
	return res;
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
	FILE *encode_fd = stdout;
	char *filename = NULL;
	bool decode = false;
	size_t len;
	int res;
	struct mini_options options = {
		.upgraded = false,
		.strip_filehash = true,
	};

	if (argc == 2 && (streq(argv[1], "-h") || streq(argv[1], "--help")))
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

	if (decode) {
		res = read_file_or_stdin(filename, (u8*)strbuf, sizeof(strbuf), &len);
		strbuf[len-1] = 0;

		if (res == 0)
			fail(1, "input too large");

		res = handle_decode(strbuf, encode_fd);
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
