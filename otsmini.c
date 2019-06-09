
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "ots.h"
#include "ots_internal.h"
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
	printf("usage: otsmini [--upgraded,--no-filehash] <proof.ots>\n");
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
		return "calendar attestation not found";
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
	const u8 *tag;
	int len;
	struct mini_ots_encoder *ots_encoder =
		(struct mini_ots_encoder *)token->user_data;

	struct encoder *e = ots_encoder->encoder;

	/* print_token(token, stderr); */

	switch (token->type) {
	case TOK_VERSION:
		writebuf(e, ots_proof_magic, sizeof(ots_proof_magic));
		writebuf(e, &token->data.version.number, 1);
		if (!token->data.version.has_filehash &&
		    ots_encoder->options->filehash.datalen == 0) {
			fail(2, "filehash not found, please provide --filehash");
		}

		if (!token->data.version.has_filehash) {
			debug("writing miniots -> ots filehash\n");
			assert(ots_encoder->options->filehash.datalen != 0);
		}

		break;
	case TOK_TIMESTAMP:
		// TODO: rename this to TOK_FORK
		// we don't need a fork if we're only returning 1
		/* writebuf(e, (u8*)&"\xff", 1); */
		break;
	case TOK_OP:
		if (token->data.op.class == OP_CLS_CRYPTO) {
			writebuf(e, (u8*)&token->data.op.crypto.op, 1);
			// TODO: refactor this logic, it's a bit hairy
			// since we might not have a TOK_FILEHASH in
			// the original file, we have to shimmy in it here.
			if (!ots_encoder->filehash_done) {
				if (token->data.op.crypto.datalen) {
					debug("crypto datalen %d\n", token->data.op.crypto.datalen);
					writebuf(e, token->data.op.crypto.cryptodata.sha1,
						 token->data.op.crypto.datalen);
				}
				else {
					writebuf(e, (u8*)&ots_encoder->options->filehash.cryptodata,
						 ots_encoder->options->filehash.datalen);
				}


				ots_encoder->filehash_done = true;
			}
		}
		else if (token->data.op.class == OP_CLS_BINARY) {
			writebuf(e, (u8*)&token->data.op.binary.op, 1);
			writebuf_varint(e, token->data.op.binary.data_len);
			writebuf(e, token->data.op.binary.bindata,
				token->data.op.binary.data_len);
		}
		else if (token->data.op.class == OP_CLS_UNARY) {
			writebuf(e, (u8*)&token->data.op.unary_op, 1);
		}

		break;
	case TOK_ATTESTATION:
		tag = get_attestation_tag(token->data.attestation.type, &len);
		writebuf(e, (u8*)&"\0", 1);
		writebuf(e, tag, len);
		writebuf_varint(e, token->data.attestation.raw_data_len);
		writebuf(e, token->data.attestation.raw_data,
			 token->data.attestation.raw_data_len);

		break;
	case TOK_FILEHASH:
		debug("ots_encode filehash\n");
		break;
	}
}

static int handle_decode(struct mini_options *opts, const char *mini, FILE *encode_fd)
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

	struct mini_ots_encoder ots_encoder = {
		.options = opts,
		.encoder = &encoder,
		.filehash_done = false,
	};

	res = parse_ots_mini(buf, written, ots_encode_cb, &ots_encoder);
	if (res != DECODER_PARSE_OK)
		fail(2, "otsmini decode failed");

	written = encoder.cursor - encoder.buf;
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

static int parse_filehash(const char *hex, struct crypto *hash)
{
	if (strlen(hex) != 64)
		fail(1, "only sha256 hashes are supported by --filehash at the moment");
	hash->op = OP_SHA256;
	hash->datalen = 32;
	return hex_decode(hex, strlen(hex), &hash->cryptodata, sizeof(hash->cryptodata));
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
		.strip_filehash = false,
	};

	options.filehash.datalen = 0;

	if (argc == 2 && (streq(argv[1], "-h") || streq(argv[1], "--help")))
		usage();

	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--upgraded"))
			options.upgraded = true;
		else if (streq(argv[i], "--no-filehash"))
			options.strip_filehash = true;
		else if (streq(argv[i], "--filehash"))
			parse_filehash(argv[(i++)+1], &options.filehash);
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

		res = handle_decode(&options, strbuf, encode_fd);
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
