
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "ots.h"
#include "mini.h"
#include "short_types.h"
#include "base58.h"
#include "util.h"
#include "varint.h"

#define streq(a, b) strcmp(a, b) == 0


static void fail(int err, const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(err);
}

static FILE *encode_fd;

static void assertok(enum decoder_state res)
{
	if (res != DECODER_PARSE_OK) {
		printf("error: %s, %s\n", describe_parse_state(res),
		       decoder_errmsg);
		exit(1);
	}
}

void usage()
{
	printf("usage: otsmini [--upgraded] <proof.ots>\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	size_t len = 0;
	static u8 buf[32768];
	char *filename = NULL;
	enum decoder_state res;

	struct token_search search = {
		.done = false,
		.att_token_start = -1,
		.att_candidate_payload_size = 0,
		.att_payload_size = 0,
		.upgraded = false,
		.tokindex = 0,
	};

	struct encoder encoder = {
		.attest_loc = &search,
		.strip_filehash = false,
		.has_ts = false,
		.buf = buf,
		.buflen = sizeof(buf),
		.cursor = buf,
	};

	if (argc < 2)
		usage();

	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--upgraded"))
			search.upgraded = true;
		else if (streq(argv[i], "--no-filehash"))
			encoder.strip_filehash = true;
		else
			filename = argv[i];
	}

	if (filename == NULL)
		usage();

	u8 *proof = file_contents(filename, &len);
	encode_fd = stdout;

	res = parse_ots_proof(proof, len, ots_mini_find, &search);
	assertok(res);

	search.done = search.done || search.att_token_start_candidate != 0;

	if (!search.done) {
		if (search.upgraded)
			fail(2, "ots file is not an upgraded timestamp");
		else
			fail(2, "no non-upgraded attestation not found, try --upgraded");
	}

	search.tokindex = 0;
	search.done = false;

	res = parse_ots_proof(proof, len, ots_mini_encode, &encoder);
	assertok(res);

	char *out;
	int ok =
		wally_base58_from_bytes(encoder.buf,
					encoder.cursor - encoder.buf,
					0, &out);

	if (ok != WALLY_OK)
		fail(5, "base58 encode failed");

	printf("%s\n", out);

	free(out);
	free(proof);

	return 0;
}
