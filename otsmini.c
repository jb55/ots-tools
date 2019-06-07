
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

int main(int argc, char *argv[])
{
	static u8 buf[32768];
	size_t len;
	int outlen;
	char *filename = NULL;
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
		else
			filename = argv[i];
	}

	if (filename == NULL)
		usage();

	u8 *proof = file_contents(filename, &len);
	encode_fd = stdout;

	enum mini_res res =
		ots_mini_encode(&options, proof, len, buf, sizeof(buf), &outlen);

	if (res != MINI_OK)
		fail(res, mini_err_msg(res));

	char *out;
	int ok =
		wally_base58_from_bytes(buf, outlen, 0, &out);

	if (ok != WALLY_OK)
		fail(5, "base58 encode failed");

	printf("%s\n", out);

	free(out);
	free(proof);

	return 0;
}
