
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "ots.h"
#include "print.h"
#include "util.h"

static FILE *encode_fd;
#define UNUSED __attribute__((__unused__))

static u8 buf[32768];

static void proof_cb(struct token *token) {
	print_token(token, stdout);
}

int main(int argc UNUSED, char *argv[])
{
	size_t len = 0;
	enum decoder_state res;

	(void)proof_cb;
	read_file_or_stdin(argv[1], buf, sizeof(buf), &len);
	encode_fd = stdout;
	res = parse_ots_proof(buf, sizeof(buf), proof_cb, NULL);

	if (res != DECODER_PARSE_OK) {
		printf("error: %s, %s\n", describe_parse_state(res),
		       decoder_errmsg);
		return 1;
	}

	return 0;
}
