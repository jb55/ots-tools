
#include "mini.h"
#include "util.h"
#include "compiler.h"
#include <stdio.h>
#include <assert.h>

int main(int argc UNUSED, char *argv[] UNUSED)
{
	static u8 buf[32768];
	size_t len;
	int outlen;
	enum mini_res res;
	const u8 ver = 0x01;

	struct mini_options options = {
		.upgraded = false,
		.strip_filehash = true,
	};

	u8 *proof = file_contents("test/test1.ots", &len);

	res = encode_ots_mini(&options, proof, len, buf, sizeof(buf), &outlen);
	assert(res == MINI_OK);
	assert(buf[0] == 'o' && buf[1] == 't' && buf[2] == 's');
	assert(buf[3] == (0x80 | ver)); // 0x80 is set when strip_filehash = true
	assert(outlen == 72);

	options.upgraded = true;
	options.strip_filehash = false;
	res = encode_ots_mini(&options, proof, len, buf, sizeof(buf), &outlen);
	assert(res == MINI_OK);
	assert(buf[3] == ver); // 0x80 isnt set when strip_filehash = false
	assert(outlen > 100);

	free(proof);


	return 0;
}
