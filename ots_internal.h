
#ifndef OTS_INTERNAL_H
#define OTS_INTERNAL_H

#include "short_types.h"
#include "ots.h"

int parse_op_class(u8 type, enum op_class *class);
int parse_crypto_op_payload(struct cursor *cursor, struct op *op);
int parse_crypto_op_body(struct cursor *cursor, u8 tag, struct op *op);
int consume_op(struct cursor *cursor, u8 tag, struct op *op);
int is_filehash_op(struct token *tok);
const u8 *get_attestation_tag(enum attestation_type at, int *len);

int consume_attestation_body(struct cursor *cursor,
			     struct attestation *attestation,
			     enum attestation_type att_type);


#endif /* OTS_INTERNAL_H */
