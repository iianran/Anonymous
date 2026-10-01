/* Header: minimal scaffolding (struct berval/macros/stubs), function bodies taken verbatim from ldap_extracted.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
typedef unsigned long ber_len_t;
typedef struct berval { ber_len_t bv_len; char *bv_val; } BerValue;
#define LDAP_INVALID_SYNTAX 0x15
#define STRLENOF(s) (sizeof(s)-1)
#define ASCII_DIGIT(c) (((c) >= '0') && ((c) <= '9'))
#define ASCII_HEXLOWER(c) ( (c) >= 'a' && (c) <= 'f' )
#define ASCII_HEXUPPER(c) ( (c) >= 'A' && (c) <= 'F' )
#define ASCII_HEX(c) ( ASCII_DIGIT(c) || ASCII_HEXLOWER(c) || ASCII_HEXUPPER(c) )
#define Debug(l,f,...) do{}while(0)
static void slap_sl_free(void *p, void *ctx) { free(p); }
static void *slap_sl_malloc(ber_len_t size, void *ctx) { return malloc(size); }
static void ber_dupbv_x(struct berval *dst, const struct berval *src, void *ctx) {
    dst->bv_len = src->bv_len; dst->bv_val = slap_sl_malloc(src->bv_len+1, ctx);
    memcpy(dst->bv_val, src->bv_val, src->bv_len); dst->bv_val[src->bv_len]=0;
}
static char *ber_bvchr(struct berval *bv, char c) {
    char *p = memchr(bv->bv_val, c, bv->bv_len); return p ? p : (char*)0;
}
#define BER_BVISNULL(bv) ((bv)->bv_val == NULL)
static int dnValidate(void *sy, struct berval *in) { return 0; }
typedef struct Syntax { const char *ssyn_oid; } Syntax;
#include "ldap_extracted.c"
int main(int argc, char **argv) {
    const char *s = (argc > 1) ? argv[1] : "{ issuer \"a\"\"}";
    struct berval in;
    in.bv_len = strlen(s);
    in.bv_val = malloc(in.bv_len);        /* exact size, no NUL -- berval semantics */
    memcpy(in.bv_val, s, in.bv_len);
    Syntax syn = {0};
    int rc = serialNumberAndIssuerValidate(&syn, &in);
    printf("validate rc=%d\n", rc);
    free(in.bv_val);
    return 0;
}
