// blnk.c
// 07-Dec-13    Markku-Juhani O. Saarinen <mjos@cblnk.com>
//              See LICENSE for Licensing and Warranty information.

// Utilities

#include "blnk.h"

// simple conversions

uint64_t blnk_lbf_getl(stricat_t *cx, int from)
{
    int i;
    uint64_t x;

    sbob_put(&cx->sbx, BLNK_AAD | from, cx->lbf, CBYT_LBUF);
    sbob_fin(&cx->sbx, BLNK_AAD | from);

    x = 0;
    for (i = 0; i < CBYT_LBUF; i++) {
        x += ((uint64_t) cx->lbf[i]) << (8lu * i);
    }

    // handle end code
    if (x == BLNK_TERMINATE) {
        x = 0;
        cx->run = 0;
    }

    return x;
}

void blnk_lbf_putl(stricat_t *cx, uint64_t x, int from)
{
    int i;

    for (i = 0; i < CBYT_LBUF; i++) {
        cx->lbf[i] = x & 0xFF;
        x >>= 8lu;
    }

    sbob_put(&cx->sbx, BLNK_AAD | from, cx->lbf, CBYT_LBUF);
    sbob_fin(&cx->sbx, BLNK_AAD | from);
}

// fill buffer with real random

int blnk_rand(void *buf, int len)
{
    int fd;

    if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
        return CBERRNO;
    if (read(fd, buf, len) != len)
        return CBERRNO;
    close(fd);

    return 0;
}

// blocking send

int block_send(stricat_t *cx, const void *buf, int len)
{
    int i, n;

    for (i = 0; i < len; i += n) {
        n = send(cx->sck, &((const char *) buf)[i], len - i, 0);
        if (n == 0)
            return i;
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                n = 0;
            } else {
                perror("block_send()");
                return i;
            }
        }
    }
    return len;
}

// blocking receive

int block_recv(stricat_t *cx, void *buf, int len)
{
    int i, n;


    for (i = 0; i < len; i += n) {
        n = recv(cx->sck, &((char *) buf)[i], len - i, 0);
        if (n == 0) {   // orderly shutdown
            fprintf(stderr, "Channel shutdown.\n");
            return i;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                n = 0;
            } else {
                perror("block_recv()");
                return i;
            }
        }
        usleep(10000);
    }
 
    return len;
}

// send

int blnk_send(stricat_t *cx, int from, int len)
{
    // encode length
    blnk_lbf_putl(cx, len, from);  
    if (block_send(cx, cx->lbf, CBYT_LBUF) != CBYT_LBUF)
        return CBERRNO;

    // encrypt
    if (len > 0) {
        sbob_enc(&cx->sbx, BLNK_MSG | from, cx->xfr, cx->xfr, len);
        sbob_fin(&cx->sbx, BLNK_MSG | from);
        if (block_send(cx, cx->xfr, len) != len)
            return CBERRNO;
    }
 
    // MAC
    sbob_get(&cx->sbx, BLNK_MAC | from, cx->mac, CBYT_MAC);
    sbob_fin(&cx->sbx, BLNK_MAC | from);
    if (block_send(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;

    return len;
}

// send terminator

int blnk_term(stricat_t *cx, int from)
{
    // set local terminator
    cx->run = 0;

    // ~0 is the terminate signal
    blnk_lbf_putl(cx, BLNK_TERMINATE, from);  
    if (block_send(cx, cx->lbf, CBYT_LBUF) != CBYT_LBUF)
        return CBERRNO;

    // MAC
    sbob_get(&cx->sbx, BLNK_MAC | from, cx->mac, CBYT_MAC);
    sbob_fin(&cx->sbx, BLNK_MAC | from);
    if (block_send(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;

    return 0;
}

// receive

int blnk_recv(stricat_t *cx, int from)
{
    int len;

    // decode length
    len = block_recv(cx, cx->lbf, CBYT_LBUF);
    if (len != CBYT_LBUF) {
        return CBERRNO;
    }
    len = blnk_lbf_getl(cx, from);

    if (len < 0 || len > CBYT_XFER)
        return CBERRNO;

    if (len > 0) {
        if (block_recv(cx, cx->xfr, len) != len)
            return CBERRNO;
        sbob_dec(&cx->sbx, BLNK_MSG | from, cx->xfr, cx->xfr, len);
        sbob_fin(&cx->sbx, BLNK_MSG | from);
    }

    // MAC compare
    if (block_recv(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;
    if (sbob_cmp(&cx->sbx, BLNK_MAC | from, cx->mac, CBYT_MAC) != 0)
        return CBERRNO;
    sbob_fin(&cx->sbx, BLNK_MAC | from);

    return len;
}

// client authentication handshake first messages
// leave own nonce at nnc and alien nonce at xfr, id at idn

int blnk_hand(stricat_t *cx, const uint8_t myid[CBYT_IDNT])
{
    // send id and nonce

    if (myid != NULL) {
        if (block_send(cx, myid, CBYT_IDNT) != CBYT_IDNT)
            return CBERRNO;
    }
    blnk_rand(cx->nnc, CBYT_NPUB);
    if (block_send(cx, cx->nnc, CBYT_NPUB) != CBYT_NPUB)
        return CBERRNO;

    // receive other id and nonce
    if (myid != NULL) {
        if (block_recv(cx, cx->idn, CBYT_IDNT) != CBYT_IDNT)
            return CBERRNO;
    }
    if (block_recv(cx, cx->xfr, CBYT_NPUB) != CBYT_NPUB)
        return CBERRNO;

    return 0;
}

// alice's handshake
int blnk_shake_alice(stricat_t *cx, const uint8_t aliceid[CBYT_IDNT])
{
    sbob_clr(&cx->sbx);

    // identities in
    if (aliceid != NULL) {
        sbob_put(&cx->sbx, BLNK_AAD | BLNK_A2B, aliceid, CBYT_IDNT);
        sbob_fin(&cx->sbx, BLNK_AAD | BLNK_A2B);
        sbob_put(&cx->sbx, BLNK_AAD | BLNK_B2A, cx->idn, CBYT_IDNT);
        sbob_fin(&cx->sbx, BLNK_AAD | BLNK_B2A);
    }

    // nonces in
    sbob_put(&cx->sbx, BLNK_NPUB | BLNK_A2B, cx->nnc, CBYT_NPUB);
    sbob_fin(&cx->sbx, BLNK_NPUB | BLNK_A2B);
    sbob_put(&cx->sbx, BLNK_NPUB | BLNK_B2A, cx->xfr, CBYT_NPUB);
    sbob_fin(&cx->sbx, BLNK_NPUB | BLNK_B2A);

    // load key
    sbob_put(&cx->sbx, BLNK_KEY | BLNK_A2B | BLNK_B2A, cx->key, CBYT_KEY);
    sbob_fin(&cx->sbx, BLNK_KEY | BLNK_A2B | BLNK_B2A);

    // alice generates and sends a mac first
    sbob_get(&cx->sbx, BLNK_MAC | BLNK_A2B, cx->mac, CBYT_MAC);
    sbob_fin(&cx->sbx, BLNK_MAC | BLNK_A2B);
    if (block_send(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;

    // now get bobby's mac and verify
    if (block_recv(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;
    if (sbob_cmp(&cx->sbx, BLNK_MAC | BLNK_B2A, cx->mac, CBYT_MAC) != 0) {
        fprintf(stderr, "blnk_shake_alice: authentication error.\n");
        return CBERRNO;
    }
    sbob_fin(&cx->sbx, BLNK_MAC | BLNK_B2A);
 
    return 0;
}

// bobby's handshake
int blnk_shake_bobby(stricat_t *cx, const uint8_t bobbyid[CBYT_IDNT])
{
    sbob_clr(&cx->sbx);

    // identities in
    if (bobbyid != NULL) {
        sbob_put(&cx->sbx, BLNK_AAD | BLNK_A2B, cx->idn, CBYT_IDNT);
        sbob_fin(&cx->sbx, BLNK_AAD | BLNK_A2B);
        sbob_put(&cx->sbx, BLNK_AAD | BLNK_B2A, bobbyid, CBYT_IDNT);
        sbob_fin(&cx->sbx, BLNK_AAD | BLNK_B2A);
    }

    // nonces in
    sbob_put(&cx->sbx, BLNK_NPUB | BLNK_A2B, cx->xfr, CBYT_NPUB);
    sbob_fin(&cx->sbx, BLNK_NPUB | BLNK_A2B);
    sbob_put(&cx->sbx, BLNK_NPUB | BLNK_B2A, cx->nnc, CBYT_NPUB);
    sbob_fin(&cx->sbx, BLNK_NPUB | BLNK_B2A);

    // load key
    sbob_put(&cx->sbx, BLNK_KEY | BLNK_A2B | BLNK_B2A, cx->key, CBYT_KEY);
    sbob_fin(&cx->sbx, BLNK_KEY | BLNK_A2B | BLNK_B2A);

    // now bobby verifies mac
    if (block_recv(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;
    if (sbob_cmp(&cx->sbx, BLNK_MAC | BLNK_A2B, cx->mac, CBYT_MAC) != 0) {

        // send a "fake" mac! (random number)
        blnk_rand(cx->xfr, CBYT_MAC);
        if (block_send(cx, cx->xfr, CBYT_MAC) != CBYT_MAC)
            return CBERRNO;

        fprintf(stderr, "blnk_shake_bobby: authentication error.\n");
        return CBERRNO;
    }
    sbob_fin(&cx->sbx, BLNK_MAC | BLNK_A2B);

    // bobby then generates and sends a mac
    sbob_get(&cx->sbx, BLNK_MAC | BLNK_B2A, cx->mac, CBYT_MAC);
    sbob_fin(&cx->sbx, BLNK_MAC | BLNK_B2A);
    if (block_send(cx, cx->mac, CBYT_MAC) != CBYT_MAC)
        return CBERRNO;

    return 0;
}

