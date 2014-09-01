// blnk.h
// 07-Dec-13    Markku-Juhani O. Saarinen <mjos@cblnk.com>
//              See LICENSE for Licensing and Warranty information.

#ifndef BLNK_H
#define BLNK_H

#include "stribob.h"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

// negative error code
#ifndef CBERRNO
#ifdef __LINE__
#define CBERRNO (-(__LINE__))
#else
#define CBERRNO (-1)
#endif
#endif

// connection termination flag (used in message lenth lbf)
#ifndef BLNK_TERMINATE
#define BLNK_TERMINATE (~0lu)
#endif

// application parameters
#define CBYT_KEY 24
#define CBYT_NPUB 16
#define CBYT_IDNT 16
#define CBYT_MAC 8
#define CBYT_LBUF 4
#define CBYT_HASH 16
#define CBYT_XFER 0x10000

typedef struct {
    int     sck;                // network socket
    int     fdi, fdo;           // input, output file desciptors
    int     run;                // connection is running (1) or not (0)
    sbob_t  sbx;                // StriBob context
    uint8_t idn[CBYT_IDNT];     // remote identity
    uint8_t key[CBYT_KEY];      // (hashed) key
    uint8_t mac[CBYT_MAC];      // MAC
    uint8_t lbf[CBYT_LBUF];     // 32-bit length buffer
    uint8_t nnc[CBYT_NPUB];     // nonce
    char    xfr[CBYT_XFER];     // input-output buffer
} stricat_t;

// a send function that waits for buffers to clear (success only if "len" sent)
int block_send(stricat_t *cx, const void *buf, int len);

// blocks until exactly "len" bytes has been received
int block_recv(stricat_t *cx, void *buf, int len);

// authenticated and ecnryptiond send & receive - use cx->xfr buffer
int blnk_send(stricat_t *cx, int from, int len);
int blnk_recv(stricat_t *cx, int from);

// send a terminator which is understood by blnk_recv()
int blnk_term(stricat_t *cx, int from);

// client authentication handshake first messages
// leave own nonce at nnc and alien foreign nonce and id at cx->xfr, cx->idn
int blnk_hand(stricat_t *cx, const uint8_t myid[CBYT_IDNT]);

// alice's handshake (cx->key can depend on cx->idn returned by blnk_hand)
int blnk_shake_alice(stricat_t *cx, const uint8_t alice[CBYT_IDNT]);

// bobby's handshake (cx->key can depend on cx->idn returned by blnk_hand)
int blnk_shake_bobby(stricat_t *cx, const uint8_t bobby[CBYT_IDNT]);

// utility functions
int blnk_rand(void *buf, int len);
uint64_t blnk_lbf_getl(stricat_t *cx, int from);
void blnk_lbf_putl(stricat_t *cx, uint64_t x, int from);

// selftest.c
int run_selftest();

#endif

