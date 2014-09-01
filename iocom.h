// iocom.h
// 09-Dec-13    Markku-Juhani O. Saarinen <mjos@cblnk.com>
//              See LICENSE for Licensing and Warranty information.

#ifndef IOCOM_H
#define IOCOM_H

#include "blnk.h"

// hash a file
int iocom_hash(stricat_t *cx);

// encrypt an io stream
int iocom_enc(stricat_t *cx);

// decrypt an io stream
int iocom_dec(stricat_t *cx);

// client
int iocom_client(stricat_t *cx, char *hostname, int port);

// server side
int iocom_server(stricat_t *cx, int portno);

// execute
int iocom_exec(stricat_t *cx, char *cmd);

#endif
