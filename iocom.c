// iocom.c
// 08-Dec-13    Markku-Juhani O. Saarinen <mjos@cblnk.com>
//              See LICENSE for Licensing and Warranty information.

#include "blnk.h"
#include "iocom.h"

// input (hash) a bulk file

int iocom_hash(stricat_t *cx)
{
    int len;

    while ((len = read(cx->fdi, cx->xfr, CBYT_XFER)) > 0) {
        sbob_put(&cx->sbx, BLNK_DAT, cx->xfr, len);
    }
    sbob_fin(&cx->sbx, BLNK_DAT);

    return 0;
}

// encrypt an io stream

int iocom_enc(stricat_t *cx)
{
    int len;

    // init the state with key and nonce
    sbob_clr(&cx->sbx);
    sbob_put(&cx->sbx, BLNK_KEY, cx->key, CBYT_KEY);
    sbob_fin(&cx->sbx, BLNK_KEY);

    blnk_rand(cx->nnc, CBYT_NPUB);
    sbob_put(&cx->sbx, BLNK_NPUB, cx->nnc, CBYT_NPUB);
    sbob_fin(&cx->sbx, BLNK_NPUB);

    if (write(cx->fdo, cx->nnc, CBYT_NPUB) != CBYT_NPUB) {
        perror("iocom_enc: error writing nonce");
        return CBERRNO;
    }

    // run the data
    while (1) {

        len = read(cx->fdi, cx->xfr, CBYT_XFER);
        blnk_lbf_putl(cx, len, 0);
        if (write(cx->fdo, cx->lbf, CBYT_LBUF) != CBYT_LBUF) {
            perror("iocom_enc: error writing chunk length");
            return CBERRNO;
        }
        if (len <= 0)
            break;

        sbob_enc(&cx->sbx, BLNK_MSG, cx->xfr, cx->xfr, len);
        sbob_fin(&cx->sbx, BLNK_MSG);
        if (write(cx->fdo, cx->xfr, len) != len) {
            perror("iocom_enc: error writing chunk");
            return CBERRNO;
        }

        sbob_get(&cx->sbx, BLNK_MAC, cx->mac, CBYT_MAC);
        sbob_fin(&cx->sbx, BLNK_MAC);
        if (write(cx->fdo, cx->mac, CBYT_MAC) != CBYT_MAC) {
            perror("iocom_enc: error writing MAC");
            return CBERRNO;
        }
    }

    // extract the final mac
    sbob_get(&cx->sbx, BLNK_MAC, cx->mac, CBYT_MAC);
    sbob_fin(&cx->sbx, BLNK_MAC);
    if (write(cx->fdo, cx->mac, CBYT_MAC) != CBYT_MAC) {
        perror("iocom_enc: error writing final MAC");
        return CBERRNO;
    }

    return 0;
}

// decrypt an io stream

int iocom_dec(stricat_t *cx)
{
    int len;
    struct stat st;

    // init the state with key and nonce
    sbob_clr(&cx->sbx);
    sbob_put(&cx->sbx, BLNK_KEY, cx->key, CBYT_KEY);
    sbob_fin(&cx->sbx, BLNK_KEY);

    if (read(cx->fdi, cx->nnc, CBYT_NPUB) != CBYT_NPUB) {
        perror("iocom_dec: error reading nonce");
        return CBERRNO;
    }
    sbob_put(&cx->sbx, BLNK_NPUB, cx->nnc, CBYT_NPUB);
    sbob_fin(&cx->sbx, BLNK_NPUB);

    while (1) {
        if (read(cx->fdi, cx->lbf, CBYT_LBUF) != CBYT_LBUF) {
            perror("iocom_dec: error reading chunk size");
            return CBERRNO;
        }
        len = blnk_lbf_getl(cx, 0);

        if (len < 0 || len > CBYT_XFER) {
            fprintf(stderr, "iocom_dec: chunk format / integrity error.\n");
            return 3;
        }
        if (len == 0) {          // that was the final block
            break;
        }
           
        if (read(cx->fdi, cx->xfr, len) != len) {
            perror("iocom_dec: error reading encrypted chunk");
            return CBERRNO;
        }

        // decrypt and compare mac
        sbob_dec(&cx->sbx, BLNK_MSG, cx->xfr, cx->xfr, len);
        sbob_fin(&cx->sbx, BLNK_MSG);

        if (read(cx->fdi, cx->mac, CBYT_MAC) != CBYT_MAC) {
            perror("iocom_dec: error reading MAC");
            return CBERRNO;
        }
        if (sbob_cmp(&cx->sbx, BLNK_MAC, cx->mac, CBYT_MAC) != 0) {
            fprintf(stderr, "iocom_dec: chunk integrity error!\n");
            return CBERRNO;
        }
        sbob_fin(&cx->sbx, BLNK_MAC);

        // we may now write the plaintext
        if (write(cx->fdo, cx->xfr, len) != len) {
            perror("iocom_dec: plaintext write error");
            return CBERRNO;
        }
    }

    // final mac
    if (read(cx->fdi, cx->mac, CBYT_MAC) != CBYT_MAC) {
        perror("iocom_dec: error reading final MAC");
        return CBERRNO;
    }
    if (sbob_cmp(&cx->sbx, BLNK_MAC, cx->mac, CBYT_MAC) != 0) {
        fprintf(stderr, "iocom_dec: final integrity error!\n");
        return CBERRNO;
    }
    sbob_fin(&cx->sbx, BLNK_MAC);
    
    // check if there's garbage at the end
    if (fstat(cx->fdi, &st) != 0)
        return 0;
        
    // regular file ?
    if (S_ISREG(st.st_mode)) {
        if (read(cx->fdi, cx->lbf, 1) == 1) {
            fprintf(stderr, 
                "iocom_dec: decryption ok, trailing garbage ignored\n");
        }
        lseek(cx->fdi, -1, SEEK_CUR);   // rewind back, just in case
    }

    return 0;
}

// create pipes for execution

int iocom_exec(stricat_t *cx, char *cmd)
{
    int pipi[2], pipo[2];
    pid_t pid;

    // now execute the thing
    if (pipe(pipi) != 0 || pipe(pipo) != 0) {
        perror("pipe()");
        return CBERRNO;
    }

    // fork
    pid = fork();
    if (pid == -1) {
        perror("fork()");
        return CBERRNO;
    }

    // child
    if (pid == 0) {
        if (dup2(pipi[0], STDIN_FILENO) == -1 ||
            dup2(pipo[1], STDOUT_FILENO) == -1 ||
            dup2(pipo[1], STDERR_FILENO) == -1) {
            perror("dup2() in child");
            return CBERRNO;
        }
        close(pipi[0]);
        close(pipo[1]);
        close(pipi[1]);
        close(pipo[0]);

        execl("/bin/sh", "sh", "-c", cmd, (char*) 0);

        // never reached
        exit(-1);
    }

    close(pipi[0]);                        // close duplicated handles
    close(pipo[1]);

    cx->fdi = pipo[0];
    cx->fdo = pipi[1];

    return 0;
}

// basic comms loop

int iocom_comms(stricat_t *cx, int here, int there)
{
    int n, timeout;
    struct timeval tv;
    fd_set rdset;
    const int wait_us[11] =
        { 0, 1000, 2000, 5000, 10000, 20000, 50000,
          100000, 200000, 500000, 1000000 };

    // this is the main body
    timeout = 0;
    cx->run = 1;

    // alice throws the initial null payload
    if ((here & BLNK_A2B) == BLNK_A2B) {
        if (blnk_send(cx, here, 0) != 0) {
            perror("comms blnk_send(0)");
            cx->run = 0;
        }
    }

    // turn-based comms loop
    while (cx->run) {

        // network -> fdo, blocking
        if ((n = blnk_recv(cx, there)) < 0) {
            break;
        }

        if (n > 0) {
            if (write(cx->fdo, cx->xfr, n) != n) {
                perror("iocom_comms: write()");
                break;
            }
            fsync(cx->fdo);
            timeout = 0;
        } else {
            if (timeout < 10)               // increase timeout
                timeout++;
        }

        // fdi -> network
   
        FD_ZERO(&rdset);
        FD_SET(cx->fdi, &rdset);
        tv.tv_sec = wait_us[timeout] / 1000000;
        tv.tv_usec = wait_us[timeout] % 1000000;

        if ((n = select(cx->fdi + 1, &rdset, NULL, NULL, &tv)) < 0) {
            perror("iocom_comms: select()");
            break;
        }

        if (n > 0) {
            if ((n = read(cx->fdi, cx->xfr, CBYT_XFER)) < 0) {
                perror("iocom_comms: read()");
                break;
            }
            if (n == 0) {           // EOF
                blnk_term(cx, here);
                break;
            }
            timeout = 0;
        } else {
            // if there's nothing to send, just send a zero length message
            n = 0;
        }

        if (blnk_send(cx, here, n) != n) {
            perror("iocom_comms: blnk_send()");
            break;
        }
    }

    // break was used
    if (cx->run)
        return CBERRNO;

    return 0;
}

// client

int iocom_client(stricat_t *cx, char *hostname, int port)
{
    struct hostent *he;
    struct sockaddr_in addr;
    uint32_t host = INADDR_LOOPBACK;

    // host
    if ((he = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        return CBERRNO;
    }
    if (he->h_addrtype != AF_INET || he->h_length != 4) {
        fprintf(stderr, "Currently only IPv4 supported.\n");
        return CBERRNO;
    }
    host = ntohl(*((uint32_t *) (he->h_addr)));

    // port

    if ((cx->sck = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("iocom_client: socket()");
        return CBERRNO;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(host);
    addr.sin_port = htons(port);

    if (connect(cx->sck, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("iocom_client: connect()");
        return CBERRNO;
    }

    // do a handshake
    if (blnk_hand(cx, NULL) < 0 ||
        blnk_shake_alice(cx, NULL) < 0)
        return CBERRNO;

    iocom_comms(cx, BLNK_A2B, BLNK_B2A);

    return 0;
}

// server side

int iocom_server(stricat_t *cx, int portno)
{
    int sock;
    socklen_t sl;
    struct sockaddr_in sin;

    // set up listening socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("iocom_server: socket()");
        return CBERRNO;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(portno);

    if (bind(sock, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        perror("iocom_server: bind()");
        return CBERRNO;
    }

    if (listen(sock, 1) != 0) {
        perror("iocom_server: listen()");
        return CBERRNO;
    }

    // avoid zombies if forking
    signal(SIGCHLD, SIG_IGN);

    //  handle incoming connections (XXX fork here for multiserver)
    sl = sizeof(sin);
    if ((cx->sck = accept(sock, (struct sockaddr *) &sin, &sl)) < 0) {
        perror("iocom_server: accept()");
        return CBERRNO;
    }
    close(sock);

    // handshake

    if (blnk_hand(cx, NULL) < 0 ||
        blnk_shake_bobby(cx, NULL) < 0)
        return CBERRNO;

    iocom_comms(cx, BLNK_B2A, BLNK_A2B);

    return 0;
}

