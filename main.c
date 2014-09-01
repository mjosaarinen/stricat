// main.c
// 07-Dec-13    Markku-Juhani O. Saarinen <mjos@cblnk.com>
//              See LICENSE for Licensing and Warranty information.

// Command line parsing etc.

#include "iocom.h"
#include "streebog.h"

// online help
const char usage[] =
"stricat: STRIBOB / STREEBOG Cryptographic Tool.\n"
"(c) 2013-4 Markku-Juhani O. Saarinen <mjos@iki.fi>. See LICENSE.\n"
"\n"
"stricat [OPTION].. [FILE]..\n"
" -h         This help text\n"
" -t         Quick self-test and version information\n"
"\n"
"Shared secret key (use twice to verify):\n"
" -q         Prompt for key\n"
" -f <file>  Use file as a key\n"
" -k <key>   Specify key on command line\n"
"\n"
"Files:\n"
" -e         Encrypt stdin or files (add .sb1 suffix)\n"
" -d         Decrypt stdin or files (must have .sb1 suffix)\n"
" -s         Hash stdin or files in STRIBOB BNLK mode (optionally keyed)\n"
" -g         GOST R 34.11-2012 unkeyed Streebog hash with 256-bit output\n"
" -G         GOST R 34.11-2012 unkeyed Streebog hash with 512-bit output\n"
"\n"
"Communication via Blinker protocol:\n"
" -p <port>  Specify TCP port (default 48879)\n"
" -c <host>  Connect to a specific host (client)\n"
" -l         Listen to incoming connection (server)\n";

//c:dehf:k:lp:qt

int streebog_test();

// main
int main(int argc, char **argv)
{
    // status flags
    int i, st, len;
    char *pt;
    int hlen = 32;
    int encrypt = 0,                // operation flag
        decrypt = 0,
        hashing = 0,
        streebog = 0,
        listen = 0,
        connect = 0,
        keyset = 0;

    streebog_t sbog;                // streebog context (local)
    int port = 0xBEEF;              // 48879
    char *host = NULL;              // hostname
    stricat_t *cx = NULL;           // stricat context

    // get the state
    if ((cx = malloc(sizeof(stricat_t))) == NULL)
        return CBERRNO;
    memset(cx, 0x00, sizeof(stricat_t));

    cx->sck = 0;                    // call close() if modified on fds
    cx->fdi = STDIN_FILENO;
    cx->fdo = STDOUT_FILENO;

    // try to obtain the password from command line, file or prompt
    do {
        st = getopt(argc, argv, "c:dehf:gGk:lp:qst");
        switch (st) {

            case 'h':   // help / usage
                printf("%s", usage);
                st = 0;
                goto cleanup;

            case 'd':   // decryption
                decrypt = 1;
                break;

            case 'e':   // encryption
                encrypt = 1;
                break;

            case 's':   // hashing
                hashing = 1;
                break;

            case 'c':   // connect to a host
                if (host != NULL) {
                    fprintf(stderr,
                        "Only one host can be specified with -c.\n");
                    goto cleanup;
                }

                if ((host = strdup(optarg)) == NULL)
                    goto cleanup;
                connect = 1;
                break;

            case 'l':   // listen for connections
                listen = 1;
                break;

            case 't':   // self-test
                st = run_selftest();
                printf("Compiled on " __DATE__ " " __TIME__ "\n");
                printf("run_selftest() == %d\n", st);
                goto cleanup;
                break;
   
            case 'f':   // key file

                if ((i = open(optarg, O_RDONLY)) == -1) { // open the file
                    perror(optarg);
                    goto cleanup;
                }      
                sbob_clr(&cx->sbx);

                while ((len = read(i, cx->xfr, CBYT_XFER)) > 0) {
                    sbob_put(&cx->sbx, BLNK_DAT, cx->xfr, len);
                }
                sbob_fin(&cx->sbx, BLNK_HASH);

                close(i);

                if (keyset) {
                    if (sbob_cmp(&cx->sbx, BLNK_HASH, cx->key, CBYT_KEY)) {
                        fprintf(stderr, "Key mismatch.\n");
                        goto cleanup;
                    }
                } else {
                    sbob_get(&cx->sbx, BLNK_HASH, cx->key, CBYT_KEY);
                    keyset = 1;
                }

                break;


            case 'g':   // hashing with streebog, 256-bit hash
                streebog = 1;
                hlen = 32;
                break;

            case 'G':   // hashing with streebog, 512-bit hash
                streebog = 1;
                hlen = 64;
                break;

            case 'k':   // password supplied
                sbob_clr(&cx->sbx);
                sbob_put(&cx->sbx, BLNK_DAT,
                    (const uint8_t *) optarg, strlen(optarg));
                sbob_fin(&cx->sbx, BLNK_HASH);
       
                if (keyset) {
                    if (sbob_cmp(&cx->sbx, BLNK_HASH, cx->key, CBYT_KEY)) {
                        fprintf(stderr, "Key mismatch.\n");
                        goto cleanup;
                    }
                } else {
                    sbob_get(&cx->sbx, BLNK_HASH, cx->key, CBYT_KEY);
                    keyset = 1;
                }
                break;

            case 'p':   // specify port number
                port = atoi(optarg);
                if (port <= 0 || port >= 0x10000) {
                    fprintf(stderr, "Illegal port number %s\n", optarg);
                    goto cleanup;
                }
                break;
       
            case 'q':   // prompt for key (twice to verify)
   
                if (keyset)
                    pt = getpass("Verify key:");
                else
                    pt = getpass("Secret key:");
                len = strlen(pt);
       
                if (len >= CBYT_XFER) {
                    memset(pt, 0, len);
                    fprintf(stderr,
                        "Key is too long for prompt (max %d characters).\n",
                        CBYT_XFER - 1);
                    goto cleanup;
                }
                memcpy(cx->xfr, pt, len);
                memset(pt, 0, len);

                sbob_clr(&cx->sbx);            // hash the key
                sbob_put(&cx->sbx, BLNK_DAT, cx->xfr, len);
                sbob_fin(&cx->sbx, BLNK_HASH);

                if (keyset) {
                    if (sbob_cmp(&cx->sbx, BLNK_HASH, cx->key, CBYT_KEY)) {
                        fprintf(stderr, "Key mismatch.\n");
                        goto cleanup;
                    }
                } else {
                    sbob_get(&cx->sbx, BLNK_HASH, cx->key, CBYT_KEY);
                    keyset = 1;
                }
                break;

            case -1:
                break;

            default:
            case '?':
                fprintf(stderr, "Invoke with -h for online help.\n");
                goto cleanup;
        }
    } while (st != -1);

    // see that there's a single op defined
    if (encrypt + decrypt + hashing + connect + listen + streebog != 1) {
        fprintf(stderr,
            "Exactly one of -d, -e, -g, -G, -s, -c, -l must be set.\n");
        st = 1;
        goto cleanup;
    }

    // get it from command prompt
    if (keyset == 0 && hashing == 0 && streebog == 0) {
        fprintf(stderr,
            "No key set.\n");
        st = 1;
        goto cleanup;
    }

    // networking

    if (connect || listen) {

        // see if we need to execute something
        if (optind < argc) {
            st = iocom_exec(cx, argv[optind]);
            if (st != 0)
                goto cleanup;
        }

        if (connect)
            st = iocom_client(cx, host, port);
        else
            st = iocom_server(cx, port);

        goto cleanup;
    }

    // hashing

    if (hashing) {

        st = 0;

        if (optind >= argc) {
            sbob_clr(&cx->sbx);
            if (keyset) {
                sbob_put(&cx->sbx, BLNK_KEY, cx->key, CBYT_KEY);
                sbob_fin(&cx->sbx, BLNK_KEY);       
            }
            st = iocom_hash(cx);
            sbob_get(&cx->sbx, BLNK_HASH, cx->xfr, CBYT_HASH);
            for (i = 0; i < CBYT_HASH; i++)
                printf("%02x", cx->xfr[i] & 0xFF);
            printf("\n");
            goto cleanup;
        }

        for (; optind < argc; optind++) {

            if ((cx->fdi = open(argv[optind], O_RDONLY)) == -1) {
                perror(optarg);
                goto cleanup;
            }
            sbob_clr(&cx->sbx);
            if (keyset) {
                sbob_put(&cx->sbx, BLNK_KEY, cx->key, CBYT_KEY);
                sbob_fin(&cx->sbx, BLNK_KEY);
            }
            st = iocom_hash(cx);
            close(cx->fdi);
            cx->fdi = STDIN_FILENO;

            sbob_get(&cx->sbx, BLNK_HASH, cx->xfr, CBYT_HASH);
            for (i = 0; i < CBYT_HASH; i++)
                printf("%02x", cx->xfr[i] & 0xFF);
            printf("  %s\n", argv[optind]);
        }
    }

    // streebog ops

    if (streebog) {

        if (keyset) {
             fprintf(stderr, "Streebog is an unkeyed hash. Try -s\n");
             goto cleanup;
        }

        if (optind >= argc) {
            streebog_init(&sbog, hlen);
            while ((len = read(cx->fdi, cx->xfr, CBYT_XFER)) > 0)
                streebog_update(&sbog, cx->xfr, len);
            streebog_final(cx->xfr, &sbog);
            for (i = 0; i < hlen; i++)
                printf("%02x", cx->xfr[i] & 0xFF);       
            printf("\n");
            goto cleanup;
        }

        for (; optind < argc; optind++) {

            if ((cx->fdi = open(argv[optind], O_RDONLY)) == -1) {
                perror(optarg);
                goto cleanup;
            }
            streebog_init(&sbog, hlen);
            while ((len = read(cx->fdi, cx->xfr, CBYT_XFER)) > 0)
                streebog_update(&sbog, cx->xfr, len);
            close(cx->fdi);
            cx->fdi = STDIN_FILENO;

            streebog_final(cx->xfr, &sbog);
            for (i = 0; i < hlen; i++)
                printf("%02x", cx->xfr[i] & 0xFF);
            printf("  %s\n", argv[optind]);
        }
    }

    // encrypt

    if (encrypt) {

        if (optind >= argc) {
            st = iocom_enc(cx);
            goto cleanup;
        }

        for (; optind < argc; optind++) {

            st = 1;

            if ((cx->fdi = open(argv[optind], O_RDONLY)) == -1) {
                perror(argv[optind]);
                goto cleanup;
            }
            snprintf(cx->xfr, CBYT_XFER, "%s.sb1", argv[optind]);   
            if ((cx->fdo =
                open(cx->xfr, O_WRONLY | O_CREAT | O_TRUNC, 0664)) == -1) {
                perror(cx->xfr);
                goto cleanup;
            }  

            st = iocom_enc(cx);

            close(cx->fdi);
            cx->fdi = STDIN_FILENO;
            close(cx->fdo);
            cx->fdo = STDOUT_FILENO;
   
            if (st != 0)
                goto cleanup;
        }
    }

    // decrypt

    if (decrypt) {

        if (optind >= argc) {
            st = iocom_dec(cx);
            goto cleanup;
        }

        for (; optind < argc; optind++) {

            st = 1;
            snprintf(cx->xfr, CBYT_XFER, "%s", argv[optind]);

            len = strlen(cx->xfr);
            if (len <= 4 || strcmp(&cx->xfr[len - 4], ".sb1") != 0) {
                fprintf(stderr, "Unknown file type: %s\n", cx->xfr);
                goto cleanup;
            }
            if ((cx->fdi = open(cx->xfr, O_RDONLY)) == -1) {
                perror(cx->xfr);
                goto cleanup;
            }  
            cx->xfr[len - 4] = 0;
            if ((cx->fdo =
                    open(cx->xfr, O_WRONLY | O_CREAT | O_TRUNC, 0664)) == -1) {
                perror(cx->xfr);
                goto cleanup;
            }  

            st = iocom_dec(cx);

            close(cx->fdi);
            cx->fdi = STDIN_FILENO;
            close(cx->fdo);
            cx->fdo = STDOUT_FILENO;
   
            if (st != 0)
                goto cleanup;
        }

    }

    st = 0;

cleanup:

    // clearout sensitive data

    if (cx->sck != 0)
        close(cx->sck);
    if (cx->fdi != STDIN_FILENO)
        close(cx->fdi);
    if (cx->fdo != STDOUT_FILENO)
        close(cx->fdo);
    if (host != NULL)
        free(host);
    if (cx != NULL) {
        memset(cx, 0x00, sizeof(stricat_t));
        free(cx);
    }
   
    return st;
}

