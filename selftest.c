// selftest.c
// 28-Apr-14    Markku-Juhani O. Saarinen <mjos@cblnk.com>
//              See LICENSE for Licensing and Warranty information.

// self-tests
#include "blnk.h"
#include "streebog.h"

// test code

typedef struct {
    const uint8_t *data;
    int len;
    const uint8_t h256[32];
    const uint8_t h512[64];
} streebog_test_t;

    // test messages
static const unsigned char  tmsg1[] =
    "012345678901234567890123456789012345678901234567890123456789012";

const uint8_t tmsg2[72] = {
    0xD1, 0xE5, 0x20, 0xE2, 0xE5, 0xF2, 0xF0, 0xE8,
    0x2C, 0x20, 0xD1, 0xF2, 0xF0, 0xE8, 0xE1, 0xEE,
    0xE6, 0xE8, 0x20, 0xE2, 0xED, 0xF3, 0xF6, 0xE8,
    0x2C, 0x20, 0xE2, 0xE5, 0xFE, 0xF2, 0xFA, 0x20,
    0xF1, 0x20, 0xEC, 0xEE, 0xF0, 0xFF, 0x20, 0xF1,
    0xF2, 0xF0, 0xE5, 0xEB, 0xE0, 0xEC, 0xE8, 0x20,
    0xED, 0xE0, 0x20, 0xF5, 0xF0, 0xE0, 0xE1, 0xF0,
    0xFB, 0xFF, 0x20, 0xEF, 0xEB, 0xFA, 0xEA, 0xFB,
    0x20, 0xC8, 0xE3, 0xEE, 0xF0, 0xE5, 0xE2, 0xFB
};

static const uint8_t tmsg4[64] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// test vectors

static const streebog_test_t tvec[] = {

    // M1
    { tmsg1, 63,
        {   0x00, 0x55, 0x7B, 0xE5, 0xE5, 0x84, 0xFD, 0x52,
            0xA4, 0x49, 0xB1, 0x6B, 0x02, 0x51, 0xD0, 0x5D,
            0x27, 0xF9, 0x4A, 0xB7, 0x6C, 0xBA, 0xA6, 0xDA,
            0x89, 0x0B, 0x59, 0xD8, 0xEF, 0x1E, 0x15, 0x9D  },
        {   0x48, 0x6F, 0x64, 0xC1, 0x91, 0x78, 0x79, 0x41,
            0x7F, 0xEF, 0x08, 0x2B, 0x33, 0x81, 0xA4, 0xE2,
            0x11, 0xC3, 0x24, 0xF0, 0x74, 0x65, 0x4C, 0x38,
            0x82, 0x3A, 0x7B, 0x76, 0xF8, 0x30, 0xAD, 0x00,
            0xFA, 0x1F, 0xBA, 0xE4, 0x2B, 0x12, 0x85, 0xC0,
            0x35, 0x2F, 0x22, 0x75, 0x24, 0xBC, 0x9A, 0xB1,
            0x62, 0x54, 0x28, 0x8D, 0xD6, 0x86, 0x3D, 0xCC,
            0xD5, 0xB9, 0xF5, 0x4A, 0x1A, 0xD0, 0x54, 0x1B  }
    },

    // M2
    { tmsg2, 72,
        {   0x50, 0x8F, 0x7E, 0x55, 0x3C, 0x06, 0x50, 0x1D,
            0x74, 0x9A, 0x66, 0xFC, 0x28, 0xC6, 0xCA, 0xC0,
            0xB0, 0x05, 0x74, 0x6D, 0x97, 0x53, 0x7F, 0xA8,
            0x5D, 0x9E, 0x40, 0x90, 0x4E, 0xFE, 0xD2, 0x9D  },
        {   0x28, 0xFB, 0xC9, 0xBA, 0xDA, 0x03, 0x3B, 0x14,
            0x60, 0x64, 0x2B, 0xDC, 0xDD, 0xB9, 0x0C, 0x3F,
            0xB3, 0xE5, 0x6C, 0x49, 0x7C, 0xCD, 0x0F, 0x62,
            0xB8, 0xA2, 0xAD, 0x49, 0x35, 0xE8, 0x5F, 0x03,
            0x76, 0x13, 0x96, 0x6D, 0xE4, 0xEE, 0x00, 0x53,
            0x1A, 0xE6, 0x0F, 0x3B, 0x5A, 0x47, 0xF8, 0xDA,
            0xE0, 0x69, 0x15, 0xD5, 0xF2, 0xF1, 0x94, 0x99,
            0x6F, 0xCA, 0xBF, 0x26, 0x22, 0xE6, 0x88, 0x1E  }
    },

    // M3 = zero length string
    { NULL, 0,
        {   0xBB, 0xE1, 0x9C, 0x8D, 0x20, 0x25, 0xD9, 0x9F,
            0x94, 0x3A, 0x93, 0x2A, 0x0B, 0x36, 0x5A, 0x82,
            0x2A, 0xA3, 0x6A, 0x4C, 0x47, 0x9D, 0x22, 0xCC,
            0x02, 0xC8, 0x97, 0x3E, 0x21, 0x9A, 0x53, 0x3F  },
        {   0x8A, 0x1A, 0x1C, 0x4C, 0xBF, 0x90, 0x9F, 0x8E,
            0xCB, 0x81, 0xCD, 0x1B, 0x5C, 0x71, 0x3A, 0xBA,
            0xD2, 0x6A, 0x4C, 0xAC, 0x2A, 0x5F, 0xDA, 0x3C,
            0xE8, 0x6E, 0x35, 0x28, 0x55, 0x71, 0x2F, 0x36,
            0xA7, 0xF0, 0xBE, 0x98, 0xEB, 0x6C, 0xF5, 0x15,
            0x53, 0xB5, 0x07, 0xB7, 0x3A, 0x87, 0xE9, 0x79,
            0x46, 0xAE, 0xBC, 0x29, 0x85, 0x92, 0x55, 0x04,
            0x9F, 0x86, 0xAA, 0x09, 0xA2, 0x5D, 0x94, 0x8E  }
    },

    // M4
    { tmsg4, 64,
        {   0x95, 0x6B, 0x63, 0x13, 0x5E, 0x10, 0x07, 0xC1,
            0x1D, 0x24, 0xDA, 0x0E, 0xCD, 0x54, 0xAA, 0xA6,
            0xCA, 0x2E, 0xDB, 0x31, 0x80, 0x35, 0x37, 0x05,
            0x39, 0x91, 0x31, 0xE8, 0x9C, 0xDA, 0x1F, 0xDF  },
        {   0xB7, 0x0D, 0xD2, 0x52, 0xC5, 0x02, 0x14, 0x61,
            0xF2, 0x6B, 0x56, 0xAE, 0xE9, 0xAD, 0xB4, 0xD7,
            0x45, 0xA1, 0x12, 0xB1, 0x0F, 0xB6, 0x6F, 0xB2,
            0x8C, 0xB5, 0x35, 0x92, 0x99, 0xAC, 0x14, 0xC0,
            0xC6, 0x48, 0x79, 0xAA, 0xBB, 0xB7, 0xFF, 0xCE,
            0x28, 0xFB, 0x06, 0xAC, 0xD6, 0x21, 0x77, 0xF6,
            0x4D, 0x56, 0xDC, 0xB8, 0xFD, 0xF3, 0x9F, 0x76,
            0x41, 0xF4, 0x0D, 0x1B, 0xAC, 0x29, 0xFD, 0xB0  }
    }
};

// test vector for the pi permutation
static const uint8_t pivec[64] = {
    0x16, 0x8A, 0x86, 0x7D, 0x30, 0xDB, 0x56, 0x6D,
    0x57, 0xD5, 0x30, 0xBE, 0xD9, 0x22, 0x08, 0x82,
    0x37, 0x0C, 0xE2, 0x79, 0xFB, 0xA4, 0xE5, 0x87,
    0xA3, 0x20, 0xE6, 0xED, 0xA2, 0xA3, 0xBA, 0x10,
    0x17, 0x34, 0x62, 0xB6, 0x23, 0x0E, 0xC5, 0x67,
    0x86, 0x7C, 0x34, 0x37, 0x5E, 0x2E, 0x46, 0xD9,
    0xA7, 0xFB, 0x06, 0x19, 0x27, 0xA3, 0xF5, 0x49,
    0x53, 0x19, 0xBD, 0xF9, 0xEC, 0x94, 0x1A, 0x95
};

// run selftests

int run_selftest()
{
    int i;
    uint8_t md[64];
    sbob_t sb;

    // known plaintext test on the Pi
    sbob_clr(&sb);
    for (i = 0; i < 64; i++)
        sb.s.b[i] = i;

    sbob_pi(&sb.s);

    if (memcmp(sb.s.b, pivec, 64) != 0)
        return SBOB_ERR;

    // test cases for streebog
    for (i = 0; i < 4; i++) {

        streebog(md, 32, tvec[i].data, tvec[i].len);

        if (memcmp(md, tvec[i].h256, 32) != 0) {
            printf("case %d 256\n", i);
            return SBOB_ERR;
        }

        streebog(md, 64, tvec[i].data, tvec[i].len);
        if (memcmp(md, tvec[i].h512, 32) != 0) {
            printf("case %d 512\n", i);
            return SBOB_ERR;
        }
    }

    return 0;
}
