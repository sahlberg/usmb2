/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* SMB's UTF-16 is always in Little Endian */

#ifdef USMB2_FEATURE_UNICODE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#if defined(_IOP)
#include "ps2iop-compat.h"
#else
#include <stdio.h>
#include <stdlib.h>
#endif
#include <string.h>
#include <stddef.h>

#include "unicode.h"

#if defined(Z80)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define htole16(x) (x)
#define htole32(x) (x)
#endif

/* Decodes the UTF-8 code point at *utf8 into one or two UTF-16LE code
 * units at ret and moves *utf8 to the next character in the string.
 * Returns the number of UTF-16 code units, 1 or 2, or -1 if the encoding
 * is invalid.
 */
static int
validate_utf8_cp(const char **utf8, uint16_t *ret)
{
        /* The smallest code point for 2, 3 and 4 byte sequences */
        static const uint32_t min_cp[] = {0x80, 0x800, 0x10000};
        int c = *(*utf8)++;
        int l = 0, i;
        uint32_t cp;

        if (!(c & 0x80)) {
                /* 7-bit ascii is always ok */
                *ret = htole16(c);
                return 1;
        }
        /* The number of leading 1 bits is the length of the sequence.
         * 10.. .... can never start a new codepoint.
         */
        while (c & (0x80 >> l)) {
                l++;
        }
        if (l < 2 || l > 4) {
                return -1;
        }
        cp = c & (0x7f >> l);
        /* 2, 3 and 4 byte sequences must always be followed by exactly
         * 1, 2 or 3 chars matching 10.. ....
         */
        for (i = 1; i < l; i++) {
                c = *(*utf8)++;
                if ((c & 0xc0) != 0x80) {
                        return -1;
                }
                cp = (cp << 6) | (c & 0x3f);
        }
        /* Check for overlong sequences */
        if (cp < min_cp[l - 2]) {
                return -1;
        }

        /* Write the code point in either one or two UTC-16 code units */
        if (cp < 0xd800 || (cp - 0xe000) < 0x2000) {
                /* Single UTF-16 code unit */
                *ret = htole16(cp);
                return 1;
        }
        if (cp < 0xe000 || cp >= 0x110000) {
                /* invalid unicode range */
                return -1;
        }
        cp -= 0x10000;
        ret[0] = htole16(0xd800 | (cp >> 10));
        ret[1] = htole16(0xdc00 | (cp & 0x3ff));
        return 2;
}

/* Convert a UTF8 string into UTF-16LE */
int utf8_to_utf16(const char *utf8, uint16_t *utf16)
{
        int i = 0, n;

        while ((n = validate_utf8_cp(&utf8, utf16)) > 0) {
                utf16 += n;
                i += n;
                if (!utf16[-1]) {
                        return i - 1;
                }
        }
        return -1;
}

/*
 * In-place conversion of a UTF-16LE string into UTF8.
 * Assumes short encodings. Or else it will overwrite and corrupt.
 */
int
utf16_to_utf8(const uint16_t *utf_16, int utf16_len)
{
        /* The first byte of a 2, 3 and 4 byte sequence */
        static const uint8_t lead[] = {0xc0, 0xe0, 0xf0};
        char *tmp = (char *)utf_16;
        const uint16_t *utf16 = utf_16, *utf16_end = utf_16 + utf16_len;
        uint32_t code, trail;
        int n;

        while (utf16 < utf16_end) {
                code = le16toh(*utf16++);

                if (code - 0xd800 < 0x800) {
                        /* A surrogate. Valid if it is a leading code unit, 0xd800-0xdbff,
                         * followed by a trailing one, 0xdc00-0xdfff. The stream may end
                         * with the leading one.
                         * An invalid trailing code unit is still valid on its own,
                         * so only the first unit gets replaced.
                         */
                        if (code < 0xdc00 && utf16 < utf16_end &&
                            (trail = le16toh(*utf16)) - 0xdc00 < 0x400) {
                                code = 0x10000 + ((code & 0x3ff) << 10) + (trail & 0x3ff);
                                utf16++;
                        } else {
                                code = 0xfffd; /* Replacement char */
                        }
                }

                if (code < 0x80) {
                        *tmp++ = code; /* One UTF-16 code unit maps to one UTF-8 code unit */
                        continue;
                }
                /* n is the number of continuation bytes, 10.. .... */
                n = code < 0x800 ? 1 : code < 0x10000 ? 2 : 3;
                *tmp++ = lead[n - 1] | (code >> (6 * n));
                while (n--) {
                        *tmp++ = 0x80 | ((code >> (6 * n)) & 0x3f);
                }
        }

        return tmp - (char *)utf_16;
}

#endif /* USMB2_FEATURE_UNICODE */
