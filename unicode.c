/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/* SMB's UTF-16 is always in Little Endian */

#ifdef USMB2_FEATURE_UNICODE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "unicode.h"

#if defined(Z80)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define htole16(x) (x)
#define htole32(x) (x)
#endif

/* Count number of leading 1 bits in the char */
static int
l1(char c)
{
        int i = 0;
        while (c & 0x80) {
                i++;
                c <<= 1;
        }
        return i;
}

/* Validates that utf8 points to a valid utf8 codepoint.
 * Will update **utf8 to point at the next character in the string.
 * return 1 if the encoding is valid and requires one UTF-16 code unit,
 * 2 if the encoding is valid and requires two UTF-16 code units
 * -1 if it's invalid.
 * If the encoding is valid the codepoint will be returned in *cp.
 */
static int
validate_utf8_cp(const char **utf8, uint16_t *ret)
{
        int c = *(*utf8)++;
        int l, l_tmp;
        uint32_t cp;
        l = l_tmp = l1(c);
 
        switch (l) {
        case 0:
                /* 7-bit ascii is always ok */
                *ret = c & 0x7f;
                return 1;
        case 1:
                /* 10.. .... can never start a new codepoint */
                return -1;
        case 2:
        case 3:
        case 4:
                cp = c & (0x7f >> l);
                /* 2, 3 and 4 byte sequences must always be followed by exactly
                 * 1, 2 or 3 chars matching 10.. ....
                 */
                while(--l_tmp) {
                        c = *(*utf8)++;
                        if (l1(c) != 1) {
                                return -1;
                        }
                        cp <<= 6;
                        cp |= (c & 0x3f);
                }

                /* Check for overlong sequences */
                switch (l) {
                case 2:
                        if (cp < 0x80) return -1;
                        break;
                case 3:
                        if (cp < 0x800) return -1;
                        break;
                case 4:
                        if (cp < 0x10000) return -1;
                        break;
                default: break;
                }

                /* Write the code point in either one or two UTC-16 code units */
                if (cp < 0xd800 || (cp - 0xe000) < 0x2000) {
                        /* Single UTF-16 code unit */
                        *ret = cp;
                        return 1;
                } else if (cp < 0xe000) {
                        /* invalid unicode range */
                        return -1;
                } else if (cp < 0x110000) {
                        cp -= 0x10000;
                        *ret = 0xd800 | (cp >> 10);
                        *(ret+1) = 0xdc00 | (cp & 0x3ff) ;
                        return 2;
                } else {
                        /* invalid unicode range */
                        return -1;
                }
        }
        return -1;
}

/* Convert a UTF8 string into UTF-16LE */
int utf8_to_utf16(const char *utf8, uint16_t *utf16)
{
        int i = 0;
        uint16_t u16;

        while (1) {
                switch(validate_utf8_cp(&utf8, utf16)) {
                case 1:
                    u16 = htole16(*utf16);
                    *utf16++ = u16;
                    i += 1;
                    break;
                case 2:
                    u16 = htole16(*utf16);
                    *utf16++ = u16;
                    u16 = htole16(*utf16);
                    *utf16++ = u16;
                    i += 2;
                    break;
                default:
                    return -1;
                }
                if (!*(utf16 - 1)) {
                        return i - 1;
                }
        }

}

/*
 * In-place conversion of a UTF-16LE string into UTF8.
 * Assumes short encodings. Or else it will overwrite and corrupt.
 */
int
utf16_to_utf8(const uint16_t *utf_16, int utf16_len)
{
        char *tmp;
        const uint16_t *utf16, *utf16_end;
        
        utf16 = utf_16;
        tmp = (char *)utf16;
        utf16_end = utf16 + utf16_len;
        while (utf16 < utf16_end) {
                uint32_t code = le16toh(*utf16++);

                if (code < 0x80) {
                        *tmp++ = code; /* One UTF-16 code unit maps to one UTF-8 code unit */
                } else if (code < 0x800) {
                        *tmp++ = 0xc0 |  (code >> 6);         /* One UTF-16 code unit maps to two UTF-8 code units */
                        *tmp++ = 0x80 | ((code     ) & 0x3f);
                } else if (code < 0xD800 || code - 0xe000 < 0x2000) {
                        *tmp++ = 0xe0 |  (code >> 12);         /* All other values where we only have one UTF-16 code unit map to 3 UTF-8 code units */
                        *tmp++ = 0x80 | ((code >>  6) & 0x3f);
                        *tmp++ = 0x80 | ((code      ) & 0x3f);
                } else if (code < 0xdc00) { /* Surrogate pair */
                        uint32_t trail;
                        if (utf16 == utf16_end) { /* It's possible the stream ends with a leading code unit, which is an error */
                                *tmp++ = 0xef; *tmp++ = 0xbf; *tmp++ = 0xbd; /* Replacement char */
                                return tmp - (char *)utf_16;
                        }

                        trail = le16toh(*utf16);
                        if (trail - 0xdc00 < 0x400) { /* Check that 0xdc00 <= trail < 0xe000 */
                                code = 0x10000 + ((code & 0x3ff) << 10) + (trail & 0x3ff);
                                if (code < 0x10000) {
                                        *tmp++ = 0xe0 |  (code >> 12);
                                        *tmp++ = 0x80 | ((code >>  6) & 0x3f);
                                        *tmp++ = 0x80 | ((code      ) & 0x3f);
                                } else {
                                        *tmp++ = 0xF0 | (code >> 18);
                                        *tmp++ = 0x80 | ((code >> 12) & 0x3F);
                                        *tmp++ = 0x80 | ((code >> 6) & 0x3F);
                                        *tmp++ = 0x80 | (code & 0x3F);
                                }
                                utf16++;
                        } else {
                                /* Invalid trailing code unit. It's still valid on its own though so only the first unit gets replaced */
                                *tmp++ = 0xef; *tmp++ = 0xbf; *tmp++ = 0xbd; /* Replacement char */
                        }
                } else {
                        /* 0xdc00 <= code < 0xe00, which makes code a trailing code unit without a leading one, which is invalid */
                        *tmp++ = 0xef; *tmp++ = 0xbf; *tmp++ = 0xbd; /* Replacement char */
                }
        }

        return tmp - (char *)utf_16;
}

#endif /* USMB2_FEATURE_UNICODE */
