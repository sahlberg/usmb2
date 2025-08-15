/* From RFC1204  HMAC-MD5
 */

#ifdef USMB2_FEATURE_NTLM

#ifndef HMAC_MD5_H
#define HMAC_MD5_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <sys/types.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "md5.h"

#if (__BYTE_ORDER == __BIG_ENDIAN) || defined(XBOX_360_PLATFORM)
#  define WORDS_BIGENDIAN 1
#endif

#if !defined(__PS2__) && !defined(PICO_PLATFORM)
typedef uint32_t UWORD32;
#endif

void
hmac_md5(struct MD5Context *ctx, /* ctx buffer. Must be at least 4 + 16 + 64 bytes in size */
	 unsigned char *text0, /* nul-terminated ASCII, encoed as UCS2 */
	 unsigned char *text1, int text1_len,
	 unsigned char *text2, int text2_len,
	 unsigned char *key, unsigned int key_len,
	 unsigned char *digest);


#endif /* !HMAC_MD5_H */
#endif /* USMB2_FEATURE_NTLM */
