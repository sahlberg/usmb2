/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */

#ifdef USMB2_FEATURE_UNICODE

#ifndef _UNICODE_H_
#define _UNICODE_H_

int utf16_to_utf8(const uint16_t *utf16, int utf16_len);
int utf8_to_utf16(const char *utf8, uint16_t *utf16);

#endif /* _UNICODE_H_ */

#endif /* USMB2_FEATURE_UNICODE */
