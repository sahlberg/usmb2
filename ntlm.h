/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifdef USMB2_FEATURE_NTLM

#ifndef _NTLM_H_
#define _NTLM_H_

#include "usmb2.h"

int ntlm_generate_auth(struct usmb2_context *usmb2,
                       char *username,
                       char *password);

#endif /* _NTLM_H_ */

#endif /* USMB2_FEATURE_NTLM */
