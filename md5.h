/* $Id: md5.h,v 1.1 1999/07/20 14:27:52 sova Exp $ */

/* Mostly borrowed from opie.h in opie-2.32 distribution */

#ifndef __alpha
#define UINT4 unsigned long
#else   /* __alpha */
#define UINT4 unsigned int 
#endif  /* __alpha */


struct otp_mdx_ctx {
	UINT4 state[4];
	UINT4 count[2];
	unsigned char buffer[64];
};

void otp_hashlen(void *,void *,int);
void otp_hash(void *);
