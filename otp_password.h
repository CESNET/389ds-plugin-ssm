/* $Id: otp_password.h,v 1.4 1999/08/20 18:24:12 sova Exp sova $ */

#ifndef _OTP_PASSWORD_H
#define _OTP_PASSWORD_H 1

#include "udb.h"

#define LDAP_SASL_OTP		"OTP"
#define A_OTP_N			"otpcount"
#define A_OTP_SEED		"otpseed"
#define A_OTP_VAL		"otpvalue"

struct otp {
  char	otp_buf[256];
  char	*otp_principal;
  int	otp_n;
  char	*otp_seed;
  char	*otp_val;
};

struct otp *otp_new(void);
void otp_free(struct otp *);
int otp_password(struct otp *,struct udb_global *,char *);
int otp_verify(struct otp *, char *);
char *otp_btoe(char *,char *);
int otp_etob(char *,char *);

#endif /* _OTP_PASSWORD_H */
