#ifndef lint
static char rcsid[] = "$Id: otp_password.c,v 1.2 1999/08/12 17:18:38 sova Exp $";
#endif

//#include <stdlib.h> /* malloc */
#include <string.h> /* memset */
#include <stdio.h>	/* sprintf */
#include <ctype.h>	/* isspace, tolower */
#include <time.h>

#include "slapi-plugin.h"
#include "udb.h"
#include "otp_password.h"
#include "md5.h"

#define OTP_SEED_MIN	5
#define OTP_SEED_MAX	16
#define FAKE 0

static char hextochar[16] = 
{'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

char *otp_btoa8 (char *out, char *in) {
  int i;
  char *c = out;

  for (i = 0; i < 8; i++) {
    *(c++) = hextochar[((*in) >> 4) & 0x0f];
    *(c++) = hextochar[(*in++) & 0x0f];
  }
  *c = 0;

  return out;
}

/* Convert 8-byte hex-ascii string to binary array
 */
char *otp_atob8 (char *out, char *in)
{
  register int i;
  register int val;

  for (i = 0; i < 8; i++) {
    while (*in == ' ' || *in == '\t')
      in++;
    if (!*in)
      return NULL;

    if ((*in >= '0') && (*in <= '9'))
      val = *(in++) - '0';
    else
      if ((*in >= 'a') && (*in <= 'f'))
        val = *(in++) - 'a' + 10;
      else
        if ((*in >= 'A') && (*in <= 'F'))
          val = *(in++) - 'A' + 10;
        else
	  return NULL;

    *out = val << 4;

    while (*in == ' ' || *in == '\t')
      in++;
    if (!*in)
      return NULL;

    if ((*in >= '0') && (*in <= '9'))
      val = *(in++) - '0';
    else
      if ((*in >= 'a') && (*in <= 'f'))
        val = *(in++) - 'a' + 10;
      else
        if ((*in >= 'A') && (*in <= 'F'))
          val = *(in++) - 'A' + 10;
        else
          return NULL;

    *out++ |= val;
  }

  return out;
}


#define RESPONSE_STANDARD  0
#define RESPONSE_WORD      1
#define RESPONSE_HEX       2
#define RESPONSE_INIT_HEX  3
#define RESPONSE_INIT_WORD 4
#define RESPONSE_UNKNOWN   5

struct _rtrans {
  int type;
  char *name;
};

static struct _rtrans rtrans[] = {
  { RESPONSE_WORD, "word" },
  { RESPONSE_HEX, "hex" },
  { RESPONSE_INIT_HEX, "init-hex" },
  { RESPONSE_INIT_WORD, "init-word" },
  { RESPONSE_STANDARD, "" },
  { RESPONSE_UNKNOWN, NULL }
};

//static char *algids[] = { NULL, NULL, NULL, "sha1", "md4", "md5" };

#if 0
static int changed (struct otp *otp)
{
  struct otp otp;

  memset(&otp2, 0, sizeof(struct otp));
  otp2.otp_principal = otp->otp_principal;
  if (__opiereadrec(&otp2))
    return 1;

  if ((otp2.otp_n != otp->otp_n) || strcmp(otp2.otp_val, otp->otp_val) 
      || strcmp(otp2.otp_seed, otp->otp_seed))
    return 1;

  memset(&otp2, 0, sizeof(struct otp));
  return 0;
}
#endif /* 0 */
int otp_verify (struct otp *otp, char *response)
{
  int i, rval = -1;
  char *c;
  char key[8], fkey[8], lastkey[8];

  if (!otp || !response)
    goto verret;

  if (!otp->otp_principal)
    goto verret;

  if (!otp_atob8(lastkey, otp->otp_val))
    goto verret;

  if (c = strchr(response, ':')) {
    *(c++) = 0;
    {
      struct _rtrans *r;
      for (r = rtrans; r->name && strcmp(r->name, response); r++);
      i = r->type;
    }
  } else
    i = RESPONSE_STANDARD;

  switch(i) {
  case RESPONSE_STANDARD:
    i = 1;
    
    if (otp_etob(key, response) == 1) {
      memcpy(fkey, key, sizeof(key));
      otp_hash(fkey);
      i = memcmp(fkey, lastkey, sizeof(key));
    }
    if (i && otp_atob8(key, response)) {
      memcpy(fkey, key, sizeof(key));
      otp_hash(fkey);
      i = memcmp(fkey, lastkey, sizeof(key));
    }
    break;
  case RESPONSE_WORD:
    i = 1;

    if (otp_etob(key, c) == 1) {
      memcpy(fkey, key, sizeof(key));
      otp_hash(fkey);
      i = memcmp(fkey, lastkey, sizeof(key));
    }
    break;
  case RESPONSE_HEX:
    i = 1;

    if (otp_atob8(key, c)) {
      memcpy(fkey, key, sizeof(key));
      otp_hash(fkey);
      i = memcmp(fkey, lastkey, sizeof(key));
    }
    break;
  case RESPONSE_INIT_HEX:
  case RESPONSE_INIT_WORD:
#if 0
    {
      char *c2;

      if (!(c2 = strchr(c, ':')))
	goto verret;

      *(c2++) = 0;

      if (i == RESPONSE_INIT_HEX) {
	if (!otp_atob8(key, c))
	  goto verret;
      } else {
	if (otp_etob(key, c) != 1)
	  goto verret;
      }

      memcpy(fkey, key, sizeof(key));
      otp_hash(fkey);

      if (memcmp(fkey, lastkey, sizeof(key)))
	goto verret;

      if (changed(otp))
	goto verret;
      
      otp->otp_n--;

      if (!otp_btoa8(otp->otp_val, key))
	goto verret;

      if (__opiewriterec(otp))
	goto verret;

      if (!(c2 = strchr(c = c2, ':')))
	goto verret;

      *(c2++) = 0;

      {
	int j, k;

	if (__opieparsechallenge(c, &j, &(otp->otp_n), &(otp->otp_seed), &k) || (j != MDX) || k)
	  goto verret;
      }

      if (i == RESPONSE_INIT_HEX) {
	if (!otp_atob8(key, c2))
	  goto verret;
      } else {
	if (otp_etob(key, c2) != 1)
	  goto verret;
      }
    }
    goto verwrt;
#endif /* 0 */
  case RESPONSE_UNKNOWN:
    rval = 1;
    goto verret;
  default:
    rval = -1;
    goto verret;
  }

  if (i) {
    rval = 1;
    goto verret;
  }

#if 0
  if (changed(otp))
    goto verret;
#endif  
  otp->otp_n--;

  //verwrt:
  if (!otp_btoa8(otp->otp_val, key))
    goto verret;
  //  rval = __opiewriterec(otp);
  rval = 0;
verret:
  //  opieunlock();
  //  memset(otp, 0, sizeof(struct otp));
  return rval;
}

/* seed must point to buffer at least OTP_SEED_MAX+1 chars long
   prefix must point to a string at most OTP_SEED_MAX-4 chars long
   return 0 and new seed string in seed
   or -1 (bad parameters)
 */
static int _newseed (const char *prefix,char *seed) {
  time_t now;

  if (!prefix || !seed || strlen(prefix) > OTP_SEED_MAX - 4 ) {
    return -1;
  }
  time(&now);
  srand(now);

  sprintf(seed,"%s%04d",prefix,(rand() % 9999) + 1);
  return 0;
}

static int _keycrunch(const char *seed,const char *secret,char *result) {
  char *cp,*cp2;
  int len;
  int ret = -1;

  if (!seed || ! secret || !result) {
    return -1;
  }

  len = strlen(seed) + strlen(secret);
  cp2 = cp = slapi_ch_calloc(len + 1, sizeof(char));
  
  while(*seed)
    if (isspace(*(cp2++) = tolower(*(seed++))))
      goto kcret;
  
  while ((*cp2 = *(secret++)) != 0)
    cp2++;

  *cp2 = 0;

#if DEBUG & DBG_OTP
  slapi_log_error(SLAPI_LOG_PLUGIN,"_keycrunch","cp=%s, len=%d\n",cp,len);
#endif
  otp_hashlen(cp,result,len);
#if DEBUG & DBG_OTP
  {
    char buf[256];
    slapi_log_error(SLAPI_LOG_PLUGIN,"_keycrunch","result=%s\n",
		    otp_btoa8(buf,result));
  }
#endif  
  ret = 0;

 kcret:
  cp2 = cp;
  while (*cp2)
    *(cp2++) = 0;

  slapi_ch_free((void **)&cp);

  return(ret);
}

struct otp *otp_new (void) {
  struct otp *o;

  o = (struct otp *)slapi_ch_calloc(1,sizeof(struct otp));

  return(o);
}

void otp_free (struct otp *o) {
  if (o) {
    slapi_ch_free((void**)&o->otp_principal);
    slapi_ch_free((void**)&o->otp_seed);
    slapi_ch_free((void**)&o->otp_val);
    slapi_ch_free((void**)&o);
  }
}

int otp_password (struct otp *o,struct udb_global *ug,char *pw) {
#define PREF "mal"
  if (pw == NULL || pw[0] == 0) {
    o->otp_n = 0;
    o->otp_seed = NULL;
    o->otp_val = NULL;
  } else {
    int i;
    char key[8];

    if (_newseed(ug->otp_seed_prefix,o->otp_buf)) {
      slapi_log_error(SLAPI_LOG_PLUGIN,"otp_password","newseed error\n");
      return(-1);
    }
    o->otp_seed = slapi_ch_strdup(o->otp_buf);
    o->otp_n = ug->otp_n;

    if (_keycrunch(o->otp_seed,pw,key)) {
      return -1;
    }
#if DEBUG & DBG_OTP
    slapi_log_error(SLAPI_LOG_PLUGIN,"otp_password",
		    "keycrunch=%s\n",otp_btoa8(o->otp_buf,key));
#endif
    for (i = o->otp_n ; i; i--) {
      otp_hash(key);
    }
    if (!otp_btoa8(o->otp_buf,key)) {
      return -1;
    }
    o->otp_val = slapi_ch_strdup(o->otp_buf);
  }
  return 0;
}
