/* $Id: util.h,v 1.2 1999/08/20 18:24:12 sova Exp sova $ */

#ifndef UTIL_H
#define UTIL_H

#define	DBG_CONS	8
#define	DBG_LOCK	16
#define DBG_TRACE	32
#define DBG_INTERNAL	64
#define DBG_PASSWORD	128
#define DBG_MODS	256
#define DBG_MEM		512
#define DBG_ENTRIES	1024
#define DBG_OTP		2048
#define DBG_CLOSEST_MATCH	4096

#define LOG_(x)		SLAPI_LOG_PLUGIN,ident,"conn=%d " x,conn
#define initMod(m,o,t)	(m).mod_op = (o),(m).mod_type = (t)

int get_conop(Slapi_PBlock *,char *,int *,int *);
int get_target_entry(Slapi_DN *,Slapi_Entry **,int, void *);
void berInitStr(struct berval *,char *,int);
int print_mods(LDAPMod **, char *,int);
void LDAPMod_free(LDAPMod *);

#endif /* UTIL_H */
