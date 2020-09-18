#include <string.h>
#include <time.h>
#include "slapi-plugin.h"
#include "udb_config.h"
#include "udb.h"
#include "util.h"
#include "udb_log.h"

UDB_FUNC(string_constant) 
{
  int	i;

  *res = (LDAPMod *)slapi_ch_calloc(1,sizeof(LDAPMod));
  (*res)->mod_op = cfgmod->mod_op;
  (*res)->mod_type = slapi_ch_strdup(cfgmod->mod_type);
  (*res)->mod_values = (char **)slapi_ch_calloc(cfgmod->argc+1,sizeof(char*));
  for (i = 0; i < cfgmod->argc; i++)
    (*res)->mod_values[i] = slapi_ch_strdup(cfgmod->argv[i]);
  return 0;
}

UDB_FUNC(opinit_time)
{
  char		ident[] = MIDENT("opinit_time");
  time_t	t;
  struct tm	tm;	
  char		buf[16];

  if (slapi_pblock_get(pb,SLAPI_OPINITIATED_TIME,&t)) {
    //    slapi_log_error(LOG_("Can't get opinit time\n"));
    log_err(ERR_PBLOCK, ident, "Can't get opinit time\n");
  }

  memset(buf,0,16);
  localtime_r(&t,&tm);
  strftime(buf,15,"%Y%m%d%H%M%S",&tm);
  
  *res = (LDAPMod *)slapi_ch_calloc(1,sizeof(LDAPMod));
  (*res)->mod_op = cfgmod->mod_op;
  (*res)->mod_type = slapi_ch_strdup(cfgmod->mod_type);
  (*res)->mod_values = (char **)slapi_ch_calloc(2,sizeof(char*));
  (*res)->mod_values[0] = slapi_ch_strdup(buf);
  return 0;
}

UDB_FUNC(conn_dn)
{
  char		ident[] = MIDENT("conn_dn");
  char		*dn = NULL;
  
  if (slapi_pblock_get(pb,SLAPI_CONN_DN,&dn)) {
    log_err(ERR_PBLOCK, ident, "Can't get connection DN\n");
      //    slapi_log_error(LOG_("Can't get connection DN\n"));
  }

  *res = (LDAPMod *)slapi_ch_calloc(1,sizeof(LDAPMod));
  (*res)->mod_op = cfgmod->mod_op;
  (*res)->mod_type = slapi_ch_strdup(cfgmod->mod_type);
  (*res)->mod_values = (char**)slapi_ch_calloc(2,sizeof(char*));
  (*res)->mod_values[0] = slapi_ch_strdup(dn);
  return 0;
}

UDB_FUNC(concat)
{
  char	ident[] = MIDENT("concat");
  int	i,len = 0,olen = 0;
  char	*newstr = NULL;

  *res = (LDAPMod *)slapi_ch_calloc(1,sizeof(LDAPMod));
  (*res)->mod_op = cfgmod->mod_op;
  (*res)->mod_type = slapi_ch_strdup(cfgmod->mod_type);
  (*res)->mod_values = (char **)slapi_ch_calloc(2,sizeof(char*));
  
  for (i = olen = 0; i < cfgmod->argc; i++) {
    char *freeme = NULL;

    if (cfgmod->argv[i][0] == '$') {
      freeme = newstr = slapi_entry_attr_get_charptr(e,&cfgmod->argv[i][1]);
#if DEBUG
      slapi_log_error(LOG_("var=%s, ${%s}, val=%s\n"),cfgmod->argv[i],&cfgmod->argv[i][1],newstr);
#endif 
    } else { 
      newstr = cfgmod->argv[i];
#if DEBUG
      slapi_log_error(LOG_("const val=%s\n"),newstr);
#endif 
    }
    len += strlen(newstr);
#if DEBUG
      slapi_log_error(LOG_("before realloc(%p,%d)\n"),
		      (*res)->mod_values[0],len+1);
#endif 
    (*res)->mod_values[0] = slapi_ch_realloc((*res)->mod_values[0],len+1);
#if DEBUG
      slapi_log_error(LOG_("realloc returned %p\n"),
		      (*res)->mod_values[0]);
#endif 
    strcpy((*res)->mod_values[0] + olen,newstr);
#if DEBUG
      slapi_log_error(LOG_("after strcpy\n"));
#endif 
    olen = len;
#if DEBUG
    slapi_log_error(LOG_("result val=\"%s\"\n"),(*res)->mod_values[0]);
#endif 

    slapi_ch_free((void**)&freeme);
  }
  return 0;
}
