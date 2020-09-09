
#ifndef lint
static char rcsid[] = "$Id: util.c,v 1.2 1999/08/20 18:24:12 sova Exp sova $";
#endif /* lint */

#include <string.h>
#include "slapi-plugin.h"
#include "util.h"
#include "udb_log.h"

int get_conop(Slapi_PBlock *pb,char *ident,int *conn,int *opret) {
  if (slapi_pblock_get(pb,SLAPI_CONN_ID,conn)) {
    log_err(ERR_PBLOCK,ident,"Can't get connection id\n");
    return -1;
  } 
  if (slapi_pblock_get(pb,SLAPI_PLUGIN_OPRETURN,opret)) {
    log_err(ERR_PBLOCK,ident,"Can't get opreturn\n");
    return -1;
  }
  return 0;
}

int print_mods(LDAPMod **mods, char *ident,int conn) {
  LDAPMod **m;
  int modcnt;

  for (m = mods,modcnt=0; *m != NULL; m++,modcnt++) {
    //    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","mod=%p\n",*m);
    log_info(ident,"mod #%d (%p): mod_op=0x%x, mod_type=%s, mod_op_stripped=0x%x\n",
	     modcnt,*m,(*m)->mod_op,(*m)->mod_type,
	     (*m)->mod_op & ~LDAP_MOD_BVALUES);
    if ((*m)->mod_op & LDAP_MOD_BVALUES) {
      struct berval **bv;

      if ((*m)->mod_bvalues == NULL) {
	log_info(ident,"no bvalues\n");
      } else {
	for (bv = (*m)->mod_bvalues; *bv != NULL; bv++) {
	  log_info(ident,"bv_len=%lu,bv_val=%.200s\n",
		   (*bv)->bv_len,(*bv)->bv_val);
	}
      }
    } else {
      char **cpp;

      if ((*m)->mod_values == NULL) {
	log_info(ident,"no values\n");
      } else {
	for (cpp = (*m)->mod_values; *cpp != NULL; cpp++) {
	  log_info(ident,"mod_values=%p\n",cpp);
	  log_info(ident,"strval=%.200s\n",*cpp);
	}
      }
    }
  }
  return(modcnt);
}

int get_target_entry (Slapi_DN *dn,Slapi_Entry **entry, int conn, void *caller) {
  char ident[] = MIDENT("get_target_entry");
  int ret=-1;
  //  Slapi_PBlock *ipb = NULL;

  ret = slapi_search_internal_get_entry(dn, NULL, entry, caller);
  if (ret != LDAP_SUCCESS) {
    log_err(ERR_LDAP_OPERATION,ident,
      "Internal search (dn:%s) error: %s\n",
      dn,ldap_err2string(ret));
  }
  return ret;
}

#if OBSOLETE
int get_target_entry_old(char *dn,Slapi_Entry **entry,int conn) {
  char ident[] = "get_target_entry";
  int ret=-1;
  Slapi_PBlock *ipb = NULL;
  Slapi_Entry **entries;

  ipb = slapi_search_internal(dn,LDAP_SCOPE_BASE,"(objectclass=*)",
			       NULL,NULL,0);
  if (slapi_pblock_get(ipb,SLAPI_PLUGIN_INTOP_RESULT,&ret)) {
    slapi_log_error(LOG_("Can't get internal search result\n"));
    goto cleanup;
  }

  if (ret != LDAP_SUCCESS) {
    slapi_log_error(LOG_("Internal search (dn:%s) error: %s\n"),
		    dn,ldap_err2string(ret));
    goto cleanup;
  }

  if (slapi_pblock_get(ipb,SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,&entries)) {
    slapi_log_error(LOG_("Can't get entry for %d\n"));
    ret = -1;
    goto cleanup;
  }
  
  if (entries[0] == NULL) {
    *entry = NULL;
  } else {
    *entry = slapi_entry_dup(entries[0]);
  }
  ret = LDAP_SUCCESS;

 cleanup:
  if (ipb) {
    slapi_free_search_results_internal(ipb);
#if DEBUG & DEBUG_MEM
    slapi_log_error(LOG_(__FILE__ ":" __LINE__ "about to call slapi_pblock_destroy\n"));
#endif
    slapi_pblock_destroy(ipb);
#if DEBUG & DEBUG_MEM
    slapi_log_error(LOG_("after slapi_pblock_destroy\n"));
#endif
  }
  return(ret);
}
#endif /* OBSOLETE */

void berInitStr(struct berval *bv,char *val,int copy) {
  bv->bv_len = strlen(val);
  bv->bv_val = (copy ? slapi_ch_strdup(val) : val);
}

void LDAPMod_free(LDAPMod *lm) 
{
  if (lm) {
    if (lm->mod_type)
      slapi_ch_free((void**)&lm->mod_type);

    if (lm->mod_op & LDAP_MOD_BVALUES) {
      struct berval **bv;

      for (bv = lm->mod_bvalues; *bv; bv++) {
	slapi_ch_free((void**)&(*bv)->bv_val);
	slapi_ch_free((void**)bv);
      }
      slapi_ch_free((void**)&lm->mod_bvalues);
    } else {
      char **cpp;

      for (cpp = lm->mod_values; *cpp; cpp++) {
	slapi_ch_free((void**)cpp); 
      }
      slapi_ch_free((void**)&lm->mod_values);
    }
    lm = NULL;
  }
}
