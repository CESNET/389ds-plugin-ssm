#include "slapi-plugin.h"

#ifndef lint
static char version[] = "$Id: test-preop.c,v 1.2 1999/08/12 18:00:22 sova Exp sova $";
#endif
#define DEBUG 1
#define MOD_TYPE_PW_CLEAR	"unhashed#user#password"

#define MESSAGE_ONE_PW		"Only single value allowed for userPassword\n"
#define MESSAGE_INTERNAL_ERROR	"Internal server error"

static char *passwd_from_mod(Slapi_PBlock *pb,LDAPMod *m) {
  char *pw;

  if (m->mod_op & LDAP_MOD_BVALUES) {
    struct berval **bv;

    /* only accept single value for userPassword */
    bv = m->mod_bvalues;
#if DEBUG
    slapi_log_error(SLAPI_LOG_PLUGIN,"passwd_from_mod",
		    "bv_len=%lu, bv_val=%.200s\n",
		    (*bv)->bv_len,(*bv)->bv_val);
#endif
    if (*(bv + 1) != NULL) {
      slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
		      "more than one value for userPassword\n");
      slapi_send_ldap_result(pb,LDAP_OTHER/*?should send better code?*/,
			     NULL, MESSAGE_ONE_PW,0,NULL);
      return(NULL);
    }

    if ((pw = malloc((*bv)->bv_len + 1)) == NULL) {
      slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
		      "malloc error\n");
      slapi_send_ldap_result(pb,LDAP_OTHER/*?should send better code?*/,
			     NULL, MESSAGE_INTERNAL_ERROR,0,NULL);
      return(NULL);
    }
    memcpy(pw,(*bv)->bv_val,(*bv)->bv_len);
    pw[(*bv)->bv_len] = 0;
  } else {
    int len;

#if DEBUG
    slapi_log_error(SLAPI_LOG_PLUGIN,"passwd_from_mod",
		    "val=%.200s\n",
		    *(m->mod_values));
#endif
    /* only accept single value for userPassword */
    if (*(m->mod_values + 1) != NULL) {
      slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
		      "more than one value for userPassword\n");
      slapi_send_ldap_result(pb,LDAP_OTHER/*?should send better code?*/,
			     NULL, MESSAGE_ONE_PW,0,NULL);
      return(NULL);
    }
      
    len = strlen(*m->mod_values);
    if ((pw = malloc(len + 1)) == NULL) {
      slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
		      "malloc error\n");
      slapi_send_ldap_result(pb,LDAP_OTHER/*?should send better code?*/,
			     NULL, MESSAGE_INTERNAL_ERROR,0,NULL);
      return(NULL);
    }
    memcpy(pw,*m->mod_values,len);
    pw[len] = 0;
  }
#if DEBUG
  slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods","password=%s\n",pw);
#endif
  return(pw);
}

int write_mod(Slapi_PBlock *pb ) {
  char *dn;
  LDAPMod **mods;
  LDAPMod **m;
  int modcnt;

  if (slapi_pblock_get(pb,SLAPI_MODIFY_TARGET,&dn)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","Can't get dn\n");
    return(-1);
  }
  slapi_log_error(SLAPI_LOG_PLUGIN,"mod","dn: %s\n",dn);
  if (slapi_pblock_get(pb,SLAPI_MODIFY_MODS,&mods)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","Can't get mods\n");
    return(-1);
  }
    
  for (m = mods,modcnt=1; *m != NULL; m++,modcnt++) {
    //    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","mod=%p\n",*m);
    slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
		    "mod #%d: mod_op=0x%x, mod_type=%s, mod_op_stripped=%d\n",
		    modcnt,(*m)->mod_op,(*m)->mod_type,
		    (*m)->mod_op | LDAP_MOD_BVALUES);
    if ((*m)->mod_op & LDAP_MOD_BVALUES) {
      struct berval **bv;
      //      unsigned long len;
      //      unsigned long tag;

      for (bv = (*m)->mod_bvalues; *bv != NULL; bv++) {
	slapi_log_error(SLAPI_LOG_PLUGIN,"mod","bv_len=%lu,bv_val=%.200s\n",
			(*bv)->bv_len,(*bv)->bv_val);
      }
    }
  }
  return(0);
}

int check_mods(Slapi_PBlock *pb) {
  LDAPMod **mods;
  LDAPMod **m;
  LDAPMod *m_otpCount,*m_otpSeed,*m_otpValue;
  int modcnt;

  if (slapi_pblock_get(pb,SLAPI_MODIFY_MODS,&mods)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","Can't get mods\n");
    return(-1);
  }
    
  for (m = mods,modcnt=1; *m != NULL; m++,modcnt++) {
#if DEBUG
    slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
		    "mod #%d: mod_op=0x%x, mod_type=%s, mod_op_stripped=0x%x\n",
		    modcnt,(*m)->mod_op,(*m)->mod_type, 
		    (*m)->mod_op & ~LDAP_MOD_BVALUES);
#endif
    if (strcmp((*m)->mod_type,MOD_TYPE_PW_CLEAR) == 0) {
      char *pw;

      switch ((*m)->mod_op & ~LDAP_MOD_BVALUES) {
      case LDAP_MOD_ADD:
	if((pw = passwd_from_mod(pb,*m)) == NULL) {
	  return(-1);
	}
	break;
      case LDAP_MOD_REPLACE:
	if((pw = passwd_from_mod(pb,*m)) == NULL) {
	  return(-1);
	}
	break;
      case LDAP_MOD_DELETE:
	break;
      default:
	slapi_log_error(SLAPI_LOG_PLUGIN,"check_mods",
			"unknown mod_op: 0x%x\n",(*m)->mod_op);
	return(-1);
	break;
      }

      free(pw);
/*       for (bv = (*m)->mod_bvalues; *bv != NULL; bv++) { */
/* 	slapi_log_error(SLAPI_LOG_PLUGIN,"mod","bv_len=%lu,bv_val=%.200s\n", */
/* 			(*bv)->bv_len,(*bv)->bv_val); */
/*       } */
    }
  }
  return(0);
}

int write_search(Slapi_PBlock *pb ) {
  char *flt;

  if(slapi_pblock_get(pb,SLAPI_SEARCH_STRFILTER,&flt)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","Can't get parameters\n");
    return(-1);
  }
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","flt: %s\n",flt);
  return(0);
}

int write_add(Slapi_PBlock *pb) {
  char *target;
  Slapi_Entry *e;
  int len;

  if (slapi_pblock_get(pb,SLAPI_ADD_TARGET,&target)
      || slapi_pblock_get(pb,SLAPI_ADD_ENTRY,&e)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_add","Can't get parameters\n");
    return(-1);
  }
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_add","adding %s\n",target);
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_add","adding %s\n",
		  slapi_entry2str(e,&len ));
  return(0);
}

int pre_init(Slapi_PBlock *pb) {
  Slapi_PluginDesc mypdesc = { "test-plugin", "mylan", "0.1", 
			       "sample pre-operation plugin" };
  if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_DESCRIPTION,(void *)&mypdesc )
      //      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_MODIFY_FN,(void*)write_mod)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_MODIFY_FN,(void*)check_mods)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_SEARCH_FN,(void*)write_search )
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_ADD_FN,(void*)write_add)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"preinit","something went bad\n");
  } else { 
    slapi_log_error(SLAPI_LOG_PLUGIN,"preinit","%s loaded\n",version);
  }
  return(0);
}

int post_init(Slapi_PBlock *pb) {
  Slapi_PluginDesc mypdesc = { "test-plugin", "mylan", "0.1", 
			       "sample pre-operation plugin" };
  if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_DESCRIPTION,(void *)&mypdesc )
      || slapi_pblock_set(pb,SLAPI_PLUGIN_POST_MODIFY_FN,(void*)write_mod)
      //      || slapi_pblock_set(pb,SLAPI_PLUGIN_POST_MODIFY_FN,(void*)check_mods)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_POST_SEARCH_FN,(void*)write_search )
      || slapi_pblock_set(pb,SLAPI_PLUGIN_POST_ADD_FN,(void*)write_add)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"postinit","something went bad\n");
  } else { 
    slapi_log_error(SLAPI_LOG_PLUGIN,"postinit","%s loaded\n",version);
  }
  return(0);
}
