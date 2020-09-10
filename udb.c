#ifndef lint
static char rcsid[] = "$Id: udb.c,v 1.5 1999/11/19 09:54:59 sova Exp sova $";
#endif

#include "udb.h"
#include "udb_hash.h"
#include "slapi-plugin.h"
#include "otp_password.h"
#include "util.h"

#include <stdio.h>	/* sprintf */
#include <string.h>	/* strncmp */

#ifndef DEBUG
#define DEBUG 1
#endif

#define ERRBUFSZ		256
#define MOD_TYPE_PW_CLEAR	"unhashed#user#password"


#define MESSAGE_ONE_PW		"Only single value allowed for userPassword\n"
#define MESSAGE_INTERNAL_ERROR	"Internal server error"

#define LOG_HEAD	SLAPI_LOG_PLUGIN,ident,"conn=%d op=%d"
#define LOG_TAIL	conn


static int passwd_from_mod(LDAPMod *m,char **pw,int conn) {
  char ident[] = "passwd_from_mod";

  if (m->mod_op & LDAP_MOD_BVALUES) {
    struct berval **bv;

    /* only accept single value for userPassword */
    bv = m->mod_bvalues;
#if DEBUG & DBG_PASSWORD
    slapi_log_error(LOG_("bv_len=%lu, bv_val=%.200s\n"),
		    (*bv)->bv_len,(*bv)->bv_val);
#endif
    if (*(bv + 1) != NULL) {
      slapi_log_error(LOG_("more than one value for userPassword\n"));
      return(LDAP_OTHER);
    }

    *pw = slapi_ch_calloc((*bv)->bv_len + 1, sizeof(char));
    memcpy(*pw,(*bv)->bv_val,(*bv)->bv_len);
  } else {

#if DEBUG & DBG_PASSWORD
    slapi_log_error(LOG_("val=%.200s\n"),
		    *(m->mod_values));
#endif
    /* only accept single value for userPassword */
    if (*(m->mod_values + 1) != NULL) {
      slapi_log_error(LOG_("more than one value for userPassword\n"));
      return(LDAP_OTHER);
    }
      
    *pw = slapi_ch_strdup(*m->mod_values);
  }
#if DEBUG & DBG_PASSWORD
  slapi_log_error(LOG_("password=%s (at %p)\n"),*pw,*pw);
#endif
  return(LDAP_SUCCESS);
}


static int do_otp(Slapi_PBlock *pb,char *dn,char *pw,int conn) {
  char ident[] = "do_otp";
  LDAPMod otpCount,otpSeed,otpValue;
  LDAPMod *mods[4];
  struct otp *o;
  int ret = -1, mod_result;
  Slapi_PBlock *rpb=NULL;
  struct udb_global *ug;

#if DEBUG & DBG_TRACE
  slapi_log_error(LOG_("starting with dn=%s,pw=%s\n"),dn,pw);
#endif
  if ((o = otp_new()) == NULL) {
    slapi_log_error(LOG_("Can't get otp structure\n"));
    return(-1);
  }
  
  if (slapi_pblock_get(pb,SLAPI_PLUGIN_PRIVATE,&ug)) {
    slapi_log_error(LOG_("Can't get private data\n"));
    goto cleanup;
  }

  if (otp_password(o,ug,pw)) {
    slapi_log_error(LOG_("cannot create OTP\n"));
    goto cleanup;
  }

  initMod(otpCount,LDAP_MOD_REPLACE,A_OTP_N);
  initMod(otpSeed,LDAP_MOD_REPLACE,A_OTP_SEED);
  initMod(otpValue,LDAP_MOD_REPLACE,A_OTP_VAL);
  
  otpCount.mod_values = (char **)slapi_ch_calloc(2,sizeof(char*));
  sprintf(o->otp_buf,"%d",o->otp_n);
  otpCount.mod_values[0] = o->otp_buf;
  
  otpSeed.mod_values = (char **)slapi_ch_calloc(2,sizeof(char*));
  otpSeed.mod_values[0] = o->otp_seed;

  otpValue.mod_values = (char **)slapi_ch_calloc(2,sizeof(char*));
  otpValue.mod_values[0] = o->otp_val;

  mods[0] = &otpValue;
  mods[1] = &otpSeed;
  mods[2] = &otpCount;
  mods[3] = NULL;

#if DEBUG & DBG_MODS
  print_mods(mods,"otp_mods",conn);
#endif
  rpb = slapi_modify_internal(dn,mods,NULL,1);

  if (slapi_pblock_get(rpb,SLAPI_PLUGIN_INTOP_RESULT,&mod_result)) {
    slapi_log_error(LOG_("Can't get modify result\n"));
    goto cleanup;
  }
  
  if (mod_result == LDAP_SUCCESS) {
    ret = 0;
  } else {
    slapi_log_error(LOG_("Error modifyng otp: %d\n"),mod_result);
  }
 cleanup:
  otp_free(o);
  slapi_ch_free((void**)&otpCount.mod_values);
  slapi_ch_free((void**)&otpSeed.mod_values);
  slapi_ch_free((void**)&otpValue.mod_values);

  /* shouldn't we free rpb? */
  // let's try and see
#if DEBUG & DEBUG_MEM
  slapi_log_error(LOG_(__FILE__ ":" __LINE__ "about to call slapi_pblock_destroy\n"));
#endif
  slapi_pblock_destroy(rpb);
#if DEBUG & DEBUG_MEM
  slapi_log_error(LOG_("after slapi_pblock_destroy\n"));
#endif

#if DEBUG & DBG_TRACE
  slapi_log_error(LOG_("returning %d\n"),ret);
#endif
  return(ret);
}

static int del_otp(char *dn,int conn) {
  char ident[] = "del_otp";
  char *nullval = NULL;
  LDAPMod otpCount={LDAP_MOD_DELETE,A_OTP_N,{NULL}};
  LDAPMod otpValue={LDAP_MOD_DELETE,A_OTP_VAL,{NULL}};
  LDAPMod otpSeed={LDAP_MOD_DELETE,A_OTP_SEED,{NULL}};
  LDAPMod *mods[4]; /* = {&otpCount,&otpValue,&otpSeed,NULL}; */
  Slapi_PBlock *rpb;
  int i,mod_result;

#if DEBUG & DBG_TRACE
  slapi_log_error(LOG_("starting with dn=%s\n"),dn);
#endif
  
  mods[0] = &otpCount;
  mods[1] = &otpValue;
  mods[2] = &otpSeed;
  mods[3] = NULL;

  for (i = 0; i < 3; i++) {
    mods[i]->mod_values = &nullval;
      /*(char **)slapi_ch_calloc(1,sizeof(char *));*/
  }
#if DEBUG & DBG_MODS
  slapi_log_error(LOG_("modcnt=%d\n"),print_mods(mods,"del_otp",conn));
#endif

  rpb = slapi_modify_internal(dn,mods,NULL,1);

#if DEBUG & DBG_INTERNAL
  slapi_log_error(LOG_("rpb=%p\n"),rpb);
#endif
  if (slapi_pblock_get(rpb,SLAPI_PLUGIN_INTOP_RESULT,&mod_result)) {
    slapi_log_error(LOG_("Can't get modify result\n"));
    return -1;
  }
  
  // let's try and see
#if DEBUG & DEBUG_MEM
  slapi_log_error(LOG_(__FILE__ ":" __LINE__ "about to call slapi_pblock_destroy\n"));
#endif
  slapi_pblock_destroy(rpb);
#if DEBUG & DEBUG_MEM
  slapi_log_error(LOG_("after slapi_pblock_destroy\n"));
#endif

  if (mod_result == LDAP_SUCCESS) {
    return 0;
  } else {
    slapi_log_error(LOG_("Error modifyng otp: %d\n"),mod_result);
    return -1;
  }
}

int do_mods(Slapi_PBlock *pb) {
  char ident[] = "do_mods";
  LDAPMod **mods;
  LDAPMod **m;
  Slapi_Entry *e_target;
  /*  Slapi_Attr *attr; */
  int modcnt,ret=-1;
  char *pw=NULL,*dn=NULL/*,*binddn=NULL*/;
  /*  char *errbuf; */
  int conn,opret;

  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }
  if (opret != LDAP_SUCCESS) {
    slapi_log_error(LOG_("Preceeding operation returned %d, giving up\n"),
		    opret);
    return 0;
  }

  if (slapi_pblock_get(pb,SLAPI_MODIFY_MODS,&mods)) {
    slapi_log_error(LOG_("Can't get mods\n"));
    return(-1);
  }
  
  if (slapi_pblock_get(pb,SLAPI_MODIFY_TARGET,&dn)) {
    slapi_log_error(LOG_("Can't get dn\n"));
    return(-1);
  }

  if (get_target_entry(dn,&e_target,conn) != LDAP_SUCCESS) {
    return(-1);
  }
  /* seems like this is handled by get_conop
     - precceding operation should have returned error */
#if 0
  if (slapi_acl_check_mods(pb,e_target,mods,&errbuf) != LDAP_SUCCESS) {
    /* access for client mods denied - skip our work too */
    return(0);
  }
#endif
#if DEBUG & DBG_MODS
  print_mods(mods,"init mods",conn);
#endif
  /* find the userPassword cleartext */
  for (m = mods,modcnt=0; *m != NULL; m++,modcnt++) {
    /*    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","mod=%p\n",*m); */
#if (DEBUG & DBG_MODS)
    slapi_log_error(LOG_("mod #%d (%p): mod_op=0x%x, mod_type=%s, mod_op_stripped=0x%x\n"),
		    modcnt,*m,(*m)->mod_op,(*m)->mod_type,
		    (*m)->mod_op & ~LDAP_MOD_BVALUES);
#endif
    if (strncmp(MOD_TYPE_PW_CLEAR,
		(*m)->mod_type,strlen(MOD_TYPE_PW_CLEAR)) == 0) {

      if (passwd_from_mod(*m,&pw,conn) != LDAP_SUCCESS) {
	goto cleanup;
      }
	
#if DEBUG & DGB_PASSWORD
      slapi_log_error(LOG_("pw=%s (at %p)\n"),pw,pw);
#endif
      switch ((*m)->mod_op & ~LDAP_MOD_BVALUES) {
      case LDAP_MOD_ADD:
	/* single value for userPassword constraint handled in check_mods */
      case LDAP_MOD_REPLACE:
	if (do_otp(pb,dn,pw,conn)) {
	  slapi_log_error(LOG_("Error updating OTP\n"));
	  goto cleanup;
	}
	ret = 0;
	break;
      }
    } else if ((*m)->mod_op & LDAP_MOD_DELETE
	       && (strncmp("userpassword",
			   (*m)->mod_type,strlen(MOD_TYPE_PW_CLEAR)) == 0)) {
#if DEBUG
      slapi_log_error(LOG_("gonna delete otp\n"));
#endif
      if (del_otp(dn,conn)) {
	slapi_log_error(LOG_("Error deleting OTP\n"));
	goto cleanup;
      }
      ret = 0;
    }
  }
  /* no userPassword */
  ret = 0;
 cleanup:
  slapi_ch_free((void**)&pw);
  slapi_entry_free(e_target);
  slapi_log_error(LOG_("returning %d\n"),ret);
  return ret;
}

int check_mods(Slapi_PBlock *pb) {
  char ident[] = "check_mods";
  LDAPMod **mods,**m;
  Slapi_Entry *e_target=NULL;
  Slapi_Attr *attr;
  char *dn;
  int conn,opret,ret=-1;

  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }
  if (opret != LDAP_SUCCESS) {
    slapi_log_error(LOG_("Preceeding operation returned %d, giving up\n"),
		    opret);
    return 0;
  }
  
  if (slapi_pblock_get(pb,SLAPI_MODIFY_MODS,&mods)) {
    slapi_log_error(LOG_("Can't get mods\n"));
    return(-1);
  }
  
  if (slapi_pblock_get(pb,SLAPI_MODIFY_TARGET,&dn)) {
    slapi_log_error(LOG_("Can't get dn\n"));
    return(-1);
  }

  if (get_target_entry(dn,&e_target,conn, (void *)&mypdesc) != LDAP_SUCCESS) {
    return(-1);
  }

  for (m = mods; *m != NULL; m++) {
    if (strncmp(MOD_TYPE_PW_CLEAR,
		(*m)->mod_type,strlen(MOD_TYPE_PW_CLEAR)) == 0) {
      if(((*m)->mod_op & ~LDAP_MOD_BVALUES) == LDAP_MOD_ADD
	 && (slapi_entry_attr_find(e_target,"userpassword",&attr) == 0)) {
	slapi_log_error(LOG_("Won't add another userPassword for %s\n"),dn);
	slapi_send_ldap_result(pb,LDAP_CONSTRAINT_VIOLATION,NULL,
			       MESSAGE_ONE_PW,0,NULL);
	goto cleanup;
      }
    }
  }
  ret = 0;
 cleanup:
  if (e_target) slapi_entry_free(e_target);
#if DEBUG
  slapi_log_error(LOG_("returning %d\n"),ret);
#endif
  return ret;
}

int check_add(Slapi_PBlock *pb) {
  char ident[] = "check_add";
  Slapi_Entry *e;
  Slapi_Attr *a;
  struct berval **vals;
  char *dn;
  int conn,opret;

  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }
  if (opret != LDAP_SUCCESS) {
    slapi_log_error(LOG_("Preceeding operation returned %d, giving up\n"),
		    opret);
    return 0;
  }
  if (slapi_pblock_get(pb,SLAPI_ADD_TARGET,&dn)) {
    slapi_log_error(LOG_("Can't get dn\n"));
    return -1;
  }
  if (slapi_pblock_get(pb,SLAPI_ADD_ENTRY,&e)) {
    slapi_log_error(LOG_("Can't get entry\n"));
    return -1;
  }
  /* check values count of userPassword */
  if (slapi_entry_attr_find(e,"userpassword",&a) != 0) {
    /* no value */
    return 0;
  } else {
    if (slapi_attr_get_values(a,&vals)) {
      slapi_log_error(LOG_("Can't get userPassword values\n"));
      return -1;
    }
    if (*(vals+1) != NULL) {
      slapi_log_error(LOG_("userPassword: not a single value\n"));
      slapi_send_ldap_result(pb,LDAP_CONSTRAINT_VIOLATION,NULL,
			     MESSAGE_ONE_PW,0,NULL);
      return -1;
    }
  }
  return 0;
}

int do_add(Slapi_PBlock *pb) {
  char ident[] = "check_add";
  Slapi_Entry *e;
  char *dn,*pw;
  int conn,opret;
  int ret = -1;

  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }
  if (opret != LDAP_SUCCESS) {
    slapi_log_error(LOG_("Preceeding operation returned %d, giving up\n"),
		    opret);
    return 0;
  }
  if (slapi_pblock_get(pb,SLAPI_ADD_TARGET,&dn)) {
    slapi_log_error(LOG_("Can't get dn\n"));
    return -1;
  }
  if (slapi_pblock_get(pb,SLAPI_ADD_ENTRY,&e)) {
    slapi_log_error(LOG_("Can't get entry\n"));
    return -1;
  }
  if ((pw = slapi_entry_attr_get_charptr(e,"userpassword")) == NULL) {
    return 0;
  }
  if (do_otp(pb,dn,pw,conn)) {
    slapi_log_error(LOG_("Error updating OTP\n"));
    goto cleanup;
  }
  ret = 0;

 cleanup:
  slapi_ch_free((void**)&pw);
  return ret;
}

#if TEST_FUNCTIONS
int write_mod(Slapi_PBlock *pb ) {
  char *dn;
  LDAPMod **mods;
  LDAPMod **m;
  int modcnt;

  if (slapi_pblock_get(pb,SLAPI_MODIFY_TARGET,&dn)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod","Can't get dn\n");
    return(-1);
  }
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod","dn: %s\n",dn);
  if (slapi_pblock_get(pb,SLAPI_MODIFY_MODS,&mods)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod","Can't get mods\n");
    return(-1);
  }
  
  check_mod_access(pb,dn,mods,0);
  for (m = mods,modcnt=0; *m != NULL; m++,modcnt++) {
    /*    slapi_log_error(SLAPI_LOG_PLUGIN,"mod","mod=%p\n",*m); */
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod",
		    "mod #%d (%p): mod_op=0x%x, mod_type=%s, mod_op_stripped=0x%x\n",
		    modcnt,*m,(*m)->mod_op,(*m)->mod_type,
		    (*m)->mod_op & ~LDAP_MOD_BVALUES);
    if ((*m)->mod_op & LDAP_MOD_BVALUES) {
      struct berval **bv;

      for (bv = (*m)->mod_bvalues; *bv != NULL; bv++) {
	slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod",
			"bv_len=%lu,bv_val=%.200s\n",
			(*bv)->bv_len,(*bv)->bv_val);
      }
    } else {
      char **cpp;

      for (cpp = (*m)->mod_values; *cpp != NULL; cpp++) {
	slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod",
			"mod_values=%p\n",cpp);
	slapi_log_error(SLAPI_LOG_PLUGIN,"write_mod",
			"strval=%.200s\n",*cpp);
      }
    }
  }
  return(0);
}

int write_search(Slapi_PBlock *pb ) {
  char *flt,*dn,*authtype;

  //  get_cfg(pb);

  if(slapi_pblock_get(pb,SLAPI_SEARCH_STRFILTER,&flt)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","Can't get parameters\n");
    return(-1);
  }
  if(slapi_pblock_get(pb,SLAPI_CONN_DN,&dn)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","Can't get parameters\n");
    return(-1);
  }
  if(slapi_pblock_get(pb,SLAPI_CONN_AUTHTYPE,&authtype)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","Can't get parameters\n");
    return(-1);
  }
  
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","conn_dn: \"%s\"\n",dn);
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","conn_authtype: \"%s\"\n",authtype);
  slapi_log_error(SLAPI_LOG_PLUGIN,"write_search","flt: \"%s\"\n",flt);
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
#endif

int pre_init(Slapi_PBlock *pb) {
  if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_DESCRIPTION,(void *)&mypdesc )
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_MODIFY_FN,(void*)check_mods)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_ADD_FN,(void*)check_add)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP pre","something went bad\n");
  } else { 
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP pre","%s loaded\n",rcsid);
  }
  return(0);
}

int post_init(Slapi_PBlock *pb) {
  int ac;
  char **ag;
  struct udb_global *ug;

  if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_DESCRIPTION,(void *)&mypdesc )
      || slapi_pblock_set(pb,SLAPI_PLUGIN_POST_MODIFY_FN,(void*)do_mods)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_POST_ADD_FN,(void*)do_add)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"postinit","something went bad\n");
    return -1;
  }

  if (slapi_pblock_get(pb,SLAPI_PLUGIN_ARGC,&ac)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP","Can't get arguments count\n");
    return -1;
  }
  
  if (ac != 2) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP",
		    "Bad argument count (%d, must be 2)\n",ac);
    return -1;
  }

  if (slapi_pblock_get(pb,SLAPI_PLUGIN_ARGV,&ag)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP","Can't get arguments\n");
    return -1;
  }

  ug = (struct udb_global *)slapi_ch_calloc(1,sizeof(struct udb_global));
  ug->otp_n = atoi(ag[0]);

  if (ug->otp_n < 1 || ug->otp_n > 9999) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP",
		    "OTP count must be between 1 and 9999\n");
    return -1;
  }

  if (strlen(ag[1]) < 2 || strlen(ag[1]) > 11) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP",
		    "OTP seed prefix must be between 2 and 11 characters long\n");
    return -1;
  }
  ug->otp_seed_prefix = ag[1];

  if (slapi_pblock_set(pb,SLAPI_PLUGIN_PRIVATE,(void *)ug)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP","Can't set global data\n");
    return -1;
  }
#if notdef
  {
    // FAKE
    char tmpbuf[2048];
    int i;

    strcpy(tmpbuf,"arguments (ac=%d):");
    for (i = 0; i < ac; i++) {
      strcat(tmpbuf," ");
      strcat(tmpbuf,ag[i]);
    }
    strcat(tmpbuf,"\n");

    slapi_log_error(SLAPI_LOG_PLUGIN,"postinit",tmpbuf,ac);
  }
#endif
  slapi_log_error(SLAPI_LOG_PLUGIN,"postinit","%s loaded\n",rcsid);
  
  return(0);
}

#if OBSOLETE
static int check_mod_access(Slapi_PBlock *pb,char *dn,LDAPMod **mods,int conn) {
  char ident[] = "check_mod_access";
  Slapi_PBlock *ipb=NULL;
  Slapi_Entry **entries;
  char *attr[] = {"objectclass","uid",NULL};
  int internal_ret;
  char *errbuf = NULL;
  int ret = -1;

#if DEBUG
  slapi_log_error(LOG_("pb=%p, dn=%s\n"),pb,dn);
#endif
  
  ipb = slapi_search_internal(dn,LDAP_SCOPE_BASE,"(objectclass=*)",
			      NULL,attr,1);
#if DEBUG & DBG_INTERNAL
  slapi_log_error(LOG_("ipb=%p\n"),ipb);
#endif

  if (slapi_pblock_get(ipb,SLAPI_PLUGIN_INTOP_RESULT,&internal_ret)) {
    slapi_log_error(LOG_("Can't get internal search result\n"),dn);
    goto cleanup;
  }
  if (internal_ret != LDAP_SUCCESS) {
    slapi_log_error(LOG_("Internal search (dn:%s) error=%d\n"),
		    dn,internal_ret);
    goto cleanup;
  } 
#if DEBUG & DBG_INTERNAL
  slapi_log_error(LOG_("Internal search ok (%d)\n"),internal_ret);
#endif
  if (slapi_pblock_get(ipb,SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,&entries)) {
    slapi_log_error(LOG_("Can't get entry \"%d\"\n"),dn);
    goto cleanup;
  }
#if (DEBUG & DBG_ENTRIES)
  slapi_log_error(LOG_("entries=%p\n"),entries);
  {
    int len;
    slapi_log_error(LOG_("entries[0]=%s\n"),
		    slapi_entry2str(entries[0], &len));
  }
#endif
  /* check the acces rights */
  ret = slapi_acl_check_mods(pb,entries[0],mods,&errbuf);
#if DEBUG
  slapi_log_error(LOG_("internal_ret(access)=%d,errbuff=%s\n"),
		  ret,errbuf ? errbuf : "(empty)");
#endif

 cleanup:
  if (ipb) slapi_free_search_results_internal(ipb);
  return(ret);
}
#endif /* OBSOLETE */
