
#ifndef lint
static char rcsid[] = "$Id: otp_sasl.c,v 1.3 1999/11/19 09:53:36 sova Exp sova $";
#endif /* lint */

#include "slapi-plugin.h"
#include "udb.h"
#include "udb_hash.h"
#include "otp_password.h"
#include "util.h"

#include <string.h>
#include <stdio.h>

/* return 0 to pass bind to other modules 
   non-zero to stop binding  here
   2 - challenge sent - don't unlock the user entry
*/
int sasl_otp(Slapi_PBlock *pb) {
  char ident[] = "OTP bind";
  char *sasl_mech=NULL;
  Slapi_Entry *e=NULL;
  int bindmethod,is_response=0;
  struct berval *creq=NULL,cresp;
#define RBUFSZ 128 /* opie.h says 115 */
  char rbuf[RBUFSZ];
  int ret = -1;
  struct otp o;
  int conn,opret;
  htab *ht;
  Slapi_PBlock *mpb = NULL;

  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }

  memset(&o,0,sizeof(struct otp));

  /* Gather the request info */
  if (slapi_pblock_get(pb,SLAPI_BIND_METHOD,&bindmethod)) {
    slapi_log_error(LOG_("Can't get bind method\n"));
    slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
    return -1;
  }
#if DEBUG & DBG_OTP
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"bindmethod=%d\n",bindmethod);
#endif
  if (bindmethod != LDAP_AUTH_SASL) {
    /* no SASL, pass to others */
    return 0;
  }
  if (slapi_pblock_get(pb,SLAPI_BIND_SASLMECHANISM,&sasl_mech)) {
    slapi_log_error(LOG_("Can't get SASL mechanism\n"));
    slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
    return -1;
  }
#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("sasl_mech=%s\n"),sasl_mech);
#endif

  if (strcmp(sasl_mech,LDAP_SASL_OTP)) {
    /* some other SASL mechanism, pass */
    return 0;
  }

  /* OK, we're asked for OTP */
  if (slapi_pblock_get(pb,SLAPI_BIND_TARGET,&o.otp_principal)) {
    slapi_log_error(LOG_("Can't get SASL mechanism\n"));
    slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
    return -1;
  }

#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("dn=%s\n"),o.otp_principal);
#endif

  if (slapi_pblock_get(pb,SLAPI_BIND_CREDENTIALS,&creq)) {
    slapi_log_error(LOG_("Can't get client credentials\n"));
    slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
    return -1;
  }
  if (creq == NULL || creq->bv_len == 0)
    is_response = 0;
  else
    is_response = 1;
  
  /* Lock the record */
  if (slapi_pblock_get(pb,SLAPI_PLUGIN_PRIVATE,&ht)) {
    slapi_log_error(LOG_("Can't get private data"));
    slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
    return -1;
  }

  slapi_dn_normalize_case(o.otp_principal);
#if DEBUG
  slapi_log_error(LOG_("normalized dn: \"%s\"\n"),o.otp_principal);
  slapi_log_error(LOG_("ht=%p\n"),ht);
#endif

  switch (udb_lock(ht,o.otp_principal,conn,is_response)) {
  case 0:
    break;
  case 1:
    /* record locked - refuse binding */
    slapi_log_error(LOG_("\"%s\": entry locked\n"),o.otp_principal);
    slapi_send_ldap_result(pb,LDAP_UNWILLING_TO_PERFORM,NULL,NULL,0,NULL);
    return -1;
    break;
  case 2:
    /* we were sent the response but the record is not locked */
    slapi_send_ldap_result(pb,LDAP_UNWILLING_TO_PERFORM,NULL,NULL,0,NULL);
    return -1;
    break;
  default:
    slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
    return -1;
    break;
  }

  /* Get target entry */
  if (get_target_entry(o.otp_principal,&e,conn, (void *)&mypdesc) != LDAP_SUCCESS
      || e == NULL) {
    char *dn=NULL,*par=NULL;
    Slapi_Entry *e2=NULL;

    slapi_log_error(LOG_("Unknown entry %s\n"),o.otp_principal);

    /* closest match stuff, uff */
    dn = slapi_ch_strdup(o.otp_principal);
#if DEBUG & DBG_CLOSEST_MATCH
    slapi_log_error(LOG_("dn=%s\n"),dn);
#endif
    slapi_dn_normalize_case(dn);

#if DEBUG & DBG_CLOSEST_MATCH
    slapi_log_error(LOG_("case normalized dn=%s\n"),dn);
#endif

    for (par = slapi_dn_parent(dn); 
	 par; 
	 slapi_ch_free((void**)&dn),
	   dn=par,
	   slapi_ch_free((void**)&par), 
	   par = slapi_dn_parent(dn)) {
#if DEBUG & DBG_CLOSEST_MATCH
      slapi_log_error(LOG_("parent %s\n"),par);
#endif
      if (get_target_entry(par,&e2,conn, (void *)&mypdesc) == LDAP_SUCCESS) {
#if DEBUG & DBG_CLOSEST_MATCH
	slapi_log_error(LOG_("closest match is \"%s\"\n"),par);
#endif
	slapi_entry_free(e2);
#if DEBUG & DBG_CLOSEST_MATCH
	slapi_log_error(LOG_("entry freed\n"));
#endif
	break;
      }
    }
    if (par == NULL) {
#if DEBUG & DBG_CLOSEST_MATCH
      slapi_log_error(LOG_("parent not found, dn=%s\n"),dn);
#endif
    } else {
#if DEBUG & DBG_CLOSEST_MATCH
      slapi_log_error(LOG_("parent=%s\n"),par);
#endif
    }

    slapi_send_ldap_result(pb,LDAP_NO_SUCH_OBJECT,par,NULL,0,NULL);
    ret = 1;
    slapi_ch_free((void**)&dn);
    slapi_ch_free((void**)&par);
    goto cleanup;
  }

#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("OTP info for %s\n"),o.otp_principal);
#endif

  /* gather the OTP info from target entry */
  o.otp_n = slapi_entry_attr_get_int(e,A_OTP_N);
#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("OTP count=%d\n"),o.otp_n);
#endif
  
  if ((o.otp_seed = slapi_entry_attr_get_charptr(e,A_OTP_SEED)) == NULL) {
    slapi_log_error(LOG_("No otpseed for %s"),o.otp_principal);
    slapi_send_ldap_result(pb,LDAP_INAPPROPRIATE_AUTH,NULL,NULL,0,NULL);
    goto cleanup;
  }
#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("OTP seed=%s\n"),o.otp_seed);
#endif
  
  if ((o.otp_val = slapi_entry_attr_get_charptr(e,A_OTP_VAL)) == NULL) {
    slapi_log_error(LOG_("No otpvalue for %s"),o.otp_principal);
    slapi_send_ldap_result(pb,LDAP_INAPPROPRIATE_AUTH,NULL,NULL,0,NULL);
    goto cleanup;
  }
#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("OTP value %s\n"),o.otp_val);
#endif
  
  
  /* now what stage are we at?
     with empty credentials from client we can assume that the challenge
     is expected
  */
  if (creq == NULL || creq->bv_len == 0) {
    sprintf(rbuf,"otp-md5 %d %s",o.otp_n-1,o.otp_seed);
#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("sending challenge: %s\n"),rbuf);
#endif
    
    cresp.bv_val = rbuf;
    cresp.bv_len = strlen(rbuf);
    if (slapi_pblock_set(pb,SLAPI_BIND_RET_SASLCREDS,&cresp)) {
      slapi_log_error(LOG_("Can't set OTP challenge"));
      slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
      goto cleanup;
    }
#if DEBUG & DBG_OTP
  slapi_log_error(LOG_("challenge set\n"));
#endif

    slapi_send_ldap_result(pb,LDAP_SASL_BIND_IN_PROGRESS,NULL,
			   "OTP Challenge",0,NULL);
    ret = 2;
    goto cleanup;
  } else {
    /* we've got something from client, let's check it out */
#if DEBUG & DBG_OTP
    slapi_log_error(LOG_("got response \"%s\"\n"),creq->bv_val);
#endif    
    ret = otp_verify(&o,creq->bv_val);
    switch(ret) {
    case -1:
      slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
      break;
    case 1:
      slapi_send_ldap_result(pb,LDAP_INVALID_CREDENTIALS,NULL,NULL,0,NULL);
      break;
    case 0:
      ret = 1; /* bypass the default BIND */
      /* store count and value */
      {
	char *ovals[4] = {NULL,NULL,NULL,NULL};
	LDAPMod otpCount,otpValue;
	LDAPMod *mods[3];
	int mres;

	initMod(otpCount,LDAP_MOD_REPLACE,A_OTP_N);
	initMod(otpValue,LDAP_MOD_REPLACE,A_OTP_VAL);
	otpCount.mod_values = &ovals[0];
	otpValue.mod_values = &ovals[2];

	mods[0] = &otpCount;
	mods[1] = &otpValue;
	mods[2] = NULL;

	sprintf(rbuf,"%d",o.otp_n);
	ovals[0] = rbuf;
	ovals[2] = o.otp_val;

	mpb = slapi_modify_internal(o.otp_principal,mods,NULL,0);
	
	if (slapi_pblock_get(mpb,SLAPI_PLUGIN_INTOP_RESULT,&mres)) {
	  slapi_log_error(LOG_("Can't get modify result\n"));
	  ret = -1;
	  slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
	  goto cleanup;
	}
	if (mres != LDAP_SUCCESS) {
	  slapi_log_error(LOG_("Error modifying OTP status: %s"),
			  ldap_err2string(mres));
	  slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
	  ret = -1;
	  goto cleanup;
	}
      }

      if(slapi_pblock_set(pb,SLAPI_CONN_DN,slapi_ch_strdup(o.otp_principal))
	 || slapi_pblock_set(pb,SLAPI_CONN_AUTHTYPE,SLAPD_AUTH_SASL LDAP_SASL_OTP)) {
	slapi_log_error(LOG_("Can't set CONN_DN or CONN_AUTHTYPE\n"));
	slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
	ret = -1;
	goto cleanup;
      }
#if DEBUG
      slapi_log_error(LOG_("authenticated \"%s\"\n"),o.otp_principal);
#endif
      slapi_send_ldap_result(pb,LDAP_SUCCESS,NULL,NULL,0,NULL);
      break;
    default:
      slapi_send_ldap_result(pb,LDAP_OPERATIONS_ERROR,NULL,NULL,0,NULL);
      break;
    }
    goto cleanup;
  }

 cleanup:
#if DEBUG & DBG_TRACE
  slapi_log_error(LOG_("cleanup started\n"));
#endif
  if (ret != 2)
  {
    void *dummy;
    udb_unlock(ht,o.otp_principal,conn,&dummy);
  }
  if (e) slapi_entry_free(e);
  if (o.otp_seed) slapi_ch_free((void**)&o.otp_seed);
  if (o.otp_val) slapi_ch_free((void**)&o.otp_val);

#if DEBUG & DEBUG_MEM
  slapi_log_error(LOG_(__FILE__ ":" __LINE__ "about to call slapi_pblock_destroy\n"));
#endif
  slapi_pblock_destroy(mpb);
#if DEBUG & DEBUG_MEM
  slapi_log_error(LOG_("after slapi_pblock_destroy\n"));
#endif

#if DEBUG & DBG_TRACE
  slapi_log_error(LOG_("returning %d\n"),ret);
#endif
  /* SDK doc says we should return SLAPI_BIND_FAIL_OR_ANONYMOUS (1) on error
     and some lines later that we should return non-zero value to skip 
     database BIND function and postoperation BIND function calling...8^?

     We return 0 to invoke standard BIND mechanism and non-zero to skip it.
     It seems to be working */

  return ret;
}

int otp_sasl_init(Slapi_PBlock *pb) {
  htab *ht;
  Slapi_PluginDesc mypdesc = { "OTP-SASL-plugin", "mylan", "$Revision: 1.3 $",
			       "OTP SASL plugin" };

  if ((ht = udb_hash_new()) == NULL) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP SASL",
		    "Can't initialize lock hash");
    return -1;
  }
  
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,"OTP SASL","ht=%p\n",ht);
#endif

  if (slapi_pblock_set(pb,SLAPI_PLUGIN_DESCRIPTION,(void *)&mypdesc )) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP SASL",
		    "Error setting plugin description\n");
    return -1;
  }
  if (slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_BIND_FN,(void*)sasl_otp)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP SASL",
		    "Error setting/registering OTP SASL function\n");
    return -1;
  }

  slapi_register_supported_saslmechanism(LDAP_SASL_OTP);

  if (slapi_pblock_set(pb,SLAPI_PLUGIN_PRIVATE,(void *)ht)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,"OTP SASL",
		    "Can't set global data\n");
    return -1;
  }

  slapi_log_error(SLAPI_LOG_PLUGIN,"OTP SASL","%s loaded\n",rcsid);
  return 0;
}

