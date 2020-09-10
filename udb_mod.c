
#ifndef lint
static char rcsid[] = "$Id: udb_mod.c,v 1.3 2003/10/27 16:02:49 root Exp root $";
#endif /* lint */

#include <stdlib.h>	/* strtol */
#include <string.h>	/* strcasecmp */
#include "slapi-plugin.h"
#include "udb_config.h"
#include "util.h"
#include "udb_mod.h"
#include "udb_log.h"

Slapi_PluginDesc	ssm_desc = {
  "SSM",			/* plugin id */
  "mylan",			/* vendor */
  "2.0",			/* revision */
  "Server-Side modification plugin" /* desc */
};

/* Internal operations require an ID for the plug-in.                   */
static Slapi_ComponentId * ssm_plugin_id     = NULL;

int apply_ruleset (int conn,
		   Slapi_PBlock *pb,char *dn,Slapi_Entry *e,cfg_ruleset *rs,
		   int debug) {
  char		ident[] = MIDENT("apply_ruleset");
  LDAPMod	**mods,**mcurp;
  cfg_rule	*rcur, **rmatched;
  int		ret=-1/*,nrules=0*/,nmods=0,i=0;
  Slapi_PBlock	*rpb;
  int		modret;

  /* alloc array for matched rules, can be at most rs->nrules long */
  rmatched = (cfg_rule **)slapi_ch_calloc(rs->nrules+1,sizeof(cfg_rule*));

  /* find matching rules */
  for (i = 0, rcur = rs->rule; rcur; rcur = rcur->next) {
    if (slapi_filter_test(pb,e,rcur->flt,0) == 0) {
      nmods += rcur->nmods;
      rmatched[i] = rcur;
      i++;
    }
  }

  if (debug & DBG_CONS)
      slapi_log_error(LOG_("found %d matching rules\n"),i);

  /* alloc array for LDAPMod's */
  mods = (LDAPMod **)slapi_ch_calloc(nmods+1,sizeof(LDAPMod*));
  
  /* create the LDAPMod's array */
  mcurp = mods;
  for (i = 0; rmatched[i]; i++) {
    cfg_mod *cmod;

    if (debug & DBG_CONS)
      log_info(ident,"adding rule %p, lineno %d\n",
	       rmatched[i],rmatched[i]->lineno);
      //      slapi_log_error(LOG_("adding rule %p, lineno %d\n"), 
      //		      rmatched[i],rmatched[i]->lineno);

    for (cmod = rmatched[i]->mods; cmod; cmod = cmod->next) {
      if (cmod->cmd->fn(conn,pb,e,cmod,mcurp)) {
	//	slapi_log_error(LOG_("function %s: error\n"),cmod->cmd->name);
	log_err(ERR_UDB_FUNC_RUN,ident,
		"function %s: error\n",cmod->cmd->name);
	goto cleanup;
      }
      mcurp++;
    }
  }
  ret = 0;
  if (debug & DBG_CONS) {
    //    slapi_log_error(LOG_("gonna print resulting mods\n"));
    log_info(ident,"gonna print resulting mods\n");
    for (i = 0; mods[i]; i++) {
      //      slapi_log_error(LOG_("mod[%d]: mod_type=%s\n"),i,mods[i]->mod_type);
      log_info(ident,"mod[%d]: mod_type=%s\n",i,mods[i]->mod_type);
    }
    print_mods(mods,ident,conn);
  }

  //  rpb = slapi_modify_internal(dn,mods,NULL,1);
  rpb = slapi_pblock_new();
  slapi_modify_internal_set_pb (
				      rpb,
				      dn,
				      mods,
				      NULL,
				      NULL,
				      ssm_plugin_id,
				      SLAPI_OP_FLAG_NEVER_CHAIN
				      );
//  if (ret != 0) {
//    //    slapi_pblock_destroy(rpb); -> in cleanup
//    goto cleanup;
//  }

  ret = slapi_modify_internal_pb(rpb);
  
  if (slapi_pblock_get(rpb,SLAPI_PLUGIN_INTOP_RESULT,&modret)) {
    //    slapi_log_error(LOG_("Can't get modification result\n"));
    log_err(ERR_PBLOCK,ident,"Can't get modification result\n");
    goto cleanup;
  }
  if (modret != LDAP_SUCCESS) {
    log_err(ERR_LDAP_OPERATION,ident,
	    "Modification error (%d): %s\n",modret,ldap_err2string(modret));
    //    slapi_log_error(LOG_("Modification error (%d): %s\n"),
    //		    modret,ldap_err2string(modret));
  } else {
    if (debug & DBG_CONS)
      log_info(ident,"Modification status (%d): %s\n",
		      modret,ldap_err2string(modret));

    ret = 0;
  }
 cleanup:
  for (mcurp = mods; *mcurp; mcurp++) {
    LDAPMod_free(*mcurp);
  }
  slapi_ch_free((void**)&mods);
  slapi_ch_free((void**)&rmatched);
  if (debug & DBG_CONS)
    log_info(ident,"returning\n");

#if DEBUG & DEBUG_MEM
  log_info(ident,__FILE__ ":" __LINE__ "about to call slapi_pblock_destroy\n");
  //  slapi_log_error(LOG_(__FILE__ ":" __LINE__ "about to call slapi_pblock_destroy\n"));
#endif
  slapi_pblock_destroy(rpb);
#if DEBUG & DEBUG_MEM
  log_info(ident,"after slapi_pblock_destroy\n");
  //  slapi_log_error(LOG_("after slapi_pblock_destroy\n"));
#endif

  return ret;
}

int cons_mod (Slapi_PBlock *pb) {
  char	ident[] = MIDENT("cons_mod");
  char	*dn;
  int	conn,opret, ret = -1;
  //  int	nmods = 0,nrules = 0, i;
  LDAPMod	**clmods /*,**mods,**mcurp */;
  Slapi_Entry	*e_target;
  Slapi_DN	*sdn;
  cfg_ruleset	*rs,*rscur;
  mod_priv	*prv;
  int		debug;
  
  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }
  if (opret != LDAP_SUCCESS) {
    log_info(ident,"Preceeding operation returned %d, giving up\n",
	     opret);
    //    slapi_log_error(LOG_("Preceeding operation returned %d, giving up\n"),
    //		    opret);
    return 0;
  }

#if DEBUG & DBG_CONS
  //  slapi_log_error(LOG_("started\n"));
  log_info(ident,"started\n");
#endif

  if (slapi_pblock_get(pb,SLAPI_PLUGIN_PRIVATE,&prv)) {
    //    slapi_log_error(LOG_("Can't get plugin configuration\n"));
    log_err(ERR_PBLOCK,ident,"Can't get plugin configuration\n");
    return -1;
  }
  rs = prv->rs;
  debug = prv->debug;

  if (slapi_pblock_get(pb,SLAPI_MODIFY_TARGET,&dn)) {
    //    slapi_log_error(LOG_("Can't get dn\n"));
    log_err(ERR_PBLOCK,ident,"Can't get DN\n");
    return -1;
  }
  
  sdn = slapi_sdn_new_dn_byval(dn);
  /* FIXME: should check for (sdn == NULL) here... */
  if (get_target_entry(sdn,&e_target,conn,ssm_plugin_id) != LDAP_SUCCESS) {
    return -1;
  }

  if (slapi_pblock_get(pb,SLAPI_MODIFY_MODS,&clmods)) {
    log_err(ERR_PBLOCK,ident,"Can't get modifications\n");
    //    slapi_log_error(LOG_("Can' get modifications\n"));
    goto cleanup;
  }

  if (debug & DBG_CONS)
    log_info(ident,"Searching the rulesets\n");

  /* find matching rulesets */
  for (rscur = rs; rscur; rscur = rscur->next) {
    char **cpp;
    LDAPMod **clmod;

    if (debug & DBG_CONS)
      log_info(ident,"Examining ruleset from line %d\n",rscur->lineno);

    for (cpp = rscur->attrs; *cpp; cpp++) {
      if (debug & DBG_CONS)
	log_info(ident,"checking ruleheader mod_type %s\n",*cpp);

      for (clmod = clmods; *clmod; clmod++) {
	if (debug & DBG_CONS)
	  log_info(ident,"checking clmod mod_type %s\n",
		    (*clmod)->mod_type);

	if (**cpp == '*' || strcasecmp(*cpp, (*clmod)->mod_type) == 0) {
	  //	  cfg_rule *rcur,**rmatched = NULL;

	  if (debug & DBG_CONS)
	    log_info(ident,"found ruleset at line %d (mod_type=%s)\n",
		      rscur->lineno, *cpp);

	  if (apply_ruleset(conn,pb,dn,e_target,rscur,debug)) {
	    ret = -1;
	    goto cleanup;
	  } else goto nextrs;
	}
      }
    }
  nextrs:;
  }
  /* no matching ruleset  found */
  ret = 0;
 cleanup:
  slapi_sdn_free(&sdn);
  return ret;
}

int cons_add (Slapi_PBlock *pb) {
  char	ident[] = MIDENT("cons_add");
  char *dn;
  int	conn,opret, ret = -1;
  Slapi_Entry	*e;
  mod_priv	*prv;
  int		debug = 0;
  cfg_ruleset	*rs,*rscur;

  if (get_conop(pb,ident,&conn,&opret)) {
    return -1;
  }
  if (opret != LDAP_SUCCESS) {
    log_info(ident,"Preceeding operation returned %d, giving up\n",
	     opret);
    return 0;
  }

#if DEBUG & DBG_CONS
  log_info(ident,"started\n");
#endif

  if (slapi_pblock_get(pb,SLAPI_PLUGIN_PRIVATE,&prv)) {
    log_err(ERR_PBLOCK,ident,"Can't get plugin configuration\n");
    return -1;
  }
  
  rs = prv->rs;
  debug = prv->debug;

  if (slapi_pblock_get(pb,SLAPI_ADD_TARGET,&dn)) {
    log_err(ERR_PBLOCK,ident,"Can't get DN\n");
    return -1;
  }

  if (slapi_pblock_get(pb,SLAPI_ADD_ENTRY,&e)) {
    log_err(ERR_PBLOCK,ident,"Can't get added entry\n");
    return -1;
  }

  if (debug & DBG_CONS)
    log_info(ident,"Searching the rulesets\n");

  /* find matching rulesets */
  for (rscur = rs; rscur; rscur = rscur->next) {
    char **cpp;
    Slapi_Attr *attr;

    if (debug & DBG_CONS)
      log_info(ident,"Examining ruleset from line %d\n",rscur->lineno);

    for (cpp = rscur->attrs; *cpp; cpp++) {
      if (debug & DBG_CONS)
	log_info(ident,"checking ruleheader mod_type %s\n",*cpp);

      if (slapi_entry_attr_find(e,*cpp,&attr) == 0) {
	if (debug & DBG_CONS)
	  log_info(ident,"found ruleset at line %d (mod_type=%s)\n",
		   rscur->lineno, *cpp);

	if (apply_ruleset(conn,pb,dn,e,rscur,debug)) {
	  ret = -1;
	  goto cleanup;
	} else goto nextrs;
      }
    }
  nextrs:;
  }
  ret = 0;
 cleanup:
  
  return ret;
}

int ssm_init(Slapi_PBlock * pb) {
  int	rc = 0;
  int	ac;
  char	**ag;
  mod_priv	*prv;
//return 0;
  rc |= slapi_pblock_set(            /* Plug-in API version           */
			 pb,
			 SLAPI_PLUGIN_VERSION,
			 SLAPI_PLUGIN_CURRENT_VERSION
			 );
  if (rc)
    log_err(1, "SSM:ssm_init", "pblock_set VERSION: %d\n", rc);

  rc |= slapi_pblock_set(            /* Plug-in description           */
			 pb,
			 SLAPI_PLUGIN_DESCRIPTION,
			 (void *) &ssm_desc
			 );
  if (rc)
    log_err(1, "SSM:ssm_init", "pblock_set DESC: %d\n", rc);

  rc |= slapi_pblock_get(pb,
			 SLAPI_PLUGIN_ARGC,
			 &ac);
  if (rc)
    log_err(1, "SSM:ssm_init", "Can't get argument count: %d\n", rc);
  
  if (ac < 1) {
    log_err(1, "SSM:ssm_init", "Bad argument count (expecting one filename and optionally a debug level)\n");
    return -1;
  }

  rc |= slapi_pblock_get(pb,
			 SLAPI_PLUGIN_ARGV,
			 &ag);
  if (rc) {
    log_err(1, "SSM:ssm_init", "Can't get arguments\n");
    return -1;
  }

  prv = (mod_priv*)slapi_ch_calloc(1,sizeof(mod_priv));
  
  if ((prv->rs = parse_config(ag[0])) == NULL) {
    log_err(1, "SSM:ssm_init", "Error reading config file \"%s\"\n", ag[0]);
    return -1;
  }

  if (ac > 1) {
    prv->debug = strtol(ag[1], 0, 0);	/* FIXME: should accep ONLY allowed values  */
  } else {
    prv->debug = 0;
  }

  rc |= slapi_pblock_set(pb,
			 SLAPI_PLUGIN_PRIVATE,
			 (void *)prv);

  if (rc) {
      log_err(1, "SSM:ssm_init", "pblock_set PRIVATE: %d\n", rc);
    return -1;
  }

  rc |= slapi_pblock_set(            /* Post-modify function          */
			 pb,
			 SLAPI_PLUGIN_PRE_MODIFY_FN,
			 (void *) cons_mod
			 );
  if (rc)
    log_err(1,
		       "SSM:ssm_init",
		       "pblock_set POST_MOD_FN: %d\n",
		     rc);

  rc |= slapi_pblock_set(
			 pb,
			 SLAPI_PLUGIN_PRE_ADD_FN,
			 (void *) cons_add
			 );
  if (rc)
    log_err(1,
		       "SSM:ssm_init",
		       "pblock_set POST_ADD_FN: %d\n",
		       rc);

  rc |= slapi_pblock_get(pb,
			SLAPI_PLUGIN_IDENTITY, 
			&ssm_plugin_id);

  if (rc)
    log_err(1,
		       "SSM:ssm_init",
		       "returning %d\n",
		       rc);
  log_info("SSM:init","returning %d", rc);
  return (rc);
}

#if 0
int udb_mod_postop (Slapi_PBlock *pb)
{
  char		ident[] = "SSMod";
  Slapi_PluginDesc desc = {ident, "mylan", "$Revision: 1.3 $",
			   "Server Side Modification plugin"};
  int		ac;
  char		**ag;
  mod_priv	*prv;
  //  cfg_ruleset	*ruleset;

  if (slapi_pblock_get(pb,SLAPI_PLUGIN_ARGC,&ac)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't get argument count\n");
    return -1;
  }

  if (ac < 1) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		    "Bad argument count (expecting one filename and optionally a debug level)\n");
    return -1;
  }

  if (slapi_pblock_get(pb,SLAPI_PLUGIN_ARGV,&ag)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't get arguments\n");
    return -1;
  }
  
  prv = (mod_priv*)slapi_ch_calloc(1,sizeof(mod_priv));

  if ((prv->rs = parse_config(ag[0])) == NULL) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		    "Error reading config file \"%s\"\n",ag[0]);
    return -1;
  }

  if (ac > 1) {
    prv->debug = strtol(ag[1],0,0);
  } else {
    prv->debug = 0;
  }

  if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) 
      || slapi_pblock_set(pb,SLAPI_PLUGIN_DESCRIPTION,(void *)&desc )
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_MODIFY_FN,(void*)cons_mod)
      || slapi_pblock_set(pb,SLAPI_PLUGIN_PRE_ADD_FN,(void*)cons_add)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't register plugin\n");
    return -1;
  }

  if (slapi_pblock_set(pb,SLAPI_PLUGIN_PRIVATE, (void *)prv)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't set global data\n");
    return -1;
  }
  
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"%s: plugin loaded\n",rcsid);
  return 0;
}
#endif
