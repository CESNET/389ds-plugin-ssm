#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "slapi-plugin.h"
#include "udb_config.h"
#include "util.h"
#include "udb_log.h"

#ifdef MAIN
# define _L	fprintf
# ifdef LOG_
#  undef LOG_
# endif
# define LOG_(x)	stderr,x
# define mycalloc(n,s)	calloc((n),(s))
//# define myfree(p)	if (*(p)) free(*(p)),(*p) = NULL
# define mystrdup(p)	strdup(p)
# define myrealloc(p,s)	realloc((p),(s))
void myfree(void **p) {
  if (*p) free(*p);
  *p = NULL;
}
void mystrfree(char **s) {
  if (*s) free(*s);
  *s = NULL;
}
Slapi_Filter *slapi_str2filter( char *str ) {
  return (Slapi_Filter*)mystrdup(str);
}
void slapi_filter_free(Slapi_Filter *f,int r) {
  myfree((void**)&f);
}
#else /* MAIN */
# define _L	slapi_log_error_ex
# ifdef LOG_
#  undef LOG_
# endif
//# define LOG_(x)	SLAPI_LOG_PLUGIN,ident,x
//# define LOG_(x)	1,SLAPI_LOG_NO_MSGID,SLAPI_LOG_NO_CONNID,SLAPI_LOG_NO_OPID,ident,"msg",x
# define LOG_(x)	1,SLAPI_LOG_NO_MSGID,SLAPI_LOG_NO_CONNID,SLAPI_LOG_NO_OPID,ident,"msg",x
# define mycalloc(n,s)	slapi_ch_calloc((n),(s))
# define myfree(p)	slapi_ch_free(p)
# define mystrfree(s)	slapi_ch_free_string(s)
# define mystrdup(p)	slapi_ch_strdup(p)
# define myrealloc(p,s)	slapi_ch_realloc((p),(s))
#endif /* MAIN */

#define LINESZ	2048
#define TAB	0x9

#define	UDB_CMD_DEFAULT(tab)	tab

udb_cmd cmd_list[] = {
  UDB_CMD(string_constant,	-1),	/* default MUST be first */
  UDB_CMD(opinit_time,		0),
  UDB_CMD(concat,		-1),
  UDB_CMD(conn_dn,		0),
  { NULL, NULL, 0 }
};

cfg_ruleset *cfg_ruleset_new(void) {
  return((cfg_ruleset *)mycalloc(1,sizeof(cfg_ruleset)));
}

cfg_rule *cfg_rule_new(void) {
  return((cfg_rule *)mycalloc(1,sizeof(cfg_rule)));
}

cfg_mod *cfg_mod_new(void) {
  return((cfg_mod *)mycalloc(1,sizeof(cfg_mod)));
}

void cfg_mod_free(cfg_mod **mod) 
{
  cfg_mod **cur,*next;
  char **cpp;

  for (cur = mod; *cur; *cur = next) {
    next = (*cur)->next;

    //    LDAPMod_free((LDAPMod*)&(*cur)->mod);
    mystrfree(&(*cur)->mod_type);

    if ((*cur)->argv)
      for (cpp = (*cur)->argv; *cpp; cpp++) 
	myfree((void**)cpp);
    myfree((void**)&(*cur)->argv);

    myfree((void**)cur); 
  }
  mod = NULL;
}

void cfg_rule_free(cfg_rule **rule) 
{
  cfg_rule **cur,*next;

  for (cur = rule; *cur; *cur = next) {
    if ((*cur)->flt)
      slapi_filter_free((*cur)->flt,1);

    if ((*cur)->mods)
      cfg_mod_free(&(*cur)->mods);

    next = (*cur)->next;

    myfree((void**)cur);
  }
  rule = NULL;
}

void cfg_ruleset_free(cfg_ruleset **rs) 
{
  cfg_ruleset **cur,*next;

  for (cur = rs; *cur; *cur = next) {
    if ((*cur)->attrs) {
      char **cpp;
      
      for (cpp = (*cur)->attrs; *cpp; cpp++) {
	myfree((void**)cpp);
      }
      myfree((void**)&(*cur)->attrs); /* added & - worked */
    }

    if ((*cur)->rule) 
      cfg_rule_free(&(*cur)->rule);

    next = (*cur)->next;

    myfree((void**)cur);
  }
  rs = NULL;
}

cfg_ruleset *parse_config (char *path) 
{
  /*char	ident[] = MIDENT("parse_config");*/
  FILE *cfg;
  char line[LINESZ];
  int lineno = 0;
  cfg_ruleset **crs = NULL, *rs = NULL;
  cfg_rule **crule = NULL, *rule = NULL;

  if ((cfg = fopen(path,"r")) == NULL) {
    log_err(0, "udb_config", "fopen %s: %s\n", path, strerror(errno));
    return NULL;
  }

  crule = &rule;
  crs = &rs;
  while (fgets(line,LINESZ-1,cfg) != NULL) {
    lineno++;
    if (line[0] == '#' || line[0] == '\n')
      continue;
    if (line[0] == ' ' || line[0] == TAB) {
      /* new rule */
      char *cp;

      if (rs == NULL) {
	/* no ruleset started */
	log_err(0, "udb_config", "rule without attribute list at line %d\n", lineno);
	goto err;
      }

      /* empty line? */
      for (cp = line; *cp == ' ' || *cp == TAB; cp++);
      if (*cp == '\n') continue;
      
      if (*crule == NULL)
	*crule = cfg_rule_new();

      if (parse_rule(*crule,lineno,cp)) {
	log_err(0, "udb_config", "error parsing rule %d\n" ,lineno);
	goto err;
      }
      crule = &(*crule)->next;
      (*crs)->nrules++;
    } else {
      /* new ruleset */
/*       if (*crs == NULL)  */
/* 	*crs = cfg_ruleset_new(); */
      if (*crs != NULL)
	crs = &(*crs)->next;
      *crs = cfg_ruleset_new();

      if (parse_ruleset(*crs,lineno,line)) {
	log_err(0, "udb_config", "error parsing attribute list at line %d\n" ,lineno);
	goto err;
      }
      crule = &(*crs)->rule;
      //?      crs = &(*crs)->next;
    }
  }
  fclose(cfg);
  return rs;
 err:
  fclose(cfg);
  cfg_ruleset_free(&rs);
  return NULL;
}

int parse_ruleset(cfg_ruleset *rs, int lineno, char *r)
{
  /*char		ident[] = MIDENT("parse_ruleset");*/
  char		*cp,*start;
  int		nattr,i;

  rs->lineno = lineno;

  if (*r == '*' && *(r+1) == '\n') {
    rs->attrs = (char**)mycalloc(2,sizeof(char*));
    rs->attrs[0] = mystrdup("*");
  } else {
    for (nattr = 1,cp = r; *cp && *cp != '\n'; cp++) {
      if (*cp == ',') {
	nattr++;
	continue;
      }
      /* maybe should temporarily set C locale */
      if (!(isalnum(*cp) || *cp == ';' || *cp == '-')) {
	log_err(0, "udb_config","character \"%c\" not allowed in attribute name at line %d\n",
	   *cp,lineno);
	return -1;
      }
    }
    *cp = 0; /* last \n */
    
    rs->attrs = (char**)mycalloc(nattr+1,sizeof(char*));
    
    for (i = 0,start = cp = r; i < nattr; cp++,start=cp,i++) {
      while (*cp && *cp != ',') cp++;
      *cp = 0;
      rs->attrs[i] = mystrdup(start);
    }
  }
  return 0;
}

int parse_rule(cfg_rule *rule,int lineno,char *r)
{
  /*char		ident[] = MIDENT("parse_rule");*/
  char 		*cp;
  cfg_mod 	*cmod = NULL;
  char		**strvals = NULL;
  int		ret = -1;
#define ST_START	0
#define ST_FILTER	1
#define ST_MOD_TYPE	2
#define ST_MOD_VAL	3
#define	ST_MOD_ARG	4
  int		state = ST_START;
  char		tbuf[LINESZ];
  char		*tcp;
  int		strvalcnt = 0;

  rule->lineno = lineno;
  rule->mods  = cfg_mod_new();
  rule->nmods = 1;
  state = ST_FILTER;

  cmod = rule->mods;

  for (tcp = tbuf,cp = r; *cp; cp++) {
    switch (*cp) {

    case '\\':
      cp++;
      *(tcp++) = *cp;
      break;

    case '=':
      if (state == ST_MOD_TYPE) {
	*tcp = 0;
	if (strlen(tbuf) == 0) {
	  log_err(0, "udb_config", "empty mod_type at line %d\n", lineno);
	  goto err;
	}
	cmod->mod_type = mystrdup(tbuf);
	tcp = tbuf;
	cp++;
	if (*cp == '!') {
	  udb_cmd *cmd;
	  /* function */

	  /* function name */
	  for (cp++; isalnum(*cp) || *cp == '_'; cp++) {
	    *(tcp++) = *cp;
	  }
	  if ((cmd = find_cmd(cmd_list,tbuf,tcp - tbuf)) == NULL) {
	    *tcp = 0;
	    log_err(0, "udb_config","\"%s\": unknown command at line %d\n" ,tbuf,lineno);
	    goto err;
	  }
	  cmod->cmd = cmd;
	  
	  /* function parameters */
	  if (*cp != '(') {
	    log_err(0, "udb_config","expected '(' instead of %c at line %d\n",
	       *cp,lineno);
	    goto err;
	  }
	  // start actual parameters gathering
	  tcp = tbuf;
	  *tcp = 0;
#if 0
	  strvalcnt = 0;
	  strvals = mycalloc(1,sizeof(char *));
	  for (cp++; *cp; cp++) {
	    switch (*cp) {
	    case ',':
	    case ')':
	      *tcp = 0;
	      strvalcnt++;
	      strvals = (char **)myrealloc((char *)strvals,
					   (strvalcnt+1)*sizeof(char*));
	      strvals[strvalcnt-1] = mystrdup(tbuf);
	      strvals[strvalcnt] = NULL;
	      tcp = tbuf;
	      *tcp = 0;
	      if (*cp == ')') {
		if (cmod->cmd->ac != -1 && cmod->cmd->ac != strvalcnt) {
		  _L(LOG_("Function %s: bad argument count (%d) should be %d\n"),
		     cmod->cmd->name, strvalcnt, cmod->cmd->ac);
		  goto err;
		}
		cmod->args = strvals;
		cmod->ac = strvalcnt;
		strvalcnt = 0;
		strvals = NULL;
	      }
	      break;
	    default:
	      *(tcp)++ = *cp;
	      break;
	    }
	  }
#endif /* 0 */
/* 	  if (*cp != ')') { */
/* 	    _L(LOG_("expected ')' instead of %c at line %d\n"), */
/* 	       *cp,lineno); */
/* 	    goto err; */
/* 	  } */
	  state = ST_MOD_ARG;
	} else {
	  /* string */
	  cp--;
	  cmod->cmd = UDB_CMD_DEFAULT(cmd_list);
	  cmod->argv = (char **)mycalloc(2,sizeof(char *));
	  state = ST_MOD_VAL;
	}
      } else {
	/* not in ST_MOD_TYPE */
	*(tcp++) = *cp;
      }
      break;
    case ',':
    case '\n':
    case TAB:
      *tcp = 0;
      switch (state) {
      case ST_FILTER:
	rule->flt = slapi_str2filter(tbuf);
	state = ST_MOD_TYPE;
	tcp = tbuf;
	break;
      case ST_MOD_VAL:
      case ST_MOD_TYPE:
      case ST_MOD_ARG:
	if (tbuf[0]) {
	  strvalcnt++;
	  strvals = (char **)myrealloc((char *)strvals,
				       (strvalcnt+1)*sizeof(char*));
	  strvals[strvalcnt-1] = mystrdup(tbuf);
	  strvals[strvalcnt] = NULL;
	}
	tcp = tbuf;
	if (*cp == ',')
	  break;
	if (cmod->cmd->ac != -1 && cmod->cmd->ac != strvalcnt) {
 cmod = rule->mods;	  log_err(0, "udb_config", "Function %s: bad argument count (%d) should be %d\n",
	     cmod->cmd->name, strvalcnt, cmod->cmd->ac);
	  goto err;
	}
	cmod->argv = strvals;
	cmod->argc = strvalcnt;
	if (*cp == '\n')
	  break;
	cmod->next = cfg_mod_new();
	cmod = cmod->next;
	rule->nmods++;
	strvals = (char **)mycalloc(1,sizeof(char*));
	strvalcnt = 0;
	break;
      default:
	log_err(0, "udb_config", "unexpected delimiter at line %d: \"<%c>%s\"\n",
	   lineno,*cp,cp);
	goto err;
      }

      if (*cp == '\n' || *cp == ',') 
	break;

      cp++;
      switch (*cp) {
      case '+':
	cmod->mod_op = LDAP_MOD_ADD;
	break;
      case '-':
	cmod->mod_op = LDAP_MOD_DELETE;
	break;
      case '=':
	cmod->mod_op = LDAP_MOD_REPLACE;
	break;
      default:
	log_err(0, "udb_config", "unknown operator \"%c\" at line %d\n",*cp,lineno);
	goto err;
      }
      state = ST_MOD_TYPE;
      tcp = tbuf;
      break;
    case ')':
      if (state == ST_MOD_ARG) {
	state = ST_MOD_VAL;
	break;
      }
      /*@fallthrough@*/ 
    default:
      *(tcp++) = *cp;
      break;
    }
  }

  if (!cmod->cmd) {
    log_err(0, "udb_config", "Failed to correctly parse rule \"%s\" from line %d, no cmd defined (missing TAB?)\n", r, lineno);
    goto err;
  }

  return 0;

 err:
  //  cfg_rule_free(&rule);
  //  cfg_mod_free(&cmod);

  return ret;
}

udb_cmd *find_cmd (udb_cmd *tab, char *nam, int namlen) 
{
  udb_cmd	*cmd;

  for (cmd = tab; cmd->name != NULL; cmd++) {
    if (strlen(cmd->name) == namlen && strncmp(nam,cmd->name,namlen) == 0) {
      return cmd;
    }
  }
  return (udb_cmd*)NULL;
}


#if MAIN
UDB_FUNC(opinit_time) {
  return 0;
}
UDB_FUNC(string_constant) {
  return 0;
}
UDB_FUNC(concat) {
  return 0;
}

int main (int ac,char **ag)
{
  cfg_ruleset *ruleset = NULL;

  if (ac < 2) {
    _L(LOG_("usage: %s file\n"),ag[0]);
    exit(1);
  }
  ruleset = parse_config(ag[1]);
  _L(LOG_("parse_config returned %p\n"),ruleset);
  exit (0);
}
#endif /* MAIN */
