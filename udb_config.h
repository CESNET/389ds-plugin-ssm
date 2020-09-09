/* $Id: udb_config.h,v 1.2 1999/08/20 18:22:23 sova Exp sova $ */
#ifndef UDB_CONFIG_H
#define UDB_CONFIG_H

typedef struct udb_cmd_st {
  char	*name;
  int	(*fn)();
  /* argument count; ac = -1 => variable argument count */
  int	ac;
} udb_cmd;

typedef struct cfg_mod_st {
  int		mod_op;
  char		*mod_type;
  udb_cmd	*cmd;
  int		argc;
  char		**argv;
  struct cfg_mod_st *next;
} cfg_mod;

typedef struct cfg_rule_st {
  int 		lineno;
  Slapi_Filter	*flt;
  int		nmods;
  cfg_mod	*mods;
  struct cfg_rule_st *next;
} cfg_rule;

typedef struct cfg_ruleset_st {
  int		lineno;
  char		**attrs;
  int		nrules;
  cfg_rule	*rule;
  struct cfg_ruleset_st *next;
} cfg_ruleset;

cfg_ruleset *parse_config (char *);
int parse_ruleset(cfg_ruleset *,int,char*);
int parse_rule (cfg_rule *,int,char *);
udb_cmd *find_cmd (udb_cmd *,char *,int);

#define UDB_FUNC(nam)	int udb_ ## nam(int conn,Slapi_PBlock *pb,Slapi_Entry *e,cfg_mod *cfgmod,LDAPMod **res)

UDB_FUNC(opinit_time);
UDB_FUNC(string_constant);
UDB_FUNC(concat);
UDB_FUNC(conn_dn);

#define	UDB_CMD(cmd,ac)	{ #cmd, udb_##cmd, ac }

extern udb_cmd cmd_list[];

#endif
