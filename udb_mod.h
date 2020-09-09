/* $Id$ */
#ifndef UDB_MOD_H
#define UDB_MOD_H

#include "udb_config.h" /* cfg_ruleset */

typedef struct udb_mod_private_st {
  int		debug;
  cfg_ruleset	*rs;
} mod_priv;

#endif /* UDB_MOD_H */
