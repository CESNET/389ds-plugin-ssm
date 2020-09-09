
#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "slapi-plugin.h"
#include <string.h>

int get_cfg (Slapi_PBlock *pb) {
  char ident[] = "get_cfg";
  char *file;
  int line;
  int ac;
  char **ag;

  if (slapi_pblock_get(pb,SLAPI_CONFIG_FILENAME,&file)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't get config file name");
    return -1;
  }
  if (slapi_pblock_get(pb,SLAPI_CONFIG_LINENO,&line)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't get config line number");
    return -1;
  }
  if (slapi_pblock_get(pb,SLAPI_CONFIG_ARGC,&ac)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		    "Can't get config parameters count");
    return -1;
  }
  if (slapi_pblock_get(pb,SLAPI_CONFIG_FILENAME,&ag)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,"Can't get config arguments");
    return -1;
  }
  {
    // FAKE
    char tmpbuf[2048];
    int i;

    strcpy(tmpbuf,"directive %s:%d:");
    for (i = ac; i; i++)
      strcat(tmpbuf," %s");

//    slapi_log_error(SLAPI_LOG_PLUGIN,ident,tmpbuf,file,line,ag);
  }
  return 0;
}
