/********************************************************
 * An example source module to accompany...
 *
 * "Using POSIX Threads: Programming with Pthreads"
 *     by Brad nichols, Dick Buttlar, Jackie Farrell
 *     O'Reilly & Associates, Inc.
 *
 ********************************************************
 * rdwr.h --
 * 
 * Include file for reader/writer locks
 */

#include <time.h>
#include "slapi-plugin.h"

typedef struct rdwr_var {
  int readers_reading;
  int writer_writing;
  Slapi_Mutex *mutex;
  Slapi_CondVar *lock_free;
} udb_rdwr_t;

//typedef void * udb_rdwrattr_t;

//#define pthread_rdwrattr_default NULL;

int udb_rdwr_init(udb_rdwr_t *rdwrp/* , udb_rdwrattr_t *attrp */);
int udb_rdwr_rlock(udb_rdwr_t *rdwrp,struct timeval *tv);
int udb_rdwr_runlock(udb_rdwr_t *rdwrp);
int udb_rdwr_wlock(udb_rdwr_t *rdwrp,struct timeval *tv);
int udb_rdwr_wunlock(udb_rdwr_t *rdwrp);
int udb_rdwr_wwait(udb_rdwr_t *rdwrp,struct timeval *tv);
void udb_rdwr_cleanup(udb_rdwr_t *rdwrp);
