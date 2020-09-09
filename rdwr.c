/********************************************************
 * An example source module to accompany...
 *
 * "Using POSIX Threads: Programming with Pthreads"
 *     by Brad nichols, Dick Buttlar, Jackie Farrell
 *     O'Reilly & Associates, Inc.
 *
 ********************************************************
 * rdwr.c --
 * 
 * Library of functions implementing reader/writer locks
 */
//#include <pthread.h>
#include "rdwr.h"

int udb_rdwr_init(udb_rdwr_t *rdwrp/*, udb_rdwrattr_t *attrp */)
{
  rdwrp->readers_reading = 0;
  rdwrp->writer_writing = 0;
  if ((rdwrp->mutex = slapi_new_mutex()) == NULL)
    return -1;
  if ((rdwrp->lock_free = slapi_new_condvar(rdwrp->mutex)) == NULL) {
    slapi_destroy_mutex(rdwrp->mutex);
    return -1;
  }
  return 0;
}

int udb_rdwr_rlock(udb_rdwr_t *rdwrp,struct timeval *tv){
  slapi_lock_mutex(rdwrp->mutex);
  while(rdwrp->writer_writing) {
    slapi_wait_condvar(rdwrp->lock_free, tv);
  }
  /* FIXME: check timeout */
  rdwrp->readers_reading++;
  slapi_unlock_mutex(rdwrp->mutex);
  return 0;
}

int udb_rdwr_runlock(udb_rdwr_t *rdwrp)
{
  slapi_lock_mutex(rdwrp->mutex);
  if (rdwrp->readers_reading == 0) {
    slapi_unlock_mutex(rdwrp->mutex);
    return -1;
  } else {
    rdwrp->readers_reading--;
    if (rdwrp->readers_reading == 0) {
      slapi_notify_condvar(rdwrp->lock_free,1);
    }
    slapi_unlock_mutex(rdwrp->mutex);
    return 0;
  }
}

int udb_rdwr_wlock(udb_rdwr_t *rdwrp,struct timeval *tv)
{
  slapi_lock_mutex(rdwrp->mutex);
  while(rdwrp->writer_writing || rdwrp->readers_reading) {
    slapi_wait_condvar(rdwrp->lock_free,tv);
  }
  rdwrp->writer_writing++;
  slapi_unlock_mutex(rdwrp->mutex);
  return 0;
}

int udb_rdwr_wunlock(udb_rdwr_t *rdwrp)
{
  slapi_lock_mutex(rdwrp->mutex);
  if (rdwrp->writer_writing == 0) {
    slapi_unlock_mutex(rdwrp->mutex);
    return -1;
  } else {
    rdwrp->writer_writing = 0;
    slapi_notify_condvar(rdwrp->lock_free,1);
    slapi_unlock_mutex(rdwrp->mutex);
    return 0;
  }
}

int udb_rdwr_wwait(udb_rdwr_t *rdwrp,struct timeval *tv)
{
  slapi_lock_mutex(rdwrp->mutex);
  slapi_wait_condvar(rdwrp->lock_free,tv);
  slapi_unlock_mutex(rdwrp->mutex);
  return 0;
}

void udb_rdwr_cleanup(udb_rdwr_t *rdwrp) 
{
  slapi_destroy_mutex(rdwrp->mutex);
  slapi_destroy_condvar(rdwrp->lock_free);
}
