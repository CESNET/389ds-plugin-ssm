/* $Id: udb_hash.h,v 1.1 1999/08/12 17:15:57 sova Exp sova $ */

#ifndef UDB_HASH_H
#define UDB_HASH_H

#include <sys/time.h>
#include <unistd.h>

#include "rdwr.h"

#define BUCKS 256

typedef struct bucket {
  char *key;
  void *data;
  struct bucket *next;
} buck;

typedef struct hashtable {
  buck	*bucks[BUCKS];
  udb_rdwr_t rdwr;
} htab;

typedef struct lock_st {
  int			conn_id;
  struct timeval	tv;
} ulock;

#define	IS_LATER(a,b)	(((a)->tv_sec > (b)->tv_sec) ? 1 \
	: ((a)->tv_sec < (b)->tv_sec) ? 0 \
	: ((a)->tv_usec > (b)->tv_usec) ? 1 : 0)

/* user lock expiration time */
#define LOCK_EXP_TM	60


int udb_hash_add (htab *, char *, void *);
int udb_hash_del (htab *, char *, void **);
int udb_hash_init (htab *);
htab *udb_hash_new (void);
void udb_hash_free (htab *);
int udb_lock (htab *, char *, int, int);
int udb_unlock (htab *, char *, int, void **);

#endif /* UDB_HASH_H */
