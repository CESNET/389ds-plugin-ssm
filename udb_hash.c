
#ifndef lint
static char rcsid[] = "$Id: udb_hash.c,v 1.2 1999/08/20 18:24:12 sova Exp sova $";
#endif /* lint */

#include <errno.h>
#include <string.h>	/* strerror() */
#include "udb.h"
#include "udb_hash.h"
#include "slapi-plugin.h"

static int _getindex (char *key)
{
  unsigned int h = 0;
  char *cp;

  for (cp = key; *cp; cp++) {
    h = (h + *cp) & 0xFF;
  }
  return h;
}

htab *udb_hash_new (void)
{
  htab *ht;

  ht = (htab *)slapi_ch_calloc(1,sizeof(htab));
  
  if (udb_rdwr_init(&(ht->rdwr))) {
    slapi_ch_free((void**)&ht);
    return NULL;
  }
  return ht;
}

int udb_hash_add (htab *ht, char *key, void *data)
{
  buck *b,*prev;
  int i;
#if DEBUG & DBG_LOCK
  char ident[] = "udb_hash_add";

  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "started with ht=%p key=%s\n", ht,key);
#endif

  i = _getindex(key);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident, "i=%d\n", i);
#endif
  udb_rdwr_wlock(&(ht->rdwr),NULL);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash locked\n");
#endif

  if ((b = ht->bucks[i]) != NULL) {
    /* check for key presence */
    for (; b; prev=b, b=b->next) {
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"checking key \"%s\" at b=%p, b->key=%p\n",
			b->key,b,b->key);
#endif
      if (strcmp(b->key,key) == 0) {
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,"key found\n");
#endif
	udb_rdwr_wunlock(&(ht->rdwr));
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash unlocked\n");
#endif
	return 1;
      }
    }
    /* not found - add */
    b = prev->next = (buck *)slapi_ch_calloc(1,sizeof(buck));
  } else {
    ht->bucks[i] = b = (buck *)slapi_ch_calloc(1,sizeof(buck));
  }

  b->key = slapi_ch_strdup(key);
  b->data = data;
  b->next = NULL;

#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "bucket added at b=%p, ht->bucks[%d]=%p\n",b,i,ht->bucks[i]);
#endif

  udb_rdwr_wunlock(&(ht->rdwr));
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash unlocked\n");
#endif
  return 0;
}

int udb_hash_del (htab *ht, char *key, void **datap) 
{
  buck *b,*prev=NULL;
  int i, ret=-1;
#if DEBUG & DBG_LOCK
  char ident[] = "udb_hash_del";

  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "started with ht=%p key=%s\n", ht,key);
#endif

  *datap = NULL;

  i = _getindex(key);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"i=%d\n", i);
#endif

  udb_rdwr_wlock(&(ht->rdwr),NULL);

  for (prev=b=ht->bucks[i]; b; prev=b, b=b->next) {
#if DEBUG & DBG_LOCK
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		    "checking key \"%s\" at b=%p, b->key=%p\n",
		    b->key,b,b->key);
#endif
    if (strcmp(b->key,key) == 0) {
#if DEBUG & DBG_LOCK
      slapi_log_error(SLAPI_LOG_PLUGIN,ident,"found\n");
#endif
      prev->next = b->next;
      *datap = b->data;
      slapi_ch_free((void**)&(b->key));

      if (b == prev) {
	/* we're at the first buck */
	ht->bucks[i] = prev->next;
      }
      slapi_ch_free((void**)&b);
      break;
    }
  }
  udb_rdwr_wunlock(&(ht->rdwr));
  return ret;
}

void udb_hash_free (htab *ht)
{
  int i;
  buck *b;

  udb_rdwr_wlock(&(ht->rdwr),NULL);
  for (i = 0; i < BUCKS; i++) {
    for (b = ht->bucks[i]; b; b = b->next) {
      slapi_ch_free((void**)&(b->key));
    }
  }
  udb_rdwr_cleanup(&(ht->rdwr));
}

/* return 0 on success, -1 on system error, 1 when record locked, 
 2 when not found and ownonly set */
int udb_lock (htab *ht, char *key, int conn_id, int ownonly)
{
  buck *b,*prev;
  int i;
  ulock *lock;
  //  struct timeval now;
  int ret = -1;
  char ident[] = "udb_lock";

#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "conn=%d started with ht=%p key=%s, ownonly=%d\n", 
		  conn_id,ht,key,ownonly);
#endif

  i = _getindex(key);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident, "i=%d\n", i);
#endif
  udb_rdwr_wlock(&(ht->rdwr),NULL);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash locked\n");
#endif

  if ((b = ht->bucks[i]) != NULL) {
    /* check for key presence */
    for (; b; prev=b, b=b->next) {
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn=%d checking key \"%s\" at b=%p, b->key=%p, b->next=%p\n",
			conn_id,b->key,b,b->key,b->next);
#endif
      if (strcmp(b->key,key) == 0) {
	ulock *lock;

	lock = (ulock *)b->data;
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn=%d key found: conn_id=%d, exp=%s,%06ld\n",
			conn_id,lock->conn_id,ctime(&(lock->tv.tv_sec)),
			lock->tv.tv_usec);
#endif

	if (lock->conn_id == conn_id) {
	  /* it's our lock, use it (== ignore it) */
	  if (gettimeofday(&(lock->tv),NULL)) {
	    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			    "conn=%d gettimeofday error: %s",
			    strerror(errno));
	    //	    udb_rdwr_wunlock(&(ht->rdwr));
	    ret = -1;
	    goto end;
	    //	    return -1;
	  }
	  lock->tv.tv_sec += LOCK_EXP_TM;
#if DEBUG & DBG_LOCK
	  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn_id=%d, lock renewed: exp=%s,%06ld\n",
			conn_id,ctime(&(lock->tv.tv_sec)),lock->tv.tv_usec);
#endif
	  ret = 0;
	  goto end;
	} else {
	  if (ownonly) {
	    /* not our lock, takeover not allowed */
#if DEBUG
	    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			    "conn=%d \"%s\" locked by conn %d\n",
			    conn_id,key,lock->conn_id);
#endif
	    ret = 1;
	    goto end;
	  } else {
			    
	    /* not our lock, we can take it over only if it's expired */
	    struct timeval now;

	    if (gettimeofday(&now,NULL)) {
	      slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			      "conn=%d gettimeofday error: %s",
			      strerror(errno));
	      ret = -1;
	      goto end;
	    }
	  
	    if (!timercmp (&now, &(lock->tv), >)) {
	      /* fresh lock from some other thread, return */
	      ret = 1;
	      goto end;
	    }

	    /* OK, lock's expired, take it over */
	    lock->conn_id = conn_id;
	    lock->tv.tv_sec = now.tv_sec + LOCK_EXP_TM;
	    lock->tv.tv_usec = 0;
#if DEBUG & DBG_LOCK
	    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			    "conn_id=%d, lock takeover: exp=%s,%06ld\n",
			    conn_id,ctime(&(lock->tv.tv_sec)),lock->tv.tv_usec);
#endif
	    ret = 0;
	    goto end;
	  }
	}
      }
    }
    if (ownonly) {
      /* not found */
#if DEBUG & DBG_LOCK
      slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		      "conn=%d key not found\n",conn_id);
#endif
      ret = 2;
    } else {
      b = prev->next = (buck *)slapi_ch_calloc(1,sizeof(buck));
    }
  } else {
    if (!ownonly) {
      ht->bucks[i] = b = (buck *)slapi_ch_calloc(1,sizeof(buck));
    } else {
#if DEBUG & DBG_LOCK
      slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		      "conn=%d key not found\n",conn_id);
#endif
      ret = 2;
    }
  }

  if (!ownonly) {
    lock = (ulock *)slapi_ch_calloc(1,sizeof(ulock));
    lock->conn_id = conn_id;
    if (gettimeofday(&(lock->tv),NULL)) {
      slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		      "conn=%d gettimeofday error: %s",strerror(errno));
      ret = -1;
      goto end;
    }

    lock->tv.tv_sec += LOCK_EXP_TM;
    b->key = slapi_ch_strdup(key);
    b->data = lock;
    b->next = NULL;
    ret = 0;

#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "bucket added at b=%p, ht->bucks[%d]=%p\n",b,i,ht->bucks[i]);
#endif
  }
 end:
  udb_rdwr_wunlock(&(ht->rdwr));
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash unlocked, returning %d\n",ret);
#endif
  return ret;
}

#if 0
/* return 0 on success, -1 on system error, 1 when record locked */
int udb_lock_ (htab *ht, char *key, int conn_id)
{
  buck *b,*prev;
  int i;
  ulock *lock;
  //  struct timeval now;
  int ret = -1;
#if DEBUG & DBG_LOCK
  char ident[] = "udb_lock";

  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "conn=%d started with ht=%p key=%s\n", conn_id,ht,key);
#endif

  i = _getindex(key);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident, "i=%d\n", i);
#endif
  udb_rdwr_wlock(&(ht->rdwr),NULL);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash locked\n");
#endif

  if ((b = ht->bucks[i]) != NULL) {
    /* check for key presence */
    for (; b; prev=b, b=b->next) {
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn=%d checking key \"%s\" at b=%p, b->key=%p, b->next=%p\n",
			conn_id,b->key,b,b->key,b->next);
#endif
      if (strcmp(b->key,key) == 0) {
	ulock *lock;

	lock = (ulock *)b->data;
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn=%d key found: conn_id=%d, exp=%s,%06ld\n",
			conn_id,lock->conn_id,ctime(&(lock->tv.tv_sec)),
			lock->tv.tv_usec);
#endif

	if (lock->conn_id == conn_id) {
	  /* it's our lock, use it (== ignore it) */
	  if (gettimeofday(&(lock->tv),NULL)) {
	    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			    "conn=%d gettimeofday error: %s",
			    strerror(errno));
	    //	    udb_rdwr_wunlock(&(ht->rdwr));
	    ret = -1;
	    goto end;
	    //	    return -1;
	  }
	  lock->tv.tv_sec += LOCK_EXP_TM;
#if DEBUG & DBG_LOCK
	  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn_id=%d, lock renewed: exp=%s,%06ld\n",
			conn_id,ctime(&(lock->tv.tv_sec)),lock->tv.tv_usec);
#endif
	  ret = 0;
	  goto end;
	  //	  udb_rdwr_wunlock(&(ht->rdwr));
	  //	  return 0;
	} else {
	  /* not our lock, we can take it over only if it's expired */
	  struct timeval now;

	  if (gettimeofday(&now,NULL)) {
	    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			    "conn=%d gettimeofday error: %s",
			    strerror(errno));
	    //	    udb_rdwr_wunlock(&(ht->rdwr));
	    //	    return -1;
	    ret = -1;
	    goto end;
	  }
	  
	  if (!timercmp (&now, &(lock->tv), >)) {
	    /* fresh lock from some other thread, return */
	    //	    udb_rdwr_wunlock(&(ht->rdwr));
	    //	    return 1;
	    ret = 1;
	    goto end;
	  }

	  /* OK, lock's expired, take it over */
	  lock->conn_id = conn_id;
	  lock->tv.tv_sec = now.tv_sec + LOCK_EXP_TM;
	  lock->tv.tv_usec = 0;
#if DEBUG & DBG_LOCK
	  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			  "conn_id=%d, lock takeover: exp=%s,%06ld\n",
			  conn_id,ctime(&(lock->tv.tv_sec)),lock->tv.tv_usec);
#endif
	  //	  udb_rdwr_wunlock(&(ht->rdwr));
	  //	  return 0;
	  ret = 0;
	  goto end;
	}
      }
    }
    /* not found - add */
    b = prev->next = (buck *)slapi_ch_calloc(1,sizeof(buck));
  } else {
    ht->bucks[i] = b = (buck *)slapi_ch_calloc(1,sizeof(buck));
  }

  lock = (ulock *)slapi_ch_calloc(1,sizeof(ulock));
  lock->conn_id = conn_id;
  if (gettimeofday(&(lock->tv),NULL)) {
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		    "conn=%d gettimeofday error: %s",strerror(errno));
    //    udb_rdwr_wunlock(&(ht->rdwr));
    //    return -1;
    ret = -1;
    goto end;
  }

  lock->tv.tv_sec += LOCK_EXP_TM;
  b->key = slapi_ch_strdup(key);
  b->data = lock;
  b->next = NULL;
  ret = 0;

#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "bucket added at b=%p, ht->bucks[%d]=%p\n",b,i,ht->bucks[i]);
#endif
 end:
  udb_rdwr_wunlock(&(ht->rdwr));
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash unlocked, returning %d\n",ret);
#endif
  return ret;
}

/* return 0 on success, -1 on not found, 1 when locked by another connection */
int udb_lock_find (htab *ht, char *key, int conn_id)
{
  buck *b,*prev;
  int i;
  ulock *lock;
  //  struct timeval now;
  int ret = -1;
#if DEBUG & DBG_LOCK
  char ident[] = "udb_lock_find";

  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "conn=%d started with ht=%p key=%s\n", conn_id,ht,key);
#endif

  i = _getindex(key);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident, "i=%d\n", i);
#endif
  udb_rdwr_wlock(&(ht->rdwr),NULL);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"hash locked\n");
#endif

  if ((b = ht->bucks[i]) != NULL) {
    /* check for key presence */
    for (; b; prev=b, b=b->next) {
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn=%d checking key \"%s\" at b=%p, b->key=%p, b->next=%p\n",
			conn_id,b->key,b,b->key,b->next);
#endif
      if (strcmp(b->key,key) == 0) {
	ulock *lock;

	lock = (ulock *)b->data;
#if DEBUG & DBG_LOCK
	slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn=%d key found: conn_id=%d, exp=%s,%06ld\n",
			conn_id,lock->conn_id,ctime(&(lock->tv.tv_sec)),
			lock->tv.tv_usec);
#endif

	if (lock->conn_id == conn_id) {
	  /* OK, it's our lock, renew it */
	  if (gettimeofday(&(lock->tv),NULL)) {
	    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			    "conn=%d gettimeofday error: %s",
			    strerror(errno));
	    ret = -1;
	    goto end;
	  }
	  lock->tv.tv_sec += LOCK_EXP_TM;
#if DEBUG & DBG_LOCK
	  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			"conn_id=%d, lock renewed: exp=%s,%06ld\n",
			conn_id,ctime(&(lock->tv.tv_sec)),lock->tv.tv_usec);
#endif
	    ret = 0;
	    goto end;
	} else {
#if DEBUG
	  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
			  "conn=%d \"%s\" locked by conn %d\n",
			  conn_id,key,lock->conn_id);
#endif
	  ret = 1;
	}
      }
    }
  }
 end:
  udb_rdwr_wunlock(&(ht->rdwr));
  return ret;
}
#endif /* 0 */
int udb_unlock (htab *ht, char *key, int conn_id, void **datap) 
{
  buck *b,*prev=NULL;
  int i, ret=-1;
#if DEBUG & DBG_LOCK
  char ident[] = "udb_unlock";

  slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		  "conn=%d started with ht=%p key=%s\n", conn_id,ht,key);
#endif

  *datap = NULL;

  i = _getindex(key);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"conn=%d i=%d\n", conn_id,i);
#endif

  udb_rdwr_wlock(&(ht->rdwr),NULL);
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"conn=%d hash locked\n", conn_id);
#endif

  for (prev=b=ht->bucks[i]; b; prev=b, b=b->next) {
#if DEBUG & DBG_LOCK
    slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		    "conn=%d checking key \"%s\" at b=%p, b->key=%p, b->next=%p\n",
		    conn_id,b->key,b,b->key,b->next);
#endif
    if (strcmp(b->key,key) == 0) {
      ulock *lock;
      lock = (ulock *)b->data;

#if DEBUG & DBG_LOCK
      slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		      "conn=%d key found: conn_id=%d, exp=%s,%06ld\n",
		      conn_id,lock->conn_id,ctime(&(lock->tv.tv_sec)),
		      lock->tv.tv_usec);
#endif
      prev->next = b->next;
      *datap = b->data;
      slapi_ch_free((void**)&(b->key));

      if (b == prev) {
	/* we're at the first buck */
	ht->bucks[i] = prev->next;
      }
#if DEBUG & DBG_LOCK
      slapi_log_error(SLAPI_LOG_PLUGIN,ident,
		      "conn=%d bucket deleted at b=%p, ht->bucks[%d]=%p\n",
		      conn_id,b,i,ht->bucks[i]);
#endif
      slapi_ch_free((void**)&b);
      break;
    }
  }
  udb_rdwr_wunlock(&(ht->rdwr));
#if DEBUG & DBG_LOCK
  slapi_log_error(SLAPI_LOG_PLUGIN,ident,"conn=%d hash unlocked\n", conn_id);
#endif
  return ret;
}

