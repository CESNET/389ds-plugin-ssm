/* $Id$ */

#ifndef UDB_LOG_H
# define UDB_LOG_H

#define MODULE_NAME	"SSM"
#define	MIDENT(x)	"SSM:x"


#define ERR_PBLOCK		1
#define	ERR_UDB_FUNC_RUN	2
#define	ERR_LDAP_OPERATION	3

#define log_err(errid,context,x...)	slapi_log_error(SLAPI_LOG_FATAL, context, x)

#define log_info(context,x...)		slapi_log_error(SLAPI_LOG_PLUGIN, context, x)

#define log_warn(warnid,context,x...)	slapi_log_warning_ex(SLAPI_LOG_FATAL, context, x)

#endif /* UDB_LOG_H */
