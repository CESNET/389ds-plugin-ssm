
#include "udb_log.h"

#include <stdio.h>
#include <stdarg.h>

static FILE* log_file = NULL;

void log_init()
{
    if ( log_file == NULL )
        log_file = fopen( "/usr/src/UDB/debug_log", "wt" );
}

void log_exit()
{
    fclose( log_file );
    log_file = NULL;
}

void log_err( int errid, const char* context, const char* format, ... )
{
    va_list args;

    va_start( args, format );

    if ( log_file == NULL )
        log_init();

    fprintf( log_file, "log_err( %i, %s ):\n\t", errid, context );
    vfprintf( log_file, format, args );
    fputc( '\n', log_file );
    fflush( log_file );

    va_end( args );
}

void log_info( const char* context, const char* format, ... )
{
    va_list args;

    va_start( args, format );

    if ( log_file == NULL )
        log_init();

    fprintf( log_file, "log_info( %s ):\n\t", context );
    vfprintf( log_file, format, args );
    fputc( '\n', log_file );
    fflush( log_file );

    va_end( args );
}

void log_warn( int warnid, const char* context, const char* format, ... )
{
    va_list args;

    va_start( args, format );

    if ( log_file == NULL )
        log_init();

    fprintf( log_file, "log_warn( %i, %s ):\n\t", warnid, context );
    vfprintf( log_file, format, args );
    fputc( '\n', log_file );
    fflush( log_file );

    va_end( args );
}

