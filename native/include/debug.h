/**
 * ITX Security Shield - Debug System
 *
 * Provides compile-time and runtime control for debug messages.
 *
 * COMPILE-TIME CONTROL:
 *   - With -DITX_DEBUG_ENABLED: Debug code is compiled in
 *   - Without flag: All debug code is stripped out (zero overhead)
 *
 * RUNTIME CONTROL (when compiled with ITX_DEBUG_ENABLED):
 *   - Set ITX_DEBUG=1 environment variable to enable logging
 *   - Set ITX_DEBUG=0 or unset to disable logging
 *
 * USAGE:
 *   #include "debug.h"
 *
 *   DEBUG_INIT();  // Call once at start of function
 *   DEBUG_LOG("Machine ID: %s", machine_id);
 *   DEBUG_DUMP_HEX(fingerprint_data, 32);
 */

#ifndef ITX_DEBUG_H
#define ITX_DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

/**
 * Compile-time debug switch
 * Define ITX_DEBUG_ENABLED during compilation to enable debug system
 */
#ifdef ITX_DEBUG_ENABLED
    #define DEBUG_INIT() itx_debug_init()
    #define DEBUG_LOG(fmt, ...) itx_debug_log(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
    #define DEBUG_DUMP_HEX(data, len) itx_debug_dump_hex(data, len)
    #define DEBUG_WARN(fmt, ...) itx_debug_warn(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
    #define DEBUG_ERROR(fmt, ...) itx_debug_error(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
    // No-op macros when debug is disabled at compile time (zero overhead)
    #define DEBUG_INIT() ((void)0)
    #define DEBUG_LOG(fmt, ...) ((void)0)
    #define DEBUG_DUMP_HEX(data, len) ((void)0)
    #define DEBUG_WARN(fmt, ...) ((void)0)
    #define DEBUG_ERROR(fmt, ...) ((void)0)
#endif

/**
 * Runtime debug control (only used when ITX_DEBUG_ENABLED is defined)
 * 0 = disabled, 1 = enabled
 */
extern int itx_debug_enabled;

/**
 * Initialize debug system
 * Reads ITX_DEBUG environment variable to set runtime state
 * Safe to call multiple times (will only initialize once)
 */
void itx_debug_init(void);

/**
 * Log debug message with file/line information
 * Only outputs if itx_debug_enabled == 1
 */
void itx_debug_log(const char *file, int line, const char *fmt, ...);

/**
 * Log warning message with file/line information
 * Only outputs if itx_debug_enabled == 1
 */
void itx_debug_warn(const char *file, int line, const char *fmt, ...);

/**
 * Log error message with file/line information
 * Only outputs if itx_debug_enabled == 1
 */
void itx_debug_error(const char *file, int line, const char *fmt, ...);

/**
 * Dump binary data as hex (useful for fingerprints, keys, etc.)
 * Only outputs if itx_debug_enabled == 1
 */
void itx_debug_dump_hex(const unsigned char *data, size_t len);

#endif /* ITX_DEBUG_H */
