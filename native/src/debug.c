/**
 * ITX Security Shield - Debug System Implementation
 */

#include "debug.h"

/* Only compile this code if debug is enabled at compile time */
#ifdef ITX_DEBUG_ENABLED

/* Runtime control flag */
int itx_debug_enabled = 0;

/* Initialization flag to prevent multiple reads of env variable */
static int itx_debug_initialized = 0;

/**
 * Initialize debug system
 * Reads ITX_DEBUG environment variable (1 = enable, 0 or unset = disable)
 */
void itx_debug_init(void) {
    if (itx_debug_initialized) {
        return;  /* Already initialized */
    }

    const char *env_debug = getenv("ITX_DEBUG");
    if (env_debug != NULL && strcmp(env_debug, "1") == 0) {
        itx_debug_enabled = 1;
        fprintf(stderr, "[ITX DEBUG] Debug logging enabled (ITX_DEBUG=1)\n");
    } else {
        itx_debug_enabled = 0;
    }

    itx_debug_initialized = 1;
}

/**
 * Get current timestamp string for logging
 */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * Extract filename from full path
 */
static const char* get_basename(const char *path) {
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/**
 * Log debug message
 */
void itx_debug_log(const char *file, int line, const char *fmt, ...) {
    if (!itx_debug_enabled) {
        return;
    }

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(stderr, "[ITX DEBUG] [%s] %s:%d - ", timestamp, get_basename(file), line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}

/**
 * Log warning message
 */
void itx_debug_warn(const char *file, int line, const char *fmt, ...) {
    if (!itx_debug_enabled) {
        return;
    }

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(stderr, "[ITX WARN] [%s] %s:%d - ", timestamp, get_basename(file), line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}

/**
 * Log error message
 */
void itx_debug_error(const char *file, int line, const char *fmt, ...) {
    if (!itx_debug_enabled) {
        return;
    }

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(stderr, "[ITX ERROR] [%s] %s:%d - ", timestamp, get_basename(file), line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}

/**
 * Dump binary data as hex
 */
void itx_debug_dump_hex(const unsigned char *data, size_t len) {
    if (!itx_debug_enabled || data == NULL) {
        return;
    }

    fprintf(stderr, "[ITX DEBUG] Hex dump (%zu bytes):\n", len);

    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x", data[i]);
        if ((i + 1) % 32 == 0) {
            fprintf(stderr, "\n");
        } else if ((i + 1) % 4 == 0) {
            fprintf(stderr, " ");
        }
    }

    if (len % 32 != 0) {
        fprintf(stderr, "\n");
    }

    fflush(stderr);
}

#else

/* Stub definitions when debug is disabled (to satisfy linker) */
int itx_debug_enabled = 0;
void itx_debug_init(void) {}
void itx_debug_log(const char *file, int line, const char *fmt, ...) {}
void itx_debug_warn(const char *file, int line, const char *fmt, ...) {}
void itx_debug_error(const char *file, int line, const char *fmt, ...) {}
void itx_debug_dump_hex(const unsigned char *data, size_t len) {}

#endif /* ITX_DEBUG_ENABLED */
