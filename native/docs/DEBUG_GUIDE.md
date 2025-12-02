# ITX Security Shield - Debug System Guide

## Overview

The ITX Security Shield C library includes a sophisticated debug logging system that provides **zero overhead in production builds** while offering detailed diagnostic information during development.

## Key Features

- **Compile-time control**: Debug code can be completely stripped from production builds
- **Runtime control**: Even in debug builds, logging can be toggled on/off via environment variable
- **Rich logging**: File name, line number, and timestamps automatically included
- **Multiple log levels**: DEBUG, WARN, ERROR
- **Binary data dumping**: Hex dump functionality for fingerprints, hashes, etc.

## Quick Start

### Building with Debug Support

```bash
# Debug build (includes debug infrastructure)
gcc -DITX_DEBUG_ENABLED -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto

# Production build (completely strips debug code)
gcc -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

### Running with Debug Logging

```bash
# Enable debug output
ITX_DEBUG=1 ./test_integrity

# Disable debug output (default)
./test_integrity

# Explicitly disable
ITX_DEBUG=0 ./test_integrity
```

## Usage in Code

### 1. Include the Header

```c
#include "debug.h"
```

### 2. Initialize Debug System

Call `DEBUG_INIT()` once at the start of your function (usually in public API functions):

```c
char* itx_get_fingerprint() {
    DEBUG_INIT();  // Initialize debug system
    DEBUG_LOG("Starting fingerprint generation");

    // ... rest of code
}
```

### 3. Use Debug Macros

```c
// Informational logging
DEBUG_LOG("Machine ID: %s", machine_id);
DEBUG_LOG("CPU cores: %d", cpu_cores);

// Warning logging
DEBUG_WARN("Failed to open file: %s", filepath);

// Error logging
DEBUG_ERROR("NULL pointer passed to function");

// Hex dump (useful for hashes, fingerprints)
unsigned char hash[32];
DEBUG_DUMP_HEX(hash, 32);
```

## Debug Macros Reference

| Macro | Purpose | Example |
|-------|---------|---------|
| `DEBUG_INIT()` | Initialize debug system | `DEBUG_INIT();` |
| `DEBUG_LOG(fmt, ...)` | Log informational message | `DEBUG_LOG("Value: %d", x);` |
| `DEBUG_WARN(fmt, ...)` | Log warning message | `DEBUG_WARN("File not found");` |
| `DEBUG_ERROR(fmt, ...)` | Log error message | `DEBUG_ERROR("Invalid input");` |
| `DEBUG_DUMP_HEX(data, len)` | Dump binary data as hex | `DEBUG_DUMP_HEX(hash, 32);` |

## Output Format

### Log Messages

```
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:245 - Starting hardware info collection
[ITX WARN] [2025-12-01 14:30:45] integrity_check.c:16 - Failed to open file: /etc/machine-id
[ITX ERROR] [2025-12-01 14:30:45] integrity_check.c:249 - NULL pointer passed to itx_get_hardware_info
```

Format: `[LEVEL] [TIMESTAMP] filename:line - message`

### Hex Dump

```
[ITX DEBUG] Hex dump (32 bytes):
a3f2d4e5 6b8c9d1a 2e3f4a5b 6c7d8e9f
1a2b3c4d 5e6f7a8b 9c0d1e2f 3a4b5c6d
```

32 bytes per line, space every 4 bytes for readability.

## Build Configurations

### Development Build

```bash
# Full debug support with debug logging enabled by default
gcc -DITX_DEBUG_ENABLED -g -O0 -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

Flags:
- `-DITX_DEBUG_ENABLED`: Enable debug infrastructure
- `-g`: Include debug symbols for GDB
- `-O0`: No optimization (easier debugging)

### Testing Build

```bash
# Debug support included but must be explicitly enabled at runtime
gcc -DITX_DEBUG_ENABLED -O2 -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

Flags:
- `-DITX_DEBUG_ENABLED`: Enable debug infrastructure
- `-O2`: Some optimization (performance closer to production)

### Production Build

```bash
# Zero debug overhead - all debug code stripped
gcc -O3 -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

Flags:
- No `-DITX_DEBUG_ENABLED`: Debug code completely removed
- `-O3`: Full optimization

## Performance Considerations

### Production Build (No `-DITX_DEBUG_ENABLED`)

- **Binary size**: Smaller (no debug strings, no debug functions)
- **Runtime overhead**: Zero (macros expand to no-ops)
- **Security**: No debug information leakage

### Debug Build with Logging Disabled (`ITX_DEBUG=0`)

- **Binary size**: Larger (includes debug infrastructure)
- **Runtime overhead**: Minimal (only boolean checks)
- **Security**: Debug strings present in binary but not printed

### Debug Build with Logging Enabled (`ITX_DEBUG=1`)

- **Binary size**: Larger
- **Runtime overhead**: Moderate (file I/O, formatting, timestamps)
- **Use case**: Development and troubleshooting only

## Example Output

Running `ITX_DEBUG=1 ./test_integrity`:

```
[ITX DEBUG] Debug logging enabled (ITX_DEBUG=1)
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:245 - Starting hardware info collection
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:13 - Reading file: /etc/machine-id
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:23 - Successfully read from /etc/machine-id: 1234567890abcdef...
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:259 - Machine ID: 1234567890abcdef...
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:143 - Checking Docker environment
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:165 - Docker NOT detected
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:291 - Docker: NO
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:171 - Checking VM environment
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:182 - System vendor: dell inc.
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:212 - VM NOT detected
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:295 - VM: NO
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:307 - Starting fingerprint generation
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:329 - Combined hardware string length: 256 bytes
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:335 - SHA-256 hash computed
[ITX DEBUG] Hex dump (32 bytes):
a3f2d4e5 6b8c9d1a 2e3f4a5b 6c7d8e9f
1a2b3c4d 5e6f7a8b 9c0d1e2f 3a4b5c6d
[ITX DEBUG] [2025-12-01 14:30:45] integrity_check.c:344 - Final fingerprint: a3f2d4e56b8c9d1a2e3f4a5b6c7d8e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
```

## Troubleshooting

### Debug messages not appearing

1. **Check compile flag**: Was library compiled with `-DITX_DEBUG_ENABLED`?
   ```bash
   # Rebuild with debug support
   gcc -DITX_DEBUG_ENABLED -shared -fPIC -o libintegrity.so \
       src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
   ```

2. **Check environment variable**: Is `ITX_DEBUG` set to `1`?
   ```bash
   ITX_DEBUG=1 ./test_integrity
   ```

3. **Check initialization**: Is `DEBUG_INIT()` called?
   - Should be called at the start of each public API function

### Too many debug messages

```bash
# Disable at runtime
ITX_DEBUG=0 ./test_integrity

# Or rebuild without debug support
gcc -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

### Debug messages in production

If you see debug messages in a production build, you accidentally compiled with `-DITX_DEBUG_ENABLED`. Rebuild without this flag:

```bash
gcc -O3 -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

## Best Practices

### 1. Use DEBUG_INIT() in Public APIs Only

```c
// ✓ Good - public API
char* itx_get_fingerprint() {
    DEBUG_INIT();
    DEBUG_LOG("Starting fingerprint generation");
    // ...
}

// ✗ Not necessary - internal function (will inherit debug state)
static int read_file(const char *path) {
    DEBUG_LOG("Reading file: %s", path);  // Just use DEBUG_LOG directly
    // ...
}
```

### 2. Log Important State Changes

```c
DEBUG_LOG("Machine ID: %s", info->machine_id);
DEBUG_LOG("Docker: %s", info->is_docker ? "YES" : "NO");
DEBUG_LOG("VM: %s", info->is_vm ? "YES" : "NO");
```

### 3. Use Appropriate Log Levels

```c
DEBUG_LOG("Normal operation");     // Informational
DEBUG_WARN("Fallback triggered");  // Warning condition
DEBUG_ERROR("Fatal error");        // Error condition
```

### 4. Dump Binary Data with DEBUG_DUMP_HEX

```c
unsigned char hash[SHA256_DIGEST_LENGTH];
SHA256(data, len, hash);
DEBUG_DUMP_HEX(hash, SHA256_DIGEST_LENGTH);
```

### 5. Always Build Production Without Debug

```bash
# Production release
gcc -O3 -DNDEBUG -shared -fPIC -o libintegrity.so \
    src/integrity_check.c src/debug.c -I./include -lssl -lcrypto
```

## Integration with Python Wrapper

When using the library from Python via ctypes:

```python
import os
import ctypes

# Enable debug mode
os.environ['ITX_DEBUG'] = '1'

# Load library (must be compiled with -DITX_DEBUG_ENABLED)
lib = ctypes.CDLL('./libintegrity.so')

# Call functions - debug messages will appear on stderr
fingerprint = lib.itx_get_fingerprint()
```

## Security Considerations

1. **Sensitive data in logs**: Debug logs may contain hardware identifiers, fingerprints, etc.
   - Never enable debug logging in production
   - Sanitize logs before sharing

2. **Information leakage**: Debug strings are compiled into binary
   - Production builds should use `-DNDEBUG` and omit `-DITX_DEBUG_ENABLED`

3. **Log file security**: Redirect debug output to secure location
   ```bash
   ITX_DEBUG=1 ./test_integrity 2> secure_debug.log
   chmod 600 secure_debug.log
   ```

## Summary

The ITX Security Shield debug system provides:

- ✓ Zero overhead in production builds
- ✓ Flexible runtime control in debug builds
- ✓ Rich diagnostic information with timestamps and locations
- ✓ Binary data visualization
- ✓ Multiple log levels
- ✓ Easy integration into existing code

For production use, always build without `-DITX_DEBUG_ENABLED` to ensure no debug overhead.
