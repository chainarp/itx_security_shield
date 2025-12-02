# ITX Security Shield - Odoo Addon

Hardware-based license protection system for Odoo addons using native C library for secure hardware fingerprinting.

## Features

- **Hardware Fingerprinting**: SHA-256 fingerprints based on machine-id, CPU, MAC, DMI UUID, disk UUID
- **Environment Detection**: Docker, VM, and debugger detection
- **Native Performance**: C library for security and speed
- **Error Handling**: Comprehensive Python exceptions with detailed error messages
- **Debug Support**: Optional debug logging for troubleshooting

## Architecture

```
itx_security_shield/
├── native/                  # C library (source + compiled)
│   ├── src/                 # C source files
│   ├── include/             # Header files
│   ├── libintegrity.so      # Compiled library
│   └── dev.sh               # Build script
├── lib/                     # Python wrapper
│   ├── verifier.py          # Main wrapper class
│   ├── exceptions.py        # Custom exceptions
│   └── __init__.py
├── models/                  # Odoo models (future)
├── views/                   # Odoo views (future)
├── security/                # Access control (future)
└── tests/                   # Test scripts
```

## Installation

### 1. Compile C Library

```bash
cd ~/PycharmProjects/odoo19/custom_addons/itx_security_shield/native
./dev.sh prod
```

### 2. Test Python Wrapper

```bash
cd ~/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 tests/test_wrapper.py
```

### 3. Install Odoo Addon

```bash
# In Odoo
# Apps > Update Apps List
# Search for "ITX Security Shield"
# Install
```

## Usage

### Basic Usage

```python
from odoo.addons.itx_security_shield.lib import ITXSecurityVerifier

# Initialize verifier
verifier = ITXSecurityVerifier()

# Get hardware fingerprint
fingerprint = verifier.get_fingerprint()
print(f"Fingerprint: {fingerprint}")

# Get hardware information
hw_info = verifier.get_hardware_info()
print(f"Machine ID: {hw_info['machine_id']}")
print(f"CPU: {hw_info['cpu_model']}")
```

### With Error Handling

```python
from odoo.addons.itx_security_shield.lib import (
    ITXSecurityVerifier,
    LibraryError,
    HardwareDetectionError,
    FingerprintError,
)

try:
    verifier = ITXSecurityVerifier()
    fingerprint = verifier.get_fingerprint()
    print(f"Success: {fingerprint}")

except LibraryError as e:
    print(f"Library error: {e}")
    # Handle library loading issues

except HardwareDetectionError as e:
    print(f"Hardware detection error: {e}")
    if e.missing_fields:
        print(f"Missing fields: {', '.join(e.missing_fields)}")
    # Handle missing hardware info

except FingerprintError as e:
    print(f"Fingerprint error: {e}")
    # Handle fingerprint generation issues
```

### Debug Mode

```python
# Enable debug logging from C library
verifier = ITXSecurityVerifier(debug=True)

# C library will output detailed debug messages to stderr
hw_info = verifier.get_hardware_info()
```

### Comprehensive Verification

```python
verifier = ITXSecurityVerifier()

# Get everything in one call
result = verifier.verify()

print("Hardware:", result['hardware'])
print("Fingerprint:", result['fingerprint'])
print("Environment:", result['environment'])
```

## Exception Hierarchy

```
ITXSecurityError (base)
├── LibraryError              # C library loading/initialization
├── HardwareDetectionError    # Hardware info retrieval
├── FingerprintError          # Fingerprint generation
├── PermissionError           # Insufficient permissions
└── PlatformError             # Unsupported platform
```

## Error Messages

All exceptions include:
- **Detailed description** of the error
- **Possible causes** (permissions, missing files, etc.)
- **Troubleshooting steps** (commands to run, what to check)
- **Context information** (missing fields, library path, etc.)

Example:

```python
try:
    hw_info = verifier.get_hardware_info()
except HardwareDetectionError as e:
    # Error message includes:
    # - What failed
    # - Why it might have failed
    # - How to fix it
    # - Which fields are missing
    print(e)
```

## Development

### Running Tests

```bash
# Test Python wrapper
python3 tests/test_wrapper.py

# Test with debug output
ITX_DEBUG=1 python3 tests/test_wrapper.py
```

### Rebuilding C Library

```bash
cd native/

# Production build (no debug)
./dev.sh prod

# Debug build (with debug messages)
./dev.sh debug

# Run all tests
./dev.sh all
```

## Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 10+)
- **Python**: 3.8+
- **Odoo**: 19.0+
- **C Compiler**: GCC with C17 support
- **Libraries**: OpenSSL 3.0+ (`libssl-dev`)

## Troubleshooting

### Library Not Found

```bash
# Check if library exists
ls -la native/libintegrity.so

# If not, compile it
cd native/ && ./dev.sh prod
```

### Permission Errors

```bash
# Some hardware info requires root
sudo python3 tests/test_wrapper.py
```

### Debug C Library

```bash
cd native/
./dev.sh debug
ITX_DEBUG=1 ./test_integrity
```

## Security Considerations

- Hardware fingerprints are SHA-256 hashes (irreversible)
- No sensitive data is transmitted or stored
- Debugger detection helps prevent tampering
- Docker/VM detection for environment validation

## License

LGPL-3

## Support

For issues and questions:
- GitHub: https://github.com/chainarp/itx_security_shield
- Email: support@itxcorp.com
