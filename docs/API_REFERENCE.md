# API Reference - ITX Security Shield Python Wrapper

เอกสารอ้างอิง API สำหรับ Python wrapper ของ ITX Security Shield

---

## 📋 สารบัญ

1. [ITXSecurityVerifier Class](#itxsecurityverifier-class)
2. [Exception Classes](#exception-classes)
3. [Data Structures](#data-structures)
4. [Constants](#constants)
5. [Examples](#examples)

---

## ITXSecurityVerifier Class

### Overview

```python
from lib import ITXSecurityVerifier

verifier = ITXSecurityVerifier(library_path=None, debug=False)
```

Class หลักสำหรับการทำงานกับ C library เพื่อ hardware fingerprinting และ license verification

---

### Constructor

#### `__init__(library_path=None, debug=False)`

สร้าง instance ของ ITXSecurityVerifier

**Parameters:**
- `library_path` (str, optional): Path to libintegrity.so
  - Default: None (auto-detect)
  - Auto-detect ลำดับ:
    1. `native/libintegrity.so`
    2. Same directory as verifier.py
    3. Parent directory
    4. `/usr/local/lib/libintegrity.so`
    5. `/usr/lib/libintegrity.so`

- `debug` (bool, optional): Enable debug logging
  - Default: False
  - ต้อง compile C library ด้วย `-DITX_DEBUG_ENABLED`

**Returns:**
- ITXSecurityVerifier instance

**Raises:**
- `LibraryError`: ถ้า load library ไม่สำเร็จ
- `PlatformError`: ถ้าระบบไม่รองรับ (non-Linux)

**Example:**
```python
# Auto-detect library path
v = ITXSecurityVerifier()

# With debug
v = ITXSecurityVerifier(debug=True)

# Custom library path
v = ITXSecurityVerifier(library_path='/path/to/libintegrity.so')
```

---

### Methods

#### `get_hardware_info()`

ดึงข้อมูล hardware ทั้งหมด

**Parameters:**
- None

**Returns:**
- `dict`: Dictionary containing hardware information
  ```python
  {
      'machine_id': str,          # Linux machine ID
      'cpu_model': str,           # CPU model name
      'cpu_cores': int,           # Number of CPU cores
      'mac_address': str,         # MAC address
      'dmi_uuid': str,            # DMI UUID
      'disk_uuid': str,           # Root filesystem UUID
      'is_docker': bool,          # Running in Docker?
      'is_vm': bool,              # Running in VM?
      'debugger_detected': bool   # Debugger attached?
  }
  ```

**Raises:**
- `HardwareDetectionError`: ถ้าดึงข้อมูลไม่สำเร็จหรือมี field ที่เป็น 'unknown'
- `PermissionError`: ถ้า permissions ไม่พอ

**Example:**
```python
v = ITXSecurityVerifier()
hw_info = v.get_hardware_info()

print(f"Machine ID: {hw_info['machine_id']}")
print(f"CPU: {hw_info['cpu_model']}")
print(f"Cores: {hw_info['cpu_cores']}")
```

**Notes:**
- บาง field อาจต้องการ root permission (เช่น dmi_uuid)
- ถ้าข้อมูลใดไม่สามารถดึงได้ จะ raise HardwareDetectionError พร้อมระบุ missing_fields

---

#### `get_fingerprint()`

Generate hardware fingerprint (SHA-256 hash)

**Parameters:**
- None

**Returns:**
- `str`: 64-character hexadecimal fingerprint

**Raises:**
- `FingerprintError`: ถ้า generate fingerprint ไม่สำเร็จ

**Example:**
```python
v = ITXSecurityVerifier()
fingerprint = v.get_fingerprint()

print(f"Fingerprint: {fingerprint}")
# Output: 44739f4d4ecc13900b345178efd217c5b7c3bdffdb994a3626a1fee8cd4cfde1
```

**Notes:**
- Fingerprint เป็น SHA-256 hash ของ: machine_id + CPU model + CPU cores + MAC address + DMI UUID + Disk UUID
- Idempotent: การเรียกซ้ำจะได้ fingerprint เดิมถ้า hardware ไม่เปลี่ยน
- Irreversible: ไม่สามารถ reverse กลับเป็น hardware info ได้

---

#### `is_docker()`

ตรวจสอบว่ากำลังรันใน Docker container หรือไม่

**Parameters:**
- None

**Returns:**
- `bool`: True ถ้ารันใน Docker, False otherwise

**Raises:**
- `HardwareDetectionError`: ถ้าตรวจสอบไม่สำเร็จ

**Example:**
```python
v = ITXSecurityVerifier()
if v.is_docker():
    print("Running in Docker container")
else:
    print("Not running in Docker")
```

**Detection Methods:**
- ตรวจสอบ `/.dockerenv` file
- ตรวจสอบ `/proc/1/cgroup` สำหรับ "docker" หรือ "containerd"

---

#### `is_vm()`

ตรวจสอบว่ากำลังรันใน Virtual Machine หรือไม่

**Parameters:**
- None

**Returns:**
- `bool`: True ถ้ารันใน VM, False otherwise

**Raises:**
- `HardwareDetectionError`: ถ้าตรวจสอบไม่สำเร็จ

**Example:**
```python
v = ITXSecurityVerifier()
if v.is_vm():
    print("Running in Virtual Machine")
else:
    print("Running on physical hardware")
```

**Detection Methods:**
- ตรวจสอบ DMI system vendor (VMware, VirtualBox, QEMU, KVM, Xen, Hyper-V)
- ตรวจสอบ CPU flags สำหรับ "hypervisor"

---

#### `is_debugger_attached()`

ตรวจสอบว่ามี debugger attach อยู่หรือไม่

**Parameters:**
- None

**Returns:**
- `bool`: True ถ้ามี debugger, False otherwise

**Raises:**
- `HardwareDetectionError`: ถ้าตรวจสอบไม่สำเร็จ

**Example:**
```python
v = ITXSecurityVerifier()
if v.is_debugger_attached():
    print("Warning: Debugger detected!")
else:
    print("No debugger detected")
```

**Detection Methods:**
- ตรวจสอบ `TracerPid` ใน `/proc/self/status`

**Notes:**
- ใช้สำหรับ anti-tampering protection
- Debugger detection ไม่ได้ป้องกัน 100% แต่ช่วยลดความเสี่ยง

---

#### `verify()`

Comprehensive verification - รวมทุกอย่างเข้าด้วยกัน

**Parameters:**
- None

**Returns:**
- `dict`: Dictionary containing all information
  ```python
  {
      'hardware': {
          'machine_id': str,
          'cpu_model': str,
          'cpu_cores': int,
          'mac_address': str,
          'dmi_uuid': str,
          'disk_uuid': str,
          'is_docker': bool,
          'is_vm': bool,
          'debugger_detected': bool
      },
      'fingerprint': str,
      'environment': {
          'is_docker': bool,
          'is_vm': bool,
          'debugger_detected': bool
      }
  }
  ```

**Raises:**
- `ITXSecurityError`: ถ้าการ verify ล้มเหลว (subclass ใดก็ได้)

**Example:**
```python
v = ITXSecurityVerifier()
result = v.verify()

print("Hardware:", result['hardware'])
print("Fingerprint:", result['fingerprint'])
print("Environment:", result['environment'])
```

**Notes:**
- เป็น convenience method ที่เรียก get_hardware_info(), get_fingerprint(), และ environment checks ทั้งหมด
- เหมาะสำหรับการ verify ครั้งเดียวครบทุกอย่าง

---

#### `__repr__()`

String representation ของ verifier instance

**Parameters:**
- None

**Returns:**
- `str`: String representation

**Example:**
```python
v = ITXSecurityVerifier()
print(repr(v))
# Output: ITXSecurityVerifier(library_path='/path/to/libintegrity.so', debug=False)
```

---

### Properties

#### `_library_path`

Path to loaded C library (read-only)

```python
v = ITXSecurityVerifier()
print(v._library_path)
# Output: /home/chainarp/.../native/libintegrity.so
```

#### `debug`

Debug mode status (read-only)

```python
v = ITXSecurityVerifier(debug=True)
print(v.debug)
# Output: True
```

---

## Exception Classes

### Base Exception

#### `ITXSecurityError`

Base exception สำหรับทุก errors ใน ITX Security Shield

```python
from lib import ITXSecurityError

try:
    v = ITXSecurityVerifier()
    v.get_fingerprint()
except ITXSecurityError as e:
    print(f"Security error: {e}")
```

---

### Specific Exceptions

#### `LibraryError`

Raised เมื่อ C library ไม่สามารถ load หรือ initialize ได้

**Attributes:**
- `library_path` (str): Path ที่พยายาม load

**Common Causes:**
- Library file ไม่มี
- Missing dependencies (libssl, libcrypto)
- Architecture mismatch (32-bit vs 64-bit)
- Invalid/corrupted library

**Example:**
```python
from lib import ITXSecurityVerifier, LibraryError

try:
    v = ITXSecurityVerifier(library_path='/invalid/path.so')
except LibraryError as e:
    print(f"Error: {e}")
    print(f"Path: {e.library_path}")
```

---

#### `HardwareDetectionError`

Raised เมื่อไม่สามารถดึงข้อมูล hardware ได้

**Attributes:**
- `missing_fields` (list): รายชื่อ fields ที่ missing

**Common Causes:**
- Insufficient permissions
- Running in container (limited hardware access)
- Missing system files

**Example:**
```python
from lib import ITXSecurityVerifier, HardwareDetectionError

try:
    v = ITXSecurityVerifier()
    hw = v.get_hardware_info()
except HardwareDetectionError as e:
    print(f"Error: {e}")
    if e.missing_fields:
        print(f"Missing: {', '.join(e.missing_fields)}")
```

---

#### `FingerprintError`

Raised เมื่อไม่สามารถ generate fingerprint ได้

**Common Causes:**
- C library internal error
- Memory allocation failure
- Invalid hardware data

**Example:**
```python
from lib import ITXSecurityVerifier, FingerprintError

try:
    v = ITXSecurityVerifier()
    fp = v.get_fingerprint()
except FingerprintError as e:
    print(f"Fingerprint error: {e}")
```

---

#### `PermissionError`

Raised เมื่อ permissions ไม่พอสำหรับการดึงข้อมูล hardware

**Attributes:**
- `required_permissions` (list): รายการ permissions ที่ต้องการ

**Common Causes:**
- Need root/sudo for certain hardware info
- File permissions ไม่ถูกต้อง

**Example:**
```python
from lib import ITXSecurityVerifier, PermissionError

try:
    v = ITXSecurityVerifier()
    hw = v.get_hardware_info()
except PermissionError as e:
    print(f"Permission error: {e}")
    if e.required_permissions:
        print(f"Required: {', '.join(e.required_permissions)}")
```

---

#### `PlatformError`

Raised เมื่อรันบน platform ที่ไม่รองรับ

**Attributes:**
- `current_platform` (str): ชื่อ platform ปัจจุบัน

**Supported Platform:**
- Linux only

**Example:**
```python
from lib import ITXSecurityVerifier, PlatformError

try:
    v = ITXSecurityVerifier()
except PlatformError as e:
    print(f"Platform error: {e}")
    print(f"Current: {e.current_platform}")
```

---

## Data Structures

### HardwareInfo (ctypes.Structure)

C structure สำหรับ hardware information (internal use)

```python
class HardwareInfo(ctypes.Structure):
    _fields_ = [
        ("machine_id", ctypes.c_char * 256),
        ("cpu_model", ctypes.c_char * 256),
        ("cpu_cores", ctypes.c_int),
        ("mac_address", ctypes.c_char * 64),
        ("dmi_uuid", ctypes.c_char * 256),
        ("disk_uuid", ctypes.c_char * 256),
        ("is_docker", ctypes.c_bool),
        ("is_vm", ctypes.c_bool),
        ("debugger_detected", ctypes.c_bool),
    ]
```

**Note:** นี่เป็น internal structure ใช้กับ ctypes ไม่ควรใช้โดยตรง ใช้ `get_hardware_info()` แทน

---

## Constants

### Return Codes (from C library)

```python
ITX_OK = 0      # Success
ITX_ERROR = -1  # Error
```

---

## Examples

### Example 1: Basic Hardware Fingerprinting

```python
from lib import ITXSecurityVerifier

# Initialize
v = ITXSecurityVerifier()

# Get fingerprint
fp = v.get_fingerprint()
print(f"Hardware Fingerprint: {fp}")

# Get detailed hardware info
hw = v.get_hardware_info()
print(f"Machine ID: {hw['machine_id']}")
print(f"CPU: {hw['cpu_model']} ({hw['cpu_cores']} cores)")
print(f"MAC: {hw['mac_address']}")
```

---

### Example 2: Environment Detection

```python
from lib import ITXSecurityVerifier

v = ITXSecurityVerifier()

# Check environment
print(f"Docker: {v.is_docker()}")
print(f"VM: {v.is_vm()}")
print(f"Debugger: {v.is_debugger_attached()}")

# Comprehensive check
result = v.verify()
env = result['environment']
if env['is_docker']:
    print("Running in Docker container")
if env['is_vm']:
    print("Running in Virtual Machine")
if env['debugger_detected']:
    print("WARNING: Debugger detected!")
```

---

### Example 3: Error Handling

```python
from lib import (
    ITXSecurityVerifier,
    LibraryError,
    HardwareDetectionError,
    FingerprintError,
)

try:
    v = ITXSecurityVerifier()
    fp = v.get_fingerprint()
    print(f"Success: {fp}")

except LibraryError as e:
    print(f"Library error: {e}")
    print("Solution: Recompile C library")

except HardwareDetectionError as e:
    print(f"Hardware error: {e}")
    if e.missing_fields:
        print(f"Missing: {', '.join(e.missing_fields)}")
    print("Solution: Run with sudo or check permissions")

except FingerprintError as e:
    print(f"Fingerprint error: {e}")
    print("Solution: Check hardware detection first")

except Exception as e:
    print(f"Unexpected error: {e}")
```

---

### Example 4: Debug Mode

```python
from lib import ITXSecurityVerifier

# Enable debug mode
v = ITXSecurityVerifier(debug=True)

# Will show detailed C library debug output
print("Getting fingerprint...")
fp = v.get_fingerprint()
print(f"Fingerprint: {fp}")

# Debug output will show:
# - File reads
# - Hardware detection steps
# - SHA-256 calculation
# - etc.
```

---

### Example 5: Custom Library Path

```python
from lib import ITXSecurityVerifier

# Use specific library version
v = ITXSecurityVerifier(
    library_path='/opt/itx/libintegrity.so'
)

print(f"Using library: {v._library_path}")
fp = v.get_fingerprint()
print(f"Fingerprint: {fp}")
```

---

### Example 6: License Verification

```python
from lib import ITXSecurityVerifier, FingerprintError

def verify_license(expected_fingerprint):
    """Verify hardware matches expected fingerprint"""
    try:
        v = ITXSecurityVerifier()
        current_fp = v.get_fingerprint()

        if current_fp == expected_fingerprint:
            return True, "License valid"
        else:
            return False, f"Hardware mismatch"

    except FingerprintError as e:
        return False, f"Verification error: {e}"

# Usage
is_valid, message = verify_license(
    "44739f4d4ecc13900b345178efd217c5b7c3bdffdb994a3626a1fee8cd4cfde1"
)

if is_valid:
    print("✓", message)
else:
    print("✗", message)
```

---

### Example 7: Performance Monitoring

```python
from lib import ITXSecurityVerifier
import time

v = ITXSecurityVerifier()

# Measure performance
iterations = 100
start = time.time()

for _ in range(iterations):
    fp = v.get_fingerprint()

elapsed = time.time() - start
avg = (elapsed / iterations) * 1000

print(f"Iterations: {iterations}")
print(f"Total time: {elapsed:.4f}s")
print(f"Average: {avg:.2f}ms per call")
```

---

## Best Practices

### 1. Always Use Error Handling

```python
# Good
try:
    v = ITXSecurityVerifier()
    fp = v.get_fingerprint()
except ITXSecurityError as e:
    logger.error(f"Security error: {e}")

# Bad
v = ITXSecurityVerifier()
fp = v.get_fingerprint()  # May crash
```

---

### 2. Cache Verifier Instance

```python
# Good - reuse instance
v = ITXSecurityVerifier()
fp1 = v.get_fingerprint()
fp2 = v.get_fingerprint()  # Fast, reuses library

# Less efficient - creates new instance each time
fp1 = ITXSecurityVerifier().get_fingerprint()
fp2 = ITXSecurityVerifier().get_fingerprint()
```

---

### 3. Check Environment Early

```python
# Good - check environment first
v = ITXSecurityVerifier()
if v.is_docker():
    # Handle Docker case differently
    pass

hw = v.get_hardware_info()
```

---

### 4. Use Debug Mode for Troubleshooting

```python
# Development/debugging
v = ITXSecurityVerifier(debug=True)

# Production
v = ITXSecurityVerifier(debug=False)
```

---

### 5. Handle Missing Hardware Info

```python
try:
    hw = v.get_hardware_info()
except HardwareDetectionError as e:
    if e.missing_fields:
        # Handle specific missing fields
        if 'dmi_uuid' in e.missing_fields:
            # DMI UUID not available - use alternative
            pass
```

---

## Version History

- **1.0.0** (2025-12-01): Initial release
  - Basic hardware fingerprinting
  - Docker/VM/Debugger detection
  - Comprehensive error handling
  - Debug mode support

---

## See Also

- [Testing Guide](TESTING_WRAPPER.md)
- [Main README](../README.md)
- [C Library Debug Guide](../native/docs/DEBUG_GUIDE.md)

---

**Last Updated:** 2025-12-01
**Version:** 1.0.0
**Author:** ITX Corporation
