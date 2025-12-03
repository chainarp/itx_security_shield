# การทดสอบ Python Wrapper - ITX Security Shield

คู่มือการทดสอบ Python wrapper อย่างละเอียดสำหรับการใช้งานและแก้ไขปัญหา

---

## 📋 สารบัญ

1. [ข้อกำหนดเบื้องต้น](#ข้อกำหนดเบื้องต้น)
2. [โครงสร้างไฟล์](#โครงสร้างไฟล์)
3. [วิธีการทดสอบ](#วิธีการทดสอบ)
4. [คำสั่งทดสอบทั้งหมด](#คำสั่งทดสอบทั้งหมด)
5. [ตัวอย่างการใช้งาน](#ตัวอย่างการใช้งาน)
6. [การแก้ไขปัญหา](#การแก้ไขปัญหา)
7. [ข้อมูลเพิ่มเติม](#ข้อมูลเพิ่มเติม)

---

## ข้อกำหนดเบื้องต้น

### ระบบที่รองรับ
- **OS**: Linux (Ubuntu 20.04+, Debian 10+)
- **Python**: 3.8+
- **C Library**: libintegrity.so (ต้อง compile แล้ว)

### ไม่ต้อง Virtual Environment
Python wrapper นี้ใช้แค่ **standard library** (ctypes) ไม่ต้อง activate venv หรือติดตั้ง package เพิ่มเติม

### ตรวจสอบก่อนเริ่มทดสอบ

```bash
# 1. ตรวจสอบว่า C library มีอยู่
ls -lh /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/libintegrity.so

# 2. ถ้าไม่มี ให้ compile
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native
./dev.sh prod

# 3. ตรวจสอบ Python version
python3 --version
# ควรเป็น Python 3.8 ขึ้นไป
```

---

## โครงสร้างไฟล์

```
itx_security_shield/
├── lib/                          # Python wrapper
│   ├── __init__.py               # Package init
│   ├── verifier.py               # Main wrapper class (ITXSecurityVerifier)
│   └── exceptions.py             # Custom exceptions (6 classes)
│
├── native/                       # C library
│   ├── libintegrity.so           # Compiled library
│   ├── src/                      # C source files
│   ├── include/                  # Header files
│   └── dev.sh                    # Build script
│
├── tests/                        # Test scripts
│   └── test_wrapper.py           # Original test suite
│
├── test_all_functions.py         # Comprehensive function test
└── docs/                         # Documentation
    └── TESTING_WRAPPER.md        # This file
```

---

## วิธีการทดสอบ

### วิธีที่ 1: ทดสอบครบทุก Function (แนะนำ!)

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 test_all_functions.py
```

**ทดสอบ 9 Functions:**
1. `__init__()` - Initialization (3 แบบ: default, debug, custom path)
2. `get_hardware_info()` - Hardware detection
3. `get_fingerprint()` - SHA-256 fingerprint generation
4. `is_docker()` - Docker detection
5. `is_vm()` - Virtual machine detection
6. `is_debugger_attached()` - Debugger detection
7. `verify()` - Comprehensive verification
8. Error handling - Exception tests
9. `__repr__()` - String representation

**ผลลัพธ์ที่คาดหวัง:**
```
Total: 9/9 functions passed
✓ All functions tested successfully!
```

---

### วิธีที่ 2: ทดสอบแบบละเอียด

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 tests/test_wrapper.py
```

**ทดสอบ 6 Test Cases:**
- Library loading
- Hardware information
- Fingerprint generation
- Environment checks
- Comprehensive verification
- Error handling

---

### วิธีที่ 3: ทดสอบพร้อม Debug Output

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield

# เปิด debug mode ของ C library
ITX_DEBUG=1 python3 test_all_functions.py
```

**ผลลัพธ์:**
- เห็น debug messages จาก C library
- แสดงทุก step ของการทำงาน
- เหมาะสำหรับ troubleshooting

---

### วิธีที่ 4: ทดสอบแบบ Interactive (Python REPL)

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3
```

```python
# Import wrapper
from lib import ITXSecurityVerifier

# สร้าง instance
v = ITXSecurityVerifier()

# ทดสอบทีละ function
print("Fingerprint:", v.get_fingerprint())
print("Docker:", v.is_docker())
print("VM:", v.is_vm())
print("Debugger:", v.is_debugger_attached())

# ดูข้อมูล hardware
hw = v.get_hardware_info()
print("Machine ID:", hw['machine_id'])
print("CPU:", hw['cpu_model'])
print("Cores:", hw['cpu_cores'])

# Comprehensive verification
result = v.verify()
print(result)

# ออกจาก Python
exit()
```

---

## คำสั่งทดสอบทั้งหมด

### Test 1: Quick Test (Fingerprint เท่านั้น)

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
from lib import ITXSecurityVerifier
v = ITXSecurityVerifier()
print("Fingerprint:", v.get_fingerprint())
EOF
```

---

### Test 2: Hardware Information

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
from lib import ITXSecurityVerifier
v = ITXSecurityVerifier()
hw = v.get_hardware_info()

print("=== Hardware Information ===")
for key, value in hw.items():
    print(f"{key:20s}: {value}")
EOF
```

---

### Test 3: Environment Detection

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
from lib import ITXSecurityVerifier
v = ITXSecurityVerifier()

print("=== Environment Detection ===")
print(f"Docker:   {v.is_docker()}")
print(f"VM:       {v.is_vm()}")
print(f"Debugger: {v.is_debugger_attached()}")
EOF
```

---

### Test 4: Comprehensive Verification

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
from lib import ITXSecurityVerifier
v = ITXSecurityVerifier()

result = v.verify()
print("=== Comprehensive Verification ===")
print("\nHardware:")
for k, v in result['hardware'].items():
    print(f"  {k}: {v}")
print(f"\nFingerprint: {result['fingerprint']}")
print("\nEnvironment:")
for k, v in result['environment'].items():
    print(f"  {k}: {v}")
EOF
```

---

### Test 5: Error Handling

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
from lib import ITXSecurityVerifier, LibraryError

# Test 1: Invalid library path
print("=== Error Handling Test ===\n")
try:
    v = ITXSecurityVerifier(library_path="/invalid/path.so")
except LibraryError as e:
    print(f"✓ LibraryError caught successfully")
    print(f"  Message: {str(e)[:100]}...")

# Test 2: Normal operation
print("\n✓ Normal operation test")
try:
    v = ITXSecurityVerifier()
    fp = v.get_fingerprint()
    print(f"  Fingerprint: {fp[:20]}...")
except Exception as e:
    print(f"✗ Error: {e}")
EOF
```

---

### Test 6: Debug Mode

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
# Enable debug mode
from lib import ITXSecurityVerifier

print("=== Debug Mode Test ===\n")
v = ITXSecurityVerifier(debug=True)
print(f"Debug enabled: {v.debug}")
print(f"Library path: {v._library_path}")

# Get fingerprint (will show C library debug output)
fp = v.get_fingerprint()
print(f"\nFingerprint: {fp}")
EOF
```

**หมายเหตุ:** Debug mode จะแสดง output เฉพาะเมื่อ C library ถูก compile ด้วย `-DITX_DEBUG_ENABLED`

---

### Test 7: Performance Test

```bash
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield
python3 << 'EOF'
import time
from lib import ITXSecurityVerifier

v = ITXSecurityVerifier()

print("=== Performance Test ===\n")

# Test fingerprint generation speed
start = time.time()
for i in range(100):
    fp = v.get_fingerprint()
end = time.time()

print(f"100 fingerprint generations: {end - start:.4f} seconds")
print(f"Average per call: {(end - start) / 100 * 1000:.2f} ms")
EOF
```

---

## ตัวอย่างการใช้งาน

### ตัวอย่างที่ 1: Basic Usage

```python
from lib import ITXSecurityVerifier

# Initialize
verifier = ITXSecurityVerifier()

# Get fingerprint
fingerprint = verifier.get_fingerprint()
print(f"Hardware fingerprint: {fingerprint}")

# Check environment
if verifier.is_docker():
    print("Running in Docker container")
if verifier.is_vm():
    print("Running in virtual machine")
```

---

### ตัวอย่างที่ 2: With Error Handling

```python
from lib import (
    ITXSecurityVerifier,
    LibraryError,
    HardwareDetectionError,
    FingerprintError,
    PermissionError,
)

try:
    # Initialize verifier
    verifier = ITXSecurityVerifier()

    # Get hardware information
    hw_info = verifier.get_hardware_info()
    print(f"Machine ID: {hw_info['machine_id']}")

    # Generate fingerprint
    fingerprint = verifier.get_fingerprint()
    print(f"Fingerprint: {fingerprint}")

except LibraryError as e:
    print(f"Library error: {e}")
    # Handle library loading issues
    # - Recompile C library
    # - Check library path

except HardwareDetectionError as e:
    print(f"Hardware detection error: {e}")
    if e.missing_fields:
        print(f"Missing fields: {', '.join(e.missing_fields)}")
    # Handle missing hardware info
    # - Check permissions (may need sudo)
    # - Check if running in container

except FingerprintError as e:
    print(f"Fingerprint error: {e}")
    # Handle fingerprint generation issues

except PermissionError as e:
    print(f"Permission error: {e}")
    # Handle insufficient permissions
    # - Run with sudo
    # - Check file permissions
```

---

### ตัวอย่างที่ 3: License Verification (Concept)

```python
from lib import ITXSecurityVerifier
import json

def verify_license(license_file_path):
    """Verify hardware-bound license file"""

    # Get current hardware fingerprint
    verifier = ITXSecurityVerifier()
    current_fingerprint = verifier.get_fingerprint()

    # Load license file
    with open(license_file_path, 'r') as f:
        license_data = json.load(f)

    # Compare fingerprints
    if license_data['fingerprint'] == current_fingerprint:
        print("✓ License valid for this hardware")
        return True
    else:
        print("✗ License invalid: hardware mismatch")
        print(f"  Expected: {license_data['fingerprint']}")
        print(f"  Current:  {current_fingerprint}")
        return False

# Usage
if verify_license('/path/to/license.json'):
    print("Starting application...")
else:
    print("License verification failed!")
    exit(1)
```

---

### ตัวอย่างที่ 4: Generate License File

```python
from lib import ITXSecurityVerifier
import json
from datetime import datetime, timedelta

def generate_license(output_path, valid_days=365):
    """Generate hardware-bound license file"""

    verifier = ITXSecurityVerifier()

    # Collect hardware information
    hw_info = verifier.get_hardware_info()
    fingerprint = verifier.get_fingerprint()

    # Create license data
    license_data = {
        'fingerprint': fingerprint,
        'machine_id': hw_info['machine_id'],
        'issued_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=valid_days)).isoformat(),
        'hardware': {
            'cpu_model': hw_info['cpu_model'],
            'cpu_cores': hw_info['cpu_cores'],
            'is_vm': hw_info['is_vm'],
            'is_docker': hw_info['is_docker'],
        }
    }

    # Save license file
    with open(output_path, 'w') as f:
        json.dump(license_data, f, indent=2)

    print(f"✓ License generated: {output_path}")
    print(f"  Valid for: {valid_days} days")
    print(f"  Fingerprint: {fingerprint}")

    return license_data

# Usage
license = generate_license('/tmp/license.json', valid_days=365)
```

---

### ตัวอย่างที่ 5: Odoo Integration

```python
# In Odoo addon
from odoo import models, api
from odoo.exceptions import ValidationError

class LicenseManager(models.Model):
    _name = 'license.manager'

    @api.model
    def verify_hardware_license(self):
        """Verify hardware-bound license on Odoo startup"""
        try:
            from odoo.addons.itx_security_shield.lib import ITXSecurityVerifier

            verifier = ITXSecurityVerifier()
            current_fp = verifier.get_fingerprint()

            # Get stored license fingerprint from database
            license_rec = self.env['license.key'].search([('active', '=', True)], limit=1)

            if not license_rec:
                raise ValidationError("No active license found!")

            if license_rec.fingerprint != current_fp:
                raise ValidationError(
                    f"Hardware mismatch!\n"
                    f"License fingerprint: {license_rec.fingerprint}\n"
                    f"Current fingerprint: {current_fp}"
                )

            return True

        except Exception as e:
            raise ValidationError(f"License verification failed: {e}")
```

---

## การแก้ไขปัญหา

### ปัญหา 1: Library Not Found

**อาการ:**
```
LibraryError: Could not find libintegrity.so
```

**วิธีแก้:**
```bash
# 1. ตรวจสอบว่า library มีอยู่
ls -la /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/libintegrity.so

# 2. ถ้าไม่มี ให้ compile
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native
./dev.sh prod

# 3. ตรวจสอบอีกครั้ง
ls -la libintegrity.so
```

---

### ปัญหา 2: Permission Denied

**อาการ:**
```
HardwareDetectionError: Some hardware information is unavailable
Missing fields: ['dmi_uuid', 'disk_uuid']
```

**วิธีแก้:**
```bash
# บางข้อมูล hardware ต้องการ root permission
sudo python3 test_all_functions.py

# หรือเพิ่ม permissions ให้ user
sudo chmod +r /sys/class/dmi/id/product_uuid
```

---

### ปัญหา 3: Missing Dependencies

**อาการ:**
```
OSError: libssl.so.3: cannot open shared object file
```

**วิธีแก้:**
```bash
# ติดตั้ง OpenSSL libraries
sudo apt-get update
sudo apt-get install libssl-dev

# ตรวจสอบ dependencies
ldd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/libintegrity.so
```

---

### ปัญหา 4: Python Import Error

**อาการ:**
```
ModuleNotFoundError: No module named 'lib'
```

**วิธีแก้:**
```bash
# ต้อง cd ไปที่ addon directory ก่อน
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield

# หรือเพิ่ม path
python3 -c "import sys; sys.path.insert(0, '/home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield'); from lib import ITXSecurityVerifier; print(ITXSecurityVerifier())"
```

---

### ปัญหา 5: C Library Version Mismatch

**อาการ:**
```
LibraryError: Invalid library: missing required functions
```

**วิธีแก้:**
```bash
# Recompile C library
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native

# Clean และ rebuild
rm -f libintegrity.so *.o
./dev.sh prod

# ตรวจสอบ symbols ใน library
nm -D libintegrity.so | grep itx_
```

---

### ปัญหา 6: Debug Output Not Showing

**อาการ:**
Debug mode enabled แต่ไม่เห็น debug messages

**วิธีแก้:**
```bash
# C library ต้อง compile ด้วย debug flag
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native

# Rebuild with debug
./dev.sh debug

# ทดสอบ
cd ..
ITX_DEBUG=1 python3 test_all_functions.py
```

---

## ข้อมูลเพิ่มเติม

### ค่าที่คาดหวังจากการทดสอบ

**Fingerprint:**
- Format: 64-character hexadecimal string
- Example: `44739f4d4ecc13900b345178efd217c5b7c3bdffdb994a3626a1fee8cd4cfde1`
- Algorithm: SHA-256

**Hardware Info Fields:**
- `machine_id`: Linux machine ID (from /etc/machine-id)
- `cpu_model`: CPU model name
- `cpu_cores`: Number of CPU cores
- `mac_address`: MAC address (first non-loopback)
- `dmi_uuid`: DMI/SMBIOS UUID
- `disk_uuid`: Root filesystem UUID
- `is_docker`: Boolean
- `is_vm`: Boolean
- `debugger_detected`: Boolean

---

### Exception Hierarchy

```
ITXSecurityError (base)
├── LibraryError              # C library loading/initialization
├── HardwareDetectionError    # Hardware info retrieval
├── FingerprintError          # Fingerprint generation
├── PermissionError           # Insufficient permissions
└── PlatformError             # Unsupported platform
```

---

### Performance Benchmarks

บน VMware VM (Intel i7-9700, 8 cores):
- **Library loading:** ~2-5 ms
- **Hardware info collection:** ~10-20 ms
- **Fingerprint generation:** ~15-25 ms
- **Environment checks:** ~5-10 ms each

---

### Debug Logging Levels

เมื่อ compile ด้วย `-DITX_DEBUG_ENABLED`:

```bash
# ไม่มี debug output
python3 test_all_functions.py

# มี debug output
ITX_DEBUG=1 python3 test_all_functions.py
```

Debug messages จาก C library:
- `[ITX DEBUG]` - Information
- `[ITX WARN]` - Warnings
- `[ITX ERROR]` - Errors

---

### เอกสารเพิ่มเติม

- **C Library**: `native/docs/DEBUG_GUIDE.md`
- **Build Script**: `native/dev.sh --help`
- **Odoo Integration**: `../README.md`
- **API Reference**: `lib/verifier.py` (docstrings)

---

### สรุป Quick Reference

```bash
# Location
cd /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield

# Quick test
python3 test_all_functions.py

# With debug
ITX_DEBUG=1 python3 test_all_functions.py

# Interactive
python3 -c "from lib import ITXSecurityVerifier; v=ITXSecurityVerifier(); print(v.get_fingerprint())"

# Rebuild C library
cd native && ./dev.sh prod && cd ..
```

---

**สร้างเมื่อ:** 2025-12-01
**เวอร์ชัน:** 1.0.0
**ผู้เขียน:** ITX Corporation (with Claude Code assistance)
