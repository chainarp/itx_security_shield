# Odoo Addon License Protection - Complete Pipeline

## PyArmor Pricing

### Free Version
- ✅ ใช้ได้ฟรี
- ✅ Obfuscate ได้ไม่จำกัด
- ❌ แสดง banner "Protected by PyArmor"
- ❌ ไม่มี advanced features (JIT, restrict mode)

### Pro Version (~$50-200/year)
- ✅ ไม่มี banner
- ✅ Advanced obfuscation
- ✅ Commercial use

**คำตอบ: Free พอครับ** สำหรับ Odoo addon ของคุณ

---

## 📋 Complete Pipeline - License Protection System

### Phase 0: Preparation & Setup
```
0.1 → ออกแบบ addon structure
    └─ license_guardian/ (base addon)
    └─ your_addon_1..10/ (business addons)

0.2 → สร้าง C library สำหรับ hardware fingerprint
    └─ license_check.c
    └─ compile → license_check.so
    └─ ซ่อน symbols, strip debug info

0.3 → สร้าง Python wrapper
    └─ verifier.py (interface ระหว่าง Odoo ↔ .so)
    └─ obfuscate ด้วย PyArmor Free

0.4 → เตรียม promotion tools
    └─ promote_to_prod.py
    └─ verify_env.py
    └─ emergency_unlock.py

0.5 → Setup license_guardian addon
    └─ models/ (license validation logic)
    └─ controllers/ (API endpoints)
    └─ data/ (cron jobs, mail channels)
    └─ lib/ (license_check.so + verifier.py)
    └─ tools/ (promotion scripts)
```

---

### Phase 1: Development Environment (ไม่ protect)
```
1.1 → Developer เขียน addon ปกติ
    └─ your_addon_1/__manifest__.py
        ├─ depends: ['base', 'license_guardian']
        └─ installable: True

1.2 → ตั้งค่า license_guardian ใน dev mode
    └─ ENV: LICENSE_MODE=development
    └─ verify_license() → always return True
    └─ แสดง warning banner "Development Mode"

1.3 → Development workflow
    └─ เขียน code
    └─ test
    └─ debug
    └─ ไม่มีการเช็ค license

1.4 → Version control
    └─ Git commit (exclude production.lic)
    └─ .gitignore:
        ├─ production.lic
        ├─ *.pyc
        └─ __pycache__/
```

---

### Phase 2: Testing Environment (Light Protection)
```
2.1 → Deploy to test server
    └─ Clone from git
    └─ ติดตั้ง dependencies
    └─ ENV: LICENSE_MODE=testing

2.2 → Generate test license
    └─ cd license_guardian/tools/
    └─ ./promote_to_prod.py \
        --mode testing \
        --password "TestPass123" \
        --expiry "2025-12-31" \
        --output /opt/odoo/test.lic

2.3 → Test license สร้างอะไร?
    ├─ Hardware fingerprint (test server)
    ├─ Basic file hashes (ไม่เข้มงวด)
    ├─ Expiry date
    └─ Allow modifications (สำหรับ testing)

2.4 → Testing workflow
    └─ Odoo startup → อ่าน test.lic
    └─ Warning ถ้า hash ไม่ตรง (แต่ไม่ block)
    └─ Test functionality
    └─ Fix bugs → hash เปลี่ยน → regenerate test.lic
```

---

### Phase 3: Pre-Production Preparation
```
3.1 → Code freeze
    └─ Stop accepting changes
    └─ Final review
    └─ Final testing

3.2 → PyArmor obfuscation
    └─ cd license_guardian/
    └─ pyarmor gen --restrict lib/verifier.py
    └─ cd your_addon_1/
    └─ pyarmor gen --restrict __init__.py
    └─ ... ทำทุก addon

3.3 → Pre-build checks
    └─ Verify all addons มี license_guardian ใน depends
    └─ Verify __init__.py มี _verify_license()
    └─ Verify ไม่มี hardcoded passwords
    └─ Verify .gitignore ครบ

3.4 → Create deployment package
    └─ tar czf odoo_bundle.tar.gz \
        license_guardian/ \
        your_addon_*/ \
        tools/

3.5 → Documentation
    └─ Installation guide
    └─ Promotion guide (สำหรับลูกค้า admin)
    └─ Troubleshooting guide
```

---

### Phase 4: Production Deployment (Customer Site)
```
4.1 → Customer: Extract package
    └─ tar xzf odoo_bundle.tar.gz -C /opt/odoo/addons/

4.2 → Customer: Install dependencies
    └─ apt-get install libssl-dev
    └─ pip3 install -r requirements.txt

4.3 → Customer: Basic Odoo setup
    └─ Install license_guardian addon (ก่อน!)
    └─ ENV: LICENSE_MODE=production
    └─ ยังทำงานไม่ได้ (ไม่มี license)

4.4 → Customer: Install business addons
    └─ Install your_addon_1
    └─ Install your_addon_2..10
    └─ Odoo แสดง error: "No valid license"

4.5 → Customer: Request promotion
    └─ ติดต่อคุณเพื่อขอ MASTER_PASSWORD
    └─ หรือคุณ remote เข้าไป promote ให้
```

---

### Phase 5: Production Promotion (Critical!)
```
5.1 → คุณ (หรือ customer admin): เข้า production server
    └─ ssh user@customer-server
    └─ cd /opt/odoo/addons/license_guardian/tools/

5.2 → Run promotion script
    └─ ./promote_to_prod.py \
        --password "VeryLongMasterPassword!@#$%^&*()" \
        --expiry "2026-12-31" \
        --max-users 50 \
        --addons "/opt/odoo/addons/your_addon_*" \
        --scan-depth recursive \
        --strict-mode \
        --docker-aware \
        --output /opt/odoo/production.lic

5.3 → Promotion script ทำอะไร? (ละเอียด)
    
    5.3.1 → Environment detection
        ├─ ตรวจจับ Docker/VM/Bare metal
        ├─ อ่าน /etc/machine-id
        ├─ อ่าน /sys/class/dmi/id/product_uuid
        ├─ อ่าน MAC addresses (ทุก interface)
        ├─ อ่าน CPU info
        └─ สร้าง hardware_fingerprint (SHA-256)
    
    5.3.2 → Docker handling
        ├─ IF Docker detected:
        │   ├─ Mount /etc/machine-id from host? (check)
        │   ├─ Mount /sys/class/dmi/id? (check)
        │   ├─ Read container ID
        │   ├─ Create installation_id (UUID)
        │   └─ Store in persistent volume
        └─ ELSE: use host hardware directly
    
    5.3.3 → File scanning
        ├─ Scan license_guardian/:
        │   ├─ Hash __manifest__.py
        │   ├─ Hash __init__.py
        │   ├─ Hash lib/verifier.py (obfuscated)
        │   ├─ Hash lib/license_check.so
        │   ├─ Hash models/*.py
        │   └─ Hash controllers/*.py
        │
        └─ Scan each your_addon_*/:
            ├─ Hash __manifest__.py
            │   └─ Verify 'license_guardian' in depends
            ├─ Hash __init__.py
            │   └─ Verify _verify_license() exists
            ├─ Hash models/*.py (ทุกไฟล์)
            ├─ Hash views/*.xml (ทุกไฟล์)
            ├─ Hash security/*.csv
            ├─ Hash static/src/**/*.js
            ├─ Hash data/*.xml
            │
            └─ Exclude (ไม่ hash):
                ├─ __pycache__/
                ├─ *.pyc
                ├─ *.log
                ├─ i18n/*.po (translations - อนุญาตให้แก้)
                └─ README.md, LICENSE
    
    5.3.4 → License data structure creation
        license_data = {
            'version': '1.0',
            'created_at': '2025-11-09T10:30:00Z',
            'created_by': 'admin@customer.com',
            'license_key': 'SUITE-XXXX-XXXX-XXXX',
            'license_type': 'bundle',
            
            'hardware': {
                'fingerprint': 'abc123...',
                'machine_id': 'def456...',
                'dmi_uuid': 'ghi789...',
                'mac_addresses': ['00:11:22:33:44:55', ...],
                'cpu_model': 'Intel Xeon E5-2697 v2',
                'is_docker': True/False,
                'docker_info': {
                    'container_id': '...',
                    'installation_id': '...'
                }
            },
            
            'validity': {
                'expires_at': '2026-12-31T23:59:59Z',
                'max_users': 50,
                'grace_period_days': 30
            },
            
            'addons': {
                'license_guardian': {
                    'version': '1.0.0',
                    'files': {
                        '__manifest__.py': 'hash...',
                        '__init__.py': 'hash...',
                        'lib/license_check.so': 'hash...',
                        'lib/verifier.py': 'hash...',
                        'models/license_check.py': 'hash...',
                        ...
                    }
                },
                'your_addon_1': {
                    'version': '1.0.0',
                    'files': { ... }
                },
                ...
            },
            
            'permissions': {
                'allow_translation_edits': True,
                'allow_config_changes': True,
                'modifiable_files': [
                    'your_addon_*/i18n/*.po',
                    'your_addon_*/data/config.xml'
                ]
            },
            
            'security': {
                'signature_algorithm': 'RSA-2048',
                'hash_algorithm': 'SHA-256',
                'encryption': 'AES-256-GCM'
            }
        }
    
    5.3.5 → Encryption
        ├─ Generate AES-256 key from MASTER_PASSWORD (PBKDF2)
        ├─ Encrypt license_data with AES-256-GCM
        ├─ Add authentication tag (tamper detection)
        └─ Optional: RSA signature (ถ้ามี private key)
    
    5.3.6 → Write production.lic
        ├─ Binary format:
        │   ├─ Header (64 bytes):
        │   │   ├─ Magic: "ODLI" (4 bytes)
        │   │   ├─ Version: 1 (4 bytes)
        │   │   ├─ Timestamp (8 bytes)
        │   │   └─ Reserved (48 bytes)
        │   │
        │   ├─ Encrypted data (variable)
        │   └─ Footer (32 bytes):
        │       ├─ Checksum (16 bytes)
        │       └─ Signature (16 bytes)
        │
        └─ Write to /opt/odoo/production.lic
        └─ Set permissions: 400 (read-only, owner only)

5.4 → Promotion verification
    └─ ./verify_env.py --license /opt/odoo/production.lic
    └─ แสดงสรุป:
        ├─ ✓ Hardware fingerprint: OK
        ├─ ✓ Scanned 10 addons, 1,234 files
        ├─ ✓ License valid until: 2026-12-31
        └─ ⚠ Grace period: 30 days after expiry

5.5 → Restart Odoo
    └─ systemctl restart odoo
    └─ Odoo reads production.lic
    └─ ✅ All addons working!

5.6 → MASTER_PASSWORD handling
    ├─ ลูกค้าเก็บไว้ในที่ปลอดภัย (password manager)
    ├─ ใช้สำหรับ re-promotion เท่านั้น
    └─ ⚠️ ถ้าหาย → ต้องติดต่อคุณเพื่อสร้าง license ใหม่
```

---

### Phase 6: Runtime Protection (Ongoing)
```
6.1 → Odoo startup sequence
    
    6.1.1 → Pre-init (ก่อน load modules)
        ├─ license_guardian/__init__.py
        │   └─ pre_init_hook(cr) executed
        │       ├─ Load production.lic
        │       ├─ Decrypt with compiled .so library
        │       ├─ Verify hardware fingerprint
        │       ├─ Check expiry date
        │       └─ IF invalid:
        │           ├─ Calculate days_expired
        │           ├─ IF days_expired < grace_period:
        │           │   └─ Log WARNING, continue
        │           └─ ELSE:
        │               └─ RAISE Exception → Block startup
        │
        └─ each addon's __init__.py
            └─ _verify_license() called
                ├─ Import license_guardian.lib.verifier
                ├─ Call verify_license()
                └─ IF not valid → RAISE Exception

    6.1.2 → Module loading
        ├─ Odoo loads license_guardian first (dependency)
        ├─ Then loads business addons
        └─ Each addon's __init__ validates license

    6.1.3 → Post-init
        └─ license_guardian registers cron jobs

6.2 → Periodic checks (Cron job every 6 hours)
    
    6.2.1 → Scheduled action runs
        └─ license.check._cron_verify_license()
            ├─ Load production.lic
            ├─ Verify hardware
            ├─ Verify file hashes (sample 10% random files)
            ├─ Check expiry
            │
            └─ IF issues detected:
                ├─ Calculate severity
                ├─ Log to odoo.log
                ├─ Send email to admin
                ├─ Post to #license-alerts channel
                │
                └─ IF critical (expired > grace_period):
                    ├─ Set system parameter: license_blocked=True
                    └─ Next request will see block page

6.3 → Request-time checks (Optional, per-request)
    
    6.3.1 → Middleware check
        ├─ Check system parameter: license_blocked?
        ├─ IF blocked:
        │   └─ Return 403 page:
        │       "License expired. Contact vendor."
        └─ ELSE: continue

6.4 → File modification detection
    
    6.4.1 → Cron job samples files
        ├─ Random sample 10% of files every 6 hours
        ├─ Calculate current hash
        ├─ Compare with production.lic
        │
        └─ IF mismatch:
            ├─ Check if in modifiable_files list
            ├─ IF not allowed:
            │   ├─ Log CRITICAL
            │   ├─ Alert admin immediately
            │   └─ Start grace period countdown
            └─ ELSE: allow (e.g., translation edits)

6.5 → API endpoint monitoring
    
    6.5.1 → GET /license/status (for monitoring tools)
        └─ Returns JSON:
            {
                'valid': true,
                'expires_at': '2026-12-31',
                'days_remaining': 365,
                'grace_period_active': false,
                'last_check': '2025-11-09T12:00:00Z',
                'warnings': []
            }

6.6 → Logging
    └─ All license events logged to:
        ├─ /var/log/odoo/license.log
        └─ Odoo database (license.log model)
```

---

### Phase 7: Maintenance & Updates

```
7.1 → Minor update (bug fix, no code change)
    └─ ไม่ต้องทำอะไร (hash ไม่เปลี่ยน)

7.2 → Code update (bug fix with code change)
    
    7.2.1 → Developer แก้ code
    7.2.2 → Test in dev environment
    7.2.3 → Deploy to customer
        └─ Replace changed files
    
    7.2.4 → RE-PROMOTE (สำคัญ!)
        └─ ssh customer-server
        └─ cd /opt/odoo/addons/license_guardian/tools/
        └─ ./promote_to_prod.py \
            --password "MASTER_PASSWORD" \
            --expiry "2026-12-31" \  # same as before
            --output /opt/odoo/production.lic
        
        └─ Script detects:
            ├─ File hashes changed
            ├─ Regenerate production.lic
            ├─ Keep same hardware fingerprint
            ├─ Keep same expiry
            └─ Update file hashes only
    
    7.2.5 → Restart Odoo
        └─ systemctl restart odoo

7.3 → Major version upgrade
    
    7.3.1 → Full re-promotion needed
    7.3.2 → May need new license key
    7.3.3 → May update license terms

7.4 → Server migration (new hardware)
    
    7.4.1 → Customer: Install on new server
    7.4.2 → Customer: Copy addons
    7.4.3 → Customer: Try to use old production.lic
        └─ ❌ FAIL: Hardware fingerprint mismatch
    
    7.4.4 → Customer: Contact คุณ
    7.4.5 → คุณ: Verify it's legitimate migration
    7.4.6 → คุณ: Remote in and RE-PROMOTE
        └─ New hardware fingerprint
        └─ Same license key
        └─ Reset grace period

7.5 → Docker container rebuild
    
    7.5.1 → IF using host machine-id (mounted):
        └─ ✅ OK, production.lic still valid
    
    7.5.2 → IF using installation_id:
        └─ Check persistent volume exists
        └─ ✅ OK if volume preserved
        └─ ❌ FAIL if volume deleted → need re-promote

7.6 → License renewal
    
    7.6.1 → Customer: License approaching expiry
        └─ Cron sends warning emails (30 days before)
    
    7.6.2 → Customer: Purchase renewal
    7.6.3 → คุณ: Remote in and RE-PROMOTE
        └─ --expiry "2027-12-31"  # extend date
        └─ Same everything else
    
    7.6.4 → Restart Odoo
```

---

### Phase 8: Security Incidents

```
8.1 → Scenario: Unauthorized copy detected
    
    8.1.1 → คุณได้รับ alert: 2 servers same license
    8.1.2 → Investigate:
        ├─ Check license.log on both servers
        ├─ Compare hardware fingerprints
        └─ Identify legitimate vs. unauthorized
    
    8.1.3 → Action:
        ├─ Revoke license (if have license server)
        ├─ OR: Contact customer to resolve
        └─ Generate new license for legitimate server

8.2 → Scenario: Code tampering detected
    
    8.2.1 → Cron detects file hash mismatch
    8.2.2 → Send immediate alert
    8.2.3 → Grace period starts (30 days)
    8.2.4 → Customer must:
        ├─ Restore original files
        ├─ OR: Contact คุณ for re-promotion
        └─ OR: System blocks after 30 days

8.3 → Scenario: License file deleted
    
    8.3.1 → Odoo startup fails
    8.3.2 → Error: "License file not found"
    8.3.3 → Customer must contact คุณ
    8.3.4 → คุณ: Remote in and re-promote

8.4 → Scenario: MASTER_PASSWORD leaked
    
    8.4.1 → คุณ: Generate new encryption key
    8.4.2 → คุณ: Re-promote all customer sites
    8.4.3 → Update promote_to_prod.py with new key
    8.4.4 → Distribute new MASTER_PASSWORD

8.5 → Scenario: .so library reverse engineered
    
    8.5.1 → Prepare updated license_check.so
        ├─ Change anti-debugging techniques
        ├─ Obfuscate more
        ├─ Add new checks
    
    8.5.2 → Release as hotfix update
    8.5.3 → Force customer updates
```

---

### Phase 9: Monitoring & Analytics (Optional)

```
9.1 → License usage tracking
    └─ IF have license server:
        ├─ Daily heartbeat from customer sites
        ├─ Track: users, modules, DB size
        └─ Analytics dashboard

9.2 → Compliance monitoring
    └─ Monthly report:
        ├─ Active licenses
        ├─ Expired licenses
        ├─ Violations detected
        └─ Pending renewals

9.3 → Customer self-service portal
    └─ Customer can:
        ├─ View license status
        ├─ Request renewal
        ├─ Download invoices
        └─ Open support tickets
```

---

### Phase 10: Emergency Procedures

```
10.1 → Emergency unlock (disaster recovery)
    
    10.1.1 → Customer: Critical production down
    10.1.2 → Customer: Can't reach you
    10.1.3 → Customer: Has emergency_unlock.py
    
    10.1.4 → Customer runs:
        └─ ./emergency_unlock.py \
            --emergency-key "EMERGENCY_KEY_IN_CONTRACT" \
            --reason "Disk failure, vendor unreachable" \
            --duration 72  # hours
    
    10.1.5 → Script:
        ├─ Validates emergency key
        ├─ Creates temporary license (72 hours)
        ├─ Logs incident to file
        ├─ Sends alert (if network available)
        └─ Allows Odoo to start
    
    10.1.6 → After 72 hours:
        └─ System blocks again
        └─ Must contact you for proper license

10.2 → Rollback procedure
    └─ IF re-promotion goes wrong:
        ├─ Backup old production.lic (automatic)
        ├─ Restore: cp production.lic.bak production.lic
        └─ Restart Odoo

10.3 → Support escalation
    └─ Level 1: Email support (48h response)
    └─ Level 2: Phone support (4h response)
    └─ Level 3: Emergency (30min response)
```

---

## 🎯 Summary: Critical Checkpoints

```
☑ Phase 0: Architecture ready
☑ Phase 1-2: Dev & test working
☑ Phase 3: Code frozen & obfuscated
☑ Phase 4: Deployed to customer
☑ Phase 5: PROMOTED (production.lic created) ← CRITICAL
☑ Phase 6: Runtime protection active
☑ Phase 7: Maintenance procedures documented
☑ Phase 8: Security response plan ready
☑ Phase 9: Monitoring operational
☑ Phase 10: Emergency procedures tested
```

---

## คำถามต่อไป

1. Phase ไหนที่คุณต้องการ drill down ลงไปลึกกว่านี้?
2. มีส่วนไหนที่ยังไม่ชัดเจนไหม?
3. พร้อมเริ่ม implement ที่ Phase ไหนก่อนครับ?

