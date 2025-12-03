# 📚 คู่มือการใช้งาน License Generator

**ITX Security Shield - License Generator**
สร้างไฟล์ license สำหรับลูกค้าด้วย Odoo UI

---

## 📖 สารบัญ

1. [ภาพรวม](#ภาพรวม)
2. [การเตรียมความพร้อม](#การเตรียมความพร้อม)
3. [วิธีการสร้าง License](#วิธีการสร้าง-license)
4. [การจัดการ License ที่สร้างแล้ว](#การจัดการ-license-ที่สร้างแล้ว)
5. [คำถามที่พบบ่อย (FAQ)](#คำถามที่พบบ่อย-faq)
6. [การแก้ปัญหา](#การแก้ปัญหา)

---

## ภาพรวม

### License Generator คืออะไร?

License Generator เป็นเครื่องมือสำหรับ **ITX Staff** ในการสร้างไฟล์ license ให้กับลูกค้า โดยมีคุณสมบัติดังนี้:

✅ **สร้าง License ผ่าน Odoo UI** - ไม่ต้องใช้คำสั่ง command line
✅ **Hybrid Encryption** - ใช้ RSA-4096 + AES-256-GCM เข้ารหัสอัตโนมัติ
✅ **Hardware Binding** - ผูกกับฮาร์ดแวร์ของเครื่องลูกค้าอัตโนมัติ
✅ **บันทึกในฐานข้อมูล** - เก็บไฟล์ license ทุกไฟล์ไว้ใน Odoo
✅ **ดาวน์โหลดได้ทันที** - ส่งให้ลูกค้าได้เลย

### กระบวนการทำงาน

```
1. ITX Staff กรอกข้อมูลลูกค้า
   ├── ชื่อบริษัท, PO, Contract
   ├── Addon ที่ซื้อ, จำนวน Instance
   ├── วันหมดอายุ
   └── Upload Private Key (สิทธิ์ในการสร้าง license)
        ↓
2. กด "Generate License"
   ├── ระบบอ่านข้อมูลฮาร์ดแวร์เครื่องปัจจุบัน (6 ค่า)
   ├── สร้าง Hardware Fingerprint (SHA-256)
   ├── Encrypt ด้วย RSA + AES
   └── บันทึกไฟล์ลงฐานข้อมูล
        ↓
3. ดาวน์โหลดไฟล์ .lic ส่งให้ลูกค้า
   └── ลูกค้านำไปวางไว้ที่ /etc/odoo/production.lic
```

---

## การเตรียมความพร้อม

### สิ่งที่ต้องมี

#### 1. **RSA Private Key** (สำคัญมาก!)

ไฟล์ `private_dev.pem` เป็นกุญแจสำคัญในการสร้าง license:

- 🔐 **เฉพาะ ITX Staff เท่านั้น** ที่มีไฟล์นี้
- 🔐 **ห้ามแชร์** ไฟล์นี้กับใครก็ตาม (รวมถึงลูกค้า)
- 🔐 **ใครมีไฟล์นี้** = ใครสร้าง license ได้

**ที่เก็บ:**
```
/home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/keys/private_dev.pem
```

**ถ้าหาไม่เจอ:**
```bash
# ดูว่ามีไฟล์ไหม
ls -la /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/keys/

# ควรเห็น:
# private_dev.pem  (ห้ามให้คนอื่น!)
# public_dev.pem   (ใช้ตอน validate)
```

#### 2. **ข้อมูลลูกค้า**

เตรียมข้อมูลต่อไปนี้ก่อนสร้าง license:

- ✅ ชื่อบริษัทลูกค้า (เช่น "บริษัท ABC จำกัด")
- ✅ เลขที่ PO หรือ Contract (ถ้ามี)
- ✅ Addon ที่ลูกค้าซื้อ (เช่น `itx_helloworld, itx_sales`)
- ✅ จำนวน Instance ที่อนุญาต (เช่น 1 = ติดตั้งได้ 1 เครื่อง)
- ✅ วันหมดอายุ (เช่น 2025-12-31)

#### 3. **สิทธิ์การเข้าถึง Odoo**

- 👤 ต้องเป็น **Settings > Administration** (System Admin)
- 👤 User ทั่วไปมองไม่เห็นเมนู "Generate License"

---

## วิธีการสร้าง License

### ขั้นตอนที่ 1: เปิด License Generator

1. เข้า Odoo
2. ไปที่เมนู: **ITX Security Shield > Generate License**
3. จะเห็นหน้าฟอร์มสำหรับกรอกข้อมูล

### ขั้นตอนที่ 2: กรอกข้อมูลลูกค้า

#### 📋 **Customer Information**

| ฟิลด์ | ตัวอย่าง | จำเป็น? |
|------|---------|---------|
| Customer Name | `บริษัท ABC จำกัด` | ✅ ต้องกรอก |
| PO Number | `PO-2024-12-001` | ไม่จำเป็น |
| Contract Number | `CTR-2024-12-001` | ไม่จำเป็น |
| Contact Email | `admin@abc.com` | ไม่จำเป็น |
| Contact Phone | `02-123-4567` | ไม่จำเป็น |

#### 📦 **License Rights**

| ฟิลด์ | ตัวอย่าง | คำอธิบาย |
|------|---------|----------|
| Licensed Addons | `itx_helloworld, itx_sales` | คั่นด้วย comma (,) |
| Max Instances | `1` | ติดตั้งได้กี่เครื่อง |
| Concurrent Users | `0` | 0 = ไม่จำกัด |

#### 📅 **Validity Period**

| ฟิลด์ | ตัวอย่าง | คำอธิบาย |
|------|---------|----------|
| Issue Date | `2024-12-03` | วันที่ออก license (วันนี้) |
| Expiry Date | `2025-12-31` | วันที่หมดอายุ |
| Grace Period (Days) | `30` | หลังหมดอายุ ยังใช้ได้อีกกี่วัน |
| Maintenance Until | `2026-06-30` | วันที่สิ้นสุดการ support (ถ้ามี) |

#### 🔗 **Hardware Binding**

- ✅ **Bind to Current Hardware**: เปิดไว้เสมอ! (แนะนำ)
  - License จะผูกกับเครื่องที่กำลังสร้าง
  - ลูกค้าใช้ได้เฉพาะเครื่องที่ fingerprint ตรงกัน

- ⚠️ ถ้าปิด:
  - License ใช้ได้กับเครื่องไหนก็ได้ (ไม่ปลอดภัย!)

### ขั้นตอนที่ 3: Upload Private Key

#### 🔑 **RSA Private Key (Authorization)**

1. คลิก **"Upload"** ในช่อง "Private Key File"
2. เลือกไฟล์: `private_dev.pem`
3. ถ้า key มี passphrase: กรอกในช่อง "Key Passphrase"
4. ถ้าไม่มี passphrase: เว้นว่างไว้

⚠️ **คำเตือน:**
```
📌 Private Key เป็นตัวแทน "สิทธิ์" ในการสร้าง license
📌 ใครมีไฟล์นี้ = ใครสร้าง license ได้ไม่จำกัด
📌 เก็บไฟล์นี้ให้ปลอดภัย ห้ามให้คนอื่น!
```

### ขั้นตอนที่ 4: สร้าง License

1. ตรวจสอบข้อมูลทุกช่องให้ครบถ้วน
2. กดปุ่ม **"Generate License"** (สีน้ำเงิน)
3. รอสักครู่ (ประมาณ 2-3 วินาที)
4. เห็นข้อความ "License Generated Successfully!" ✅

### ขั้นตอนที่ 5: ดาวน์โหลด License

หลังสร้างเสร็จ จะเห็น:

```
✅ License Generated Successfully!

License file for บริษัท ABC จำกัด has been created.
Filename: บริษัท_ABC_จำกัด_license.lic

[Generation Log]
=== License Generation Started ===
Time: 2024-12-03 11:30:00
Customer: บริษัท ABC จำกัด

✓ Private key loaded: 3434 bytes
Collecting hardware information...
  - Machine ID: a1b2c3d4e5f6...
  - CPU: Intel(R) Core(TM) i7-8550U...
  - MAC: 00:11:22:33:44:55
  - Fingerprint: fbdaa17af227cbd9...
✓ Hardware binding enabled (1 instance registered)

Licensed addons: itx_helloworld, itx_sales
Max instances: 1
Concurrent users: unlimited

Encrypting license with hybrid RSA+AES...
✓ License encrypted: 1234 bytes
  - Encryption: Hybrid (RSA-4096 + AES-256-GCM)
  - File format: ODLI v1.0

=== Generation Successful ===
```

**วิธีดาวน์โหลด:**

1. กดปุ่ม **"Download License"** (สีน้ำเงิน)
2. ไฟล์ `.lic` จะดาวน์โหลดไปที่เครื่องของคุณ
3. ส่งไฟล์นี้ให้ลูกค้าผ่าน email หรือ secure channel

**วิธีสร้างอันต่อไป:**

- กดปุ่ม **"Generate Another"** เพื่อเคลียร์ฟอร์มและสร้างใหม่

---

## การจัดการ License ที่สร้างแล้ว

### ดู License ทั้งหมด

1. ไปที่เมนู: **ITX Security Shield > Generated Licenses**
2. จะเห็นรายการ license ทั้งหมดที่เคยสร้าง

### ฟังก์ชันต่างๆ

#### 📥 **Download License**

- คลิกที่ license ที่ต้องการ
- กดปุ่ม **"Download License"**
- ดาวน์โหลดซ้ำได้ไม่จำกัด

#### 🔍 **View Details**

- คลิกที่ license
- กดปุ่ม **"View Details"**
- จะเห็นข้อมูลใน license ที่ถูก decrypt แล้ว:

```
=== License Details ===

Customer: บริษัท ABC จำกัด
PO Number: PO-2024-12-001
Contract: CTR-2024-12-001
Contact: admin@abc.com

Licensed Addons: itx_helloworld, itx_sales
Max Instances: 1
Concurrent Users: unlimited

Issue Date: 2024-12-03
Expiry Date: 2025-12-31
Grace Period: 30 days
Maintenance Until: N/A

Registered Instances (1):
  - Instance #1: ubuntu-server
    Machine ID: a1b2c3d4e5f6...
    Fingerprint: fbdaa17af227cbd9...
    Status: active
```

#### 🚫 **Revoke License** (เพิกถอน)

ใช้เมื่อ:
- ลูกค้าผิดสัญญา
- ลูกค้าขอยกเลิก
- เกิดปัญหาด้านความปลอดภัย

วิธีใช้:
1. คลิกที่ license ที่ต้องการเพิกถอน
2. กดปุ่ม **"Revoke"**
3. ยืนยัน "Are you sure?"
4. สถานะจะเปลี่ยนเป็น **"Revoked"** (สีแดง)

⚠️ **หมายเหตุ:** การ revoke ในระบบนี้ไม่ได้ disable license ที่ลูกค้าไปจริงๆ (ต้องมีระบบ online check เพิ่มเติม)

#### ♻️ **Reactivate** (เปิดใช้ใหม่)

- ใช้เมื่อต้องการเปิดใช้ license ที่ revoke ไว้
- กดปุ่ม **"Reactivate"**

### Filter และ Search

#### 🔎 **Filters**

- **Active**: License ที่ใช้งานได้
- **Expired**: License ที่หมดอายุแล้ว
- **Revoked**: License ที่ถูกเพิกถอน
- **Expiring Soon (30 days)**: License ที่จะหมดอายุใน 30 วัน

#### 🔍 **Search**

ค้นหาได้ด้วย:
- ชื่อลูกค้า
- PO Number
- Contract Number
- ชื่อ Addon

#### 📊 **Group By**

จัดกลุ่มได้ตาม:
- State (สถานะ)
- Customer (ลูกค้า)
- Issue Date (วันออก)
- Expiry Date (วันหมดอายุ)

---

## คำถามที่พบบ่อย (FAQ)

### Q1: ทำไมต้องใช้ Private Key ในการสร้าง License?

**A:** เพื่อความปลอดภัย!

- Private Key เป็น "ใบอนุญาต" ในการสร้าง license
- ถ้าไม่มี key = สร้างไม่ได้
- ป้องกันไม่ให้คนที่ไม่มีสิทธิ์สร้าง license ปลอม
- ระบบใช้ RSA-4096 เข้ารหัส AES key ด้วย private key
- License สามารถ decrypt ได้ด้วย public key เท่านั้น (ฝังอยู่ในระบบ)

### Q2: Hardware Binding คืออะไร?

**A:** การผูก license กับฮาร์ดแวร์เครื่องลูกค้า

**วิธีทำงาน:**
1. ระบบอ่านข้อมูลฮาร์ดแวร์ 6 ค่า:
   - Machine ID (`/etc/machine-id`)
   - CPU Model
   - CPU Cores
   - MAC Address
   - DMI UUID
   - Disk UUID
2. รวมทุกค่าเป็น SHA-256 hash → "Hardware Fingerprint"
3. เก็บ fingerprint ในไฟล์ license
4. ตอน validate: เปรียบเทียบ fingerprint ปัจจุบันกับที่เก็บไว้
5. ต้องตรงกัน 100% ถึงจะใช้ได้

**ข้อดี:**
- ✅ ลูกค้าเอา license ไปใช้เครื่องอื่นไม่ได้
- ✅ ป้องกันการคัดลอก license
- ✅ ควบคุมจำนวน instance ได้แม่นยำ

**ข้อเสีย:**
- ❌ ถ้าลูกค้าเปลี่ยนฮาร์ดแวร์ → license ใช้ไม่ได้ (ต้องออกใหม่)
- ❌ ใน Docker/VM อาจมีปัญหา machine-id เปลี่ยน

### Q3: ลูกค้าเปลี่ยนฮาร์ดแวร์ ทำอย่างไร?

**A:** สร้าง license ใหม่ให้

**กรณีที่ 1: ลูกค้ายังอยู่ใน maintenance period**
- สร้าง license ใหม่ไม่เสียค่าใช้จ่าย
- ใช้วันหมดอายุเดิม
- ระบุใน notes ว่า "Re-issued due to hardware change"

**กรณีที่ 2: หมด maintenance แล้ว**
- ต้องทำสัญญาใหม่หรือต่ออายุ
- สร้าง license ใหม่พร้อมวันหมดอายุใหม่

**วิธีสร้าง:**
1. ไปที่เครื่องใหม่ของลูกค้า
2. สร้าง license บนเครื่องนั้น (เพื่อให้ fingerprint ตรง)
3. ส่ง license ใหม่ให้ลูกค้า
4. Revoke license เก่าในระบบ (ถ้าต้องการ)

### Q4: Max Instances คืออะไร?

**A:** จำนวนเครื่องที่ลูกค้าติดตั้ง addon ได้

**ตัวอย่าง:**

| Max Instances | ความหมาย |
|--------------|----------|
| 1 | ติดตั้งได้ 1 เครื่อง (production only) |
| 2 | ติดตั้งได้ 2 เครื่อง (production + backup) |
| 3 | ติดตั้งได้ 3 เครื่อง (production + backup + dev) |

**การทำงาน:**
- License เก็บ list ของ hardware fingerprints
- เครื่องแรกที่ validate: เพิ่ม fingerprint เข้า list
- เครื่องที่สอง: ตรวจสอบว่ามีที่ว่างใน list ไหม
- ถ้าเกิน max_instances: ปฏิเสธ

**ในเวอร์ชันปัจจุบัน:**
- ผูกกับ 1 เครื่องเท่านั้น (เครื่องที่สร้าง license)
- ถ้าต้องการ multi-instance: ต้องพัฒนาเพิ่ม (ระบบลงทะเบียนออนไลน์)

### Q5: Concurrent Users คืออะไร?

**A:** จำนวนผู้ใช้ที่ login พร้อมกันได้

**ตัวอย่าง:**

| Concurrent Users | ความหมาย |
|-----------------|----------|
| 0 | ไม่จำกัด (unlimited) |
| 10 | พร้อมกันได้ 10 คน |
| 50 | พร้อมกันได้ 50 คน |

**ในเวอร์ชันปัจจุบัน:**
- ยังไม่มีการ enforce
- เก็บค่าไว้ในไฟล์ license เท่านั้น
- ต้องพัฒนา middleware เพิ่มเติมเพื่อตรวจสอบ session

### Q6: ไฟล์ License มีอะไรบ้าง?

**A:** ไฟล์ `.lic` เป็นไฟล์เข้ารหัสที่มี:

**โครงสร้างไฟล์:**
```
┌─────────────────────────────┐
│ Header (64 bytes)           │  Magic: "ODLI"
│  - Magic bytes              │  Version: 1.0
│  - Version                  │  Encryption: RSA_AES256
│  - Encryption type          │
├─────────────────────────────┤
│ Encrypted AES Key           │  ~ 512 bytes (RSA-4096)
│  - Length (4 bytes)         │
│  - Encrypted key            │
├─────────────────────────────┤
│ Encrypted Data              │  Variable size
│  - IV (12 bytes)            │  (AES-256-GCM)
│  - Ciphertext               │
│  - Auth Tag (16 bytes)      │
├─────────────────────────────┤
│ Footer (32 bytes)           │  SHA-256 checksum
│  - Checksum                 │  (ตรวจสอบความถูกต้อง)
└─────────────────────────────┘
```

**ข้อมูลภายใน (หลัง decrypt):**
- Customer info (ชื่อ, PO, contract, email, phone)
- Licensed addons (list)
- Max instances
- Concurrent users
- Dates (issue, expiry, grace period, maintenance)
- **Hardware fingerprint** (สำคัญ!)
- License type, version, features, notes

### Q7: Grace Period คืออะไร?

**A:** ระยะเวลาผ่อนผัน หลังจาก license หมดอายุ

**ตัวอย่าง:**
- Expiry Date: 2024-12-31
- Grace Period: 30 days
- ยังใช้ได้ถึง: 2025-01-30
- หลังจากนั้น: ระบบจะบล็อก

**เหตุผล:**
- ให้ลูกค้ามีเวลาต่ออายุ
- ป้องกันระบบพังทันทีเมื่อหมดอายุ
- ธุรกิจปกติมักมี grace period 15-30 วัน

### Q8: ทำไมต้อง Encrypt ด้วย RSA + AES?

**A:** Hybrid Encryption ให้ความปลอดภัยสูงสุด

**RSA-4096 (Asymmetric):**
- ✅ ป้องกันการปลอมแปลง (เฉพาะผู้มี private key สร้างได้)
- ✅ Public key ถูกฝังในระบบ (ใช้ decrypt AES key)
- ❌ ช้า (ไม่เหมาะเข้ารหัสข้อมูลขนาดใหญ่)

**AES-256-GCM (Symmetric):**
- ✅ เร็วมาก (เข้ารหัสข้อมูลได้เป็น MB)
- ✅ Authenticated encryption (ตรวจสอบความถูกต้อง)
- ❌ ต้องแชร์ key (ไม่ปลอดภัยถ้าส่งผ่าน network)

**Hybrid = สุดยอด:**
1. สร้าง AES key แบบสุ่มใหม่ทุกครั้ง (32 bytes)
2. เข้ารหัสข้อมูล license ด้วย AES (เร็ว)
3. เข้ารหัส AES key ด้วย RSA private key (ปลอดภัย)
4. ใส่ทั้งคู่ในไฟล์ license
5. ตอน decrypt: ใช้ RSA public key ถอด AES key → ใช้ AES key ถอดข้อมูล

**ผลลัพธ์:**
- ✅ ปลอดภัยระดับธนาคาร
- ✅ เร็ว (ไม่ต่างจาก AES เพียงอย่างเดียว)
- ✅ ป้องกันการปลอมแปลง 100%

### Q9: ลูกค้าสามารถ crack license ได้ไหม?

**A:** ยากมาก แต่ไม่ใช่เป็นไปไม่ได้

**ระดับความปลอดภัย:**

| วิธีโจมตี | ความเป็นไปได้ | การป้องกัน |
|----------|--------------|-----------|
| Brute force RSA-4096 | เกือบเป็นไปไม่ได้ | ใช้เวลาหลายพันล้านปี |
| แก้ไขไฟล์ .lic | ไม่ได้ | SHA-256 checksum จะไม่ตรง |
| Copy ไป license ไปเครื่องอื่น | ไม่ได้ | Hardware fingerprint ไม่ตรง |
| Reverse engineer Python code | เป็นไปได้ | ใช้ PyArmor obfuscate |
| Patch Python validation | เป็นไปได้ | ใช้ C library + anti-debug |
| Modify C library | เป็นไปได้ | ใช้ code signing + integrity check |

**การป้องกันเพิ่มเติม (แนะนำ):**
1. ✅ ใช้ PyArmor เข้ารหัส Python code
2. ✅ ใช้ code signing สำหรับ C library
3. ✅ เพิ่ม file integrity check (hash ไฟล์ .py ทั้งหมด)
4. ✅ ใช้ anti-debugging ใน C library
5. ⚠️ ระบบ online check (ต้องพัฒนาเพิ่ม)

**ความจริง:**
- ไม่มีระบบไหนป้องกันได้ 100%
- แต่ทำให้ "ไม่คุ้มค่า" ที่จะ crack
- ส่วนใหญ่ลูกค้าจะซื้อจริงถ้าราคาสมเหตุสมผล

---

## การแก้ปัญหา

### ปัญหา: ไม่เห็นเมนู "Generate License"

**สาเหตุ:**
- ไม่มีสิทธิ์ (ไม่ใช่ system admin)

**วิธีแก้:**
1. ไปที่ Settings > Users & Companies > Users
2. เลือก user ของคุณ
3. ตรวจสอบว่ามี group "Administration / Settings" หรือไม่
4. ถ้าไม่มี: เพิ่มเข้าไป
5. Logout + Login ใหม่

### ปัญหา: Upload Private Key แล้วได้ Error

**สาเหตุที่เป็นไปได้:**

#### 1. **ไฟล์ไม่ใช่ PEM format**

```
Error: Failed to load private key: Could not deserialize key data
```

**วิธีแก้:**
```bash
# ตรวจสอบไฟล์
cat private_dev.pem

# ควรเห็น:
-----BEGIN PRIVATE KEY-----
MIIJQgIBADANBgkqhkiG9w0BAQ...
-----END PRIVATE KEY-----

# ถ้าไม่ใช่: ไฟล์ผิด
```

#### 2. **Key มี passphrase แต่ไม่ได้กรอก**

```
Error: Failed to load private key: Bad decrypt
```

**วิธีแก้:**
- กรอก passphrase ในช่อง "Key Passphrase"

#### 3. **Passphrase ผิด**

```
Error: Failed to load private key: Bad decrypt
```

**วิธีแก้:**
- ตรวจสอบ passphrase ให้ถูกต้อง
- หรือใช้ key ที่ไม่มี passphrase

### ปัญหา: Generate แล้วได้ Error "Hardware fingerprint not found"

**สาเหตุ:**
- C library ยังไม่ถูก compile หรือไม่มีอยู่

**วิธีแก้:**

```bash
# ตรวจสอบว่ามี library ไหม
ls -la /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/libintegrity.so

# ถ้าไม่มี: compile ใหม่
cd /home/chainarp/VscodeProjects/itx_security_shield_c
gcc -shared -fPIC -o libintegrity.so src/integrity_check.c src/debug.c -I./include -lssl -lcrypto

# copy ไปที่ Odoo addon
cp libintegrity.so /home/chainarp/PycharmProjects/odoo19/custom_addons/itx_security_shield/native/
```

### ปัญหา: License ใช้งานไม่ได้ที่เครื่องลูกค้า

**สาเหตุที่เป็นไปได้:**

#### 1. **Hardware fingerprint ไม่ตรง**

```
Error: Hardware mismatch detected
```

**สาเหตุ:**
- สร้าง license บนเครื่อง A แต่ใช้บนเครื่อง B
- ฮาร์ดแวร์ลูกค้าเปลี่ยน

**วิธีแก้:**
- สร้าง license ใหม่บนเครื่องลูกค้า
- หรือปิด hardware binding (ไม่แนะนำ)

#### 2. **Permission ในการอ่าน DMI UUID**

```
Warning: DMI UUID fallback used (permission denied)
```

**สาเหตุ:**
- สร้าง license ด้วย `sudo` (อ่าน DMI UUID ได้)
- ลูกค้ารัน Odoo ด้วย user ธรรมดา (อ่านไม่ได้)
- Fingerprint ไม่ตรงกัน

**วิธีแก้:**
- สร้าง license ด้วย user เดียวกับที่รัน Odoo
- หรือให้ลูกค้ารัน Odoo ด้วย sudo (ไม่แนะนำ)

```bash
# วิธีที่ถูกต้อง:
sudo -u odoo python3 tools/promote_to_prod.py ...
```

#### 3. **ไฟล์ license corrupt**

```
Error: Invalid license file: checksum mismatch
```

**สาเหตุ:**
- ไฟล์เสียขณะส่ง (email, FTP)
- ถูกแก้ไข

**วิธีแก้:**
- ส่งไฟล์ใหม่
- ใช้ md5sum/sha256sum เช็คก่อนส่ง

```bash
# เช็ค checksum ก่อนส่ง
sha256sum production.lic
```

### ปัญหา: ดาวน์โหลด License ไม่ได้

**สาเหตุ:**
- Browser block download
- ไฟล์ขนาดใหญ่เกินไป (ไม่น่าเป็น)

**วิธีแก้:**
1. ลองใช้ browser อื่น
2. เช็ค popup blocker
3. คลิกขวา > "Save link as..."

### ปัญหา: Odoo ช้าหลังจาก upgrade addon

**สาเหตุ:**
- License validation ทำงานทุกครั้งที่ Odoo start
- C library ต้อง compute fingerprint

**วิธีแก้:**
- ปกติแล้วเร็วมาก (< 1 วินาที)
- ถ้าช้า: เช็ค debug mode เปิดอยู่หรือเปล่า

```bash
# ปิด debug mode
ITX_DEBUG=0 ./odoo-bin -c odoo.conf
```

---

## สรุป

### ขั้นตอนสั้นๆ

```
1. เตรียม private key + ข้อมูลลูกค้า
2. ITX Security Shield > Generate License
3. กรอกข้อมูล + Upload key
4. กด "Generate License"
5. ดาวน์โหลดไฟล์ .lic
6. ส่งให้ลูกค้า
7. ลูกค้าวางที่ /etc/odoo/production.lic
8. Done! ✅
```

### เคล็ดลับ

✅ เก็บ private key ให้ปลอดภัย
✅ สร้าง license บนเครื่องลูกค้า (เพื่อ fingerprint ตรง)
✅ เปิด hardware binding เสมอ
✅ เก็บ record ใน "Generated Licenses" ไว้อ้างอิง
✅ ตั้ง grace period ให้เหมาะสม (30 วัน)

---

**เอกสารนี้สร้างโดย Claude Code**
**สำหรับ ITX Security Shield v19.0.1.0.0**
**วันที่: 2024-12-03**
