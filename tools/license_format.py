#!/usr/bin/env python3
"""
ITX Security Shield - License File Format

Defines the structure and schema for production.lic files.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from datetime import datetime, date
import json


@dataclass
class InstanceInfo:
    """Information about a registered instance."""
    instance_id: int
    hardware_fingerprint: str
    machine_id: str
    hostname: str
    registered_date: str
    last_seen: str
    status: str  # active, inactive, revoked

    def to_dict(self):
        return asdict(self)


@dataclass
class LicenseData:
    """
    Complete license data structure.

    This will be encrypted and stored in production.lic file.
    """

    # ========================================================================
    # Customer Information
    # ========================================================================
    customer_name: str
    po_number: str = ""                    # Purchase Order number
    contract_number: str = ""              # Contract number
    contact_email: str = ""
    contact_phone: str = ""

    # ========================================================================
    # License Rights
    # ========================================================================
    licensed_addons: List[str] = field(default_factory=list)
    max_instances: int = 1                 # Maximum number of installations
    concurrent_users: int = 0              # 0 = unlimited

    # ========================================================================
    # Hardware Binding (Multi-Instance Support)
    # ========================================================================
    registered_instances: List[Dict] = field(default_factory=list)

    # ========================================================================
    # Dates & Validity
    # ========================================================================
    issue_date: str = ""                   # When license was issued
    expiry_date: str = ""                  # When license expires
    grace_period_days: int = 30            # Grace period after expiry
    maintenance_until: str = ""            # Support/update expiry

    # ========================================================================
    # License Metadata
    # ========================================================================
    license_version: str = "1.0"
    license_type: str = "commercial"       # commercial, trial, educational, development
    license_tier: str = "standard"         # starter, standard, professional, enterprise
    features: List[str] = field(default_factory=list)

    # ========================================================================
    # Restrictions & Limits
    # ========================================================================
    max_database_size_gb: int = 0          # 0 = unlimited
    max_records_per_model: int = 0         # 0 = unlimited
    allowed_ip_ranges: List[str] = field(default_factory=list)

    # ========================================================================
    # Support & Updates
    # ========================================================================
    support_level: str = "standard"        # basic, standard, premium
    support_email: str = "support@itxcorp.com"
    update_url: str = "https://updates.itxcorp.com/"

    # ========================================================================
    # File Integrity (Optional - for Phase 2)
    # ========================================================================
    file_hashes: Dict[str, str] = field(default_factory=dict)

    # ========================================================================
    # Digital Signature (for Phase 2)
    # ========================================================================
    signature: str = ""
    signature_algorithm: str = "SHA256withRSA"

    def to_dict(self):
        """Convert to dictionary for serialization."""
        return asdict(self)

    def to_json(self):
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict):
        """Create LicenseData from dictionary."""
        # Convert registered_instances dicts to InstanceInfo objects if needed
        if 'registered_instances' in data and data['registered_instances']:
            instances = []
            for inst in data['registered_instances']:
                if isinstance(inst, dict):
                    instances.append(inst)
                else:
                    instances.append(inst.to_dict())
            data['registered_instances'] = instances

        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str):
        """Create LicenseData from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    # ========================================================================
    # Validation Methods
    # ========================================================================

    def is_expired(self) -> bool:
        """Check if license has expired."""
        if not self.expiry_date:
            return False

        try:
            expiry = datetime.strptime(self.expiry_date, '%Y-%m-%d').date()
            return date.today() > expiry
        except ValueError:
            return True

    def days_until_expiry(self) -> int:
        """Calculate days until expiry."""
        if not self.expiry_date:
            return -1

        try:
            expiry = datetime.strptime(self.expiry_date, '%Y-%m-%d').date()
            delta = expiry - date.today()
            return delta.days
        except ValueError:
            return -1

    def is_in_grace_period(self) -> bool:
        """Check if currently in grace period."""
        days = self.days_until_expiry()
        if days >= 0:
            return False  # Not expired yet

        # Check if within grace period
        return abs(days) <= self.grace_period_days

    def can_add_instance(self) -> bool:
        """Check if can add more instances."""
        active_instances = [
            inst for inst in self.registered_instances
            if inst.get('status') == 'active'
        ]
        return len(active_instances) < self.max_instances

    def get_active_instances(self) -> List[Dict]:
        """Get list of active instances."""
        return [
            inst for inst in self.registered_instances
            if inst.get('status') == 'active'
        ]

    def get_instance_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        """Find instance by hardware fingerprint."""
        for inst in self.registered_instances:
            if inst.get('hardware_fingerprint') == fingerprint:
                return inst
        return None

    def add_instance(self, instance_info: InstanceInfo) -> bool:
        """Add a new instance registration."""
        if not self.can_add_instance():
            return False

        # Check if already registered
        existing = self.get_instance_by_fingerprint(instance_info.hardware_fingerprint)
        if existing:
            # Update existing
            for i, inst in enumerate(self.registered_instances):
                if inst.get('hardware_fingerprint') == instance_info.hardware_fingerprint:
                    self.registered_instances[i] = instance_info.to_dict()
                    return True

        # Add new instance
        self.registered_instances.append(instance_info.to_dict())
        return True

    def revoke_instance(self, instance_id: int) -> bool:
        """Revoke an instance by ID."""
        for inst in self.registered_instances:
            if inst.get('instance_id') == instance_id:
                inst['status'] = 'revoked'
                return True
        return False

    def is_addon_licensed(self, addon_name: str) -> bool:
        """Check if addon is licensed."""
        if not self.licensed_addons:
            return True  # Empty list means all addons allowed
        return addon_name in self.licensed_addons


# ============================================================================
# License File Constants
# ============================================================================

MAGIC_BYTES = b'ODLI'  # Odoo License
LICENSE_VERSION = b'\x01\x00\x00\x00'  # Version 1.0
ENCRYPTION_TYPE = b'AES256GCM\x00\x00\x00'  # AES-256-GCM

HEADER_SIZE = 64
FOOTER_SIZE = 32
IV_SIZE = 12
AUTH_TAG_SIZE = 16


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == '__main__':
    # Create example license
    license_data = LicenseData(
        customer_name="บริษัท ABC จำกัด",
        po_number="PO-2024-12345",
        contract_number="CNT-2024-001",
        contact_email="admin@abc.com",
        licensed_addons=["itx_helloworld", "itx_inventory"],
        max_instances=3,
        concurrent_users=50,
        issue_date="2024-12-02",
        expiry_date="2025-12-31",
        license_type="commercial",
        license_tier="professional",
    )

    print("=" * 70)
    print("Example License Data")
    print("=" * 70)
    print(license_data.to_json())
    print()
    print(f"Expired: {license_data.is_expired()}")
    print(f"Days until expiry: {license_data.days_until_expiry()}")
    print(f"Can add instance: {license_data.can_add_instance()}")
