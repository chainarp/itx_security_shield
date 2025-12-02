#!/usr/bin/env python3
"""
ITX Security Shield - Promotion to Production

Generate production.lic file for deploying protected addons.

Usage:
    python3 promote_to_prod.py \\
        --customer "บริษัท ABC จำกัด" \\
        --po "PO-2024-12345" \\
        --contract "CNT-2024-001" \\
        --addons "itx_helloworld,itx_inventory" \\
        --max-instances 3 \\
        --users 50 \\
        --expiry "2025-12-31" \\
        --output production.lic
"""

import sys
import os
import argparse
from datetime import datetime, date
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.license_format import LicenseData, InstanceInfo
from tools.license_crypto import save_license_file
from lib import ITXSecurityVerifier


def print_banner():
    """Print banner."""
    print("=" * 70)
    print("ITX Security Shield - Promotion to Production")
    print("Generate production.lic file")
    print("=" * 70)
    print()


def collect_hardware_info() -> dict:
    """Collect hardware information from current system."""
    print("📊 Collecting hardware information...")

    try:
        verifier = ITXSecurityVerifier(debug=False)
        hw_info = verifier.get_hardware_info()
        fingerprint = verifier.get_fingerprint()

        print(f"  ✓ Machine ID: {hw_info['machine_id']}")
        print(f"  ✓ CPU: {hw_info['cpu_model']}")
        print(f"  ✓ MAC: {hw_info['mac_address']}")
        print(f"  ✓ Fingerprint: {fingerprint[:16]}...")
        print()

        return {
            'fingerprint': fingerprint,
            'machine_id': hw_info['machine_id'],
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
        }

    except Exception as e:
        print(f"  ✗ Error collecting hardware info: {e}")
        print(f"  ⚠️  Continuing without hardware binding...")
        print()
        return None


def parse_addon_list(addons_str: str) -> list:
    """Parse comma-separated addon list."""
    if not addons_str:
        return []
    return [addon.strip() for addon in addons_str.split(',') if addon.strip()]


def validate_date(date_str: str) -> str:
    """Validate date format (YYYY-MM-DD)."""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return date_str
    except ValueError:
        raise ValueError(f"Invalid date format: {date_str} (expected YYYY-MM-DD)")


def create_license(args) -> LicenseData:
    """Create LicenseData from command-line arguments."""

    # Collect hardware info if --bind-hardware is True
    hardware_info = None
    registered_instances = []

    if args.bind_hardware:
        hardware_info = collect_hardware_info()

        if hardware_info:
            # Create first instance
            instance = InstanceInfo(
                instance_id=1,
                hardware_fingerprint=hardware_info['fingerprint'],
                machine_id=hardware_info['machine_id'],
                hostname=hardware_info['hostname'],
                registered_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                status='active',
            )
            registered_instances.append(instance.to_dict())

            print(f"✓ Hardware binding enabled")
            print(f"  Instance 1 registered: {hardware_info['hostname']}")
            print()

    # Parse addon list
    licensed_addons = parse_addon_list(args.addons)

    # Create license data
    license_data = LicenseData(
        # Customer Information
        customer_name=args.customer,
        po_number=args.po or "",
        contract_number=args.contract or "",
        contact_email=args.email or "",
        contact_phone=args.phone or "",

        # License Rights
        licensed_addons=licensed_addons,
        max_instances=args.max_instances,
        concurrent_users=args.users,

        # Hardware Binding
        registered_instances=registered_instances,

        # Dates
        issue_date=date.today().strftime('%Y-%m-%d'),
        expiry_date=validate_date(args.expiry),
        grace_period_days=args.grace_days,
        maintenance_until=args.maintenance or args.expiry,

        # License Metadata
        license_version="1.0",
        license_type=args.license_type,
        license_tier=args.tier,

        # Support
        support_level=args.support_level,
        support_email=args.support_email,
    )

    return license_data


def print_license_summary(license_data: LicenseData):
    """Print license summary."""
    print("📋 License Summary")
    print("-" * 70)
    print(f"Customer:        {license_data.customer_name}")
    if license_data.po_number:
        print(f"PO Number:       {license_data.po_number}")
    if license_data.contract_number:
        print(f"Contract:        {license_data.contract_number}")

    print()
    print(f"Licensed Addons: {', '.join(license_data.licensed_addons) if license_data.licensed_addons else 'All'}")
    print(f"Max Instances:   {license_data.max_instances}")
    print(f"Max Users:       {license_data.concurrent_users if license_data.concurrent_users > 0 else 'Unlimited'}")

    print()
    print(f"Issue Date:      {license_data.issue_date}")
    print(f"Expiry Date:     {license_data.expiry_date}")
    print(f"Days Valid:      {license_data.days_until_expiry()} days")
    print(f"Grace Period:    {license_data.grace_period_days} days")

    print()
    print(f"License Type:    {license_data.license_type}")
    print(f"License Tier:    {license_data.license_tier}")
    print(f"Support Level:   {license_data.support_level}")

    if license_data.registered_instances:
        print()
        print(f"Registered Instances: {len(license_data.registered_instances)}")
        for inst in license_data.registered_instances:
            print(f"  - Instance {inst['instance_id']}: {inst['hostname']} ({inst['status']})")

    print("-" * 70)
    print()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Generate production.lic file for Odoo addon protection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic license
  python3 promote_to_prod.py \\
    --customer "บริษัท ABC จำกัด" \\
    --expiry "2025-12-31" \\
    --output production.lic

  # Full license with all options
  python3 promote_to_prod.py \\
    --customer "บริษัท XYZ จำกัด" \\
    --po "PO-2024-12345" \\
    --contract "CNT-2024-001" \\
    --email "admin@xyz.com" \\
    --addons "itx_helloworld,itx_inventory,itx_sales" \\
    --max-instances 5 \\
    --users 100 \\
    --expiry "2025-12-31" \\
    --bind-hardware \\
    --output production.lic
        """
    )

    # Required arguments
    parser.add_argument('--customer', required=True, help='Customer name (required)')
    parser.add_argument('--expiry', required=True, help='Expiry date YYYY-MM-DD (required)')

    # Optional customer info
    parser.add_argument('--po', help='Purchase Order number')
    parser.add_argument('--contract', help='Contract number')
    parser.add_argument('--email', help='Contact email')
    parser.add_argument('--phone', help='Contact phone')

    # License rights
    parser.add_argument('--addons', default='', help='Comma-separated addon names (empty = all addons)')
    parser.add_argument('--max-instances', type=int, default=1, help='Maximum installations (default: 1)')
    parser.add_argument('--users', type=int, default=0, help='Concurrent users (0 = unlimited, default: 0)')

    # Dates
    parser.add_argument('--grace-days', type=int, default=30, help='Grace period days (default: 30)')
    parser.add_argument('--maintenance', help='Maintenance/support expiry date (default: same as expiry)')

    # License type
    parser.add_argument('--license-type', default='commercial',
                       choices=['commercial', 'trial', 'educational', 'development'],
                       help='License type (default: commercial)')
    parser.add_argument('--tier', default='standard',
                       choices=['starter', 'standard', 'professional', 'enterprise'],
                       help='License tier (default: standard)')

    # Support
    parser.add_argument('--support-level', default='standard',
                       choices=['basic', 'standard', 'premium'],
                       help='Support level (default: standard)')
    parser.add_argument('--support-email', default='support@itxcorp.com',
                       help='Support email (default: support@itxcorp.com)')

    # Hardware binding
    parser.add_argument('--bind-hardware', action='store_true',
                       help='Bind license to current hardware (register this machine as instance 1)')

    # Output
    parser.add_argument('--output', default='production.lic',
                       help='Output file path (default: production.lic)')

    # Parse arguments
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Create license
    print("🔧 Creating license...")
    try:
        license_data = create_license(args)
        print("✓ License data created")
        print()
    except Exception as e:
        print(f"✗ Error creating license: {e}")
        return 1

    # Print summary
    print_license_summary(license_data)

    # Save license file
    print(f"💾 Saving license to: {args.output}")
    try:
        save_license_file(license_data, args.output)
        print()
    except Exception as e:
        print(f"✗ Error saving license file: {e}")
        return 1

    # Success
    print("=" * 70)
    print("✅ SUCCESS!")
    print("=" * 70)
    print()
    print(f"License file created: {args.output}")
    print(f"File size: {os.path.getsize(args.output)} bytes")
    print()
    print("Next steps:")
    print(f"  1. Copy {args.output} to production server:")
    print(f"     scp {args.output} user@server:/opt/odoo19/")
    print()
    print("  2. Place in Odoo addons directory")
    print()
    print("  3. Restart Odoo - license will be validated on startup")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
