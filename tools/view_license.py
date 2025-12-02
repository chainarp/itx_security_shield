#!/usr/bin/env python3
"""
ITX Security Shield - View License File

View details of production.lic file.

Usage:
    python3 view_license.py production.lic
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.license_crypto import load_license_file, validate_license_file


def print_license_details(license_data):
    """Print detailed license information."""

    print("=" * 70)
    print("ITX Security Shield - License Details")
    print("=" * 70)
    print()

    # Customer Information
    print("👤 CUSTOMER INFORMATION")
    print("-" * 70)
    print(f"Customer Name:    {license_data.customer_name}")
    if license_data.po_number:
        print(f"PO Number:        {license_data.po_number}")
    if license_data.contract_number:
        print(f"Contract Number:  {license_data.contract_number}")
    if license_data.contact_email:
        print(f"Email:            {license_data.contact_email}")
    if license_data.contact_phone:
        print(f"Phone:            {license_data.contact_phone}")
    print()

    # License Rights
    print("📜 LICENSE RIGHTS")
    print("-" * 70)
    if license_data.licensed_addons:
        print(f"Licensed Addons:  {len(license_data.licensed_addons)} addons")
        for addon in license_data.licensed_addons:
            print(f"  • {addon}")
    else:
        print(f"Licensed Addons:  All addons")

    print(f"Max Instances:    {license_data.max_instances}")
    if license_data.concurrent_users > 0:
        print(f"Concurrent Users: {license_data.concurrent_users}")
    else:
        print(f"Concurrent Users: Unlimited")
    print()

    # Registered Instances
    print("🖥️  REGISTERED INSTANCES")
    print("-" * 70)
    if license_data.registered_instances:
        active = [i for i in license_data.registered_instances if i.get('status') == 'active']
        print(f"Total Registered: {len(license_data.registered_instances)}")
        print(f"Active:           {len(active)}")
        print(f"Available Slots:  {license_data.max_instances - len(active)}")
        print()

        for inst in license_data.registered_instances:
            status_icon = "✓" if inst.get('status') == 'active' else "✗"
            print(f"  {status_icon} Instance {inst.get('instance_id')}:")
            print(f"      Hostname:     {inst.get('hostname')}")
            print(f"      Machine ID:   {inst.get('machine_id')}")
            print(f"      Fingerprint:  {inst.get('hardware_fingerprint')[:32]}...")
            print(f"      Registered:   {inst.get('registered_date')}")
            print(f"      Last Seen:    {inst.get('last_seen')}")
            print(f"      Status:       {inst.get('status').upper()}")
            print()
    else:
        print(f"No instances registered yet")
        print(f"Available Slots:  {license_data.max_instances}")
        print()

    # Validity
    print("📅 VALIDITY")
    print("-" * 70)
    print(f"Issue Date:       {license_data.issue_date}")
    print(f"Expiry Date:      {license_data.expiry_date}")

    days_left = license_data.days_until_expiry()
    if days_left >= 0:
        print(f"Days Remaining:   {days_left} days")
        if days_left < 30:
            print(f"⚠️  WARNING: License expires soon!")
    else:
        print(f"Status:           ⚠️  EXPIRED ({abs(days_left)} days ago)")
        if license_data.is_in_grace_period():
            print(f"Grace Period:     Active ({license_data.grace_period_days - abs(days_left)} days left)")
        else:
            print(f"Grace Period:     Expired")

    print(f"Grace Period:     {license_data.grace_period_days} days")
    if license_data.maintenance_until:
        print(f"Maintenance Until: {license_data.maintenance_until}")
    print()

    # License Metadata
    print("ℹ️  LICENSE METADATA")
    print("-" * 70)
    print(f"License Version:  {license_data.license_version}")
    print(f"License Type:     {license_data.license_type}")
    print(f"License Tier:     {license_data.license_tier}")

    if license_data.features:
        print(f"Enabled Features: {', '.join(license_data.features)}")
    print()

    # Support
    print("🆘 SUPPORT & UPDATES")
    print("-" * 70)
    print(f"Support Level:    {license_data.support_level}")
    print(f"Support Email:    {license_data.support_email}")
    if license_data.update_url:
        print(f"Update URL:       {license_data.update_url}")
    print()

    # Restrictions
    if (license_data.max_database_size_gb > 0 or
        license_data.max_records_per_model > 0 or
        license_data.allowed_ip_ranges):
        print("🚫 RESTRICTIONS")
        print("-" * 70)
        if license_data.max_database_size_gb > 0:
            print(f"Max Database Size: {license_data.max_database_size_gb} GB")
        if license_data.max_records_per_model > 0:
            print(f"Max Records/Model: {license_data.max_records_per_model}")
        if license_data.allowed_ip_ranges:
            print(f"Allowed IP Ranges: {', '.join(license_data.allowed_ip_ranges)}")
        print()

    # File Integrity
    if license_data.file_hashes:
        print("🔒 FILE INTEGRITY")
        print("-" * 70)
        print(f"Protected Files:  {len(license_data.file_hashes)} files")
        print()

    print("=" * 70)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='View production.lic file details'
    )
    parser.add_argument('license_file', help='Path to production.lic')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    # Validate file first
    print(f"Validating license file: {args.license_file}")
    valid, message = validate_license_file(args.license_file)

    if not valid:
        print(f"✗ Validation failed: {message}")
        return 1

    print(f"✓ File structure valid")
    print()

    # Load license
    try:
        license_data = load_license_file(args.license_file)
    except Exception as e:
        print(f"✗ Error loading license: {e}")
        return 1

    # Print details
    if args.json:
        print(license_data.to_json())
    else:
        print_license_details(license_data)

    return 0


if __name__ == '__main__':
    sys.exit(main())
