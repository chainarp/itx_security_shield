# -*- coding: utf-8 -*-
"""
ITX Security Shield - License Validation and Management
Core license checking logic with hardware binding
"""

import os
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path

from odoo import models, fields, api
from odoo.exceptions import ValidationError, UserError

# Import our Python wrapper
try:
    from ..lib import ITXSecurityVerifier
    from ..lib.exceptions import (
        ITXSecurityError,
        LibraryError,
        HardwareDetectionError,
        FingerprintError,
        PermissionError as ITXPermissionError,
        PlatformError,
    )
    # Import license crypto tools
    from ..tools.license_crypto import load_license_file
except ImportError as e:
    raise ImportError(f"Failed to import ITX Security Shield wrapper: {e}")

_logger = logging.getLogger(__name__)

# License file path (relative to addon root or absolute)
LICENSE_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'production.lic')


class LicenseCheck(models.Model):
    """
    Core License Validation Model

    Handles:
    - Hardware fingerprint validation
    - License file verification
    - File integrity checking (hash-based tampering detection)
    - Expiration date enforcement
    - Grace period management
    """

    _name = 'license.check'
    _description = 'ITX License Validation and Management'
    _order = 'check_date desc'

    # ========================================================================
    # FIELDS
    # ========================================================================

    name = fields.Char(
        string='Check Reference',
        required=True,
        default=lambda self: self._generate_check_reference(),
        readonly=True,
    )

    check_date = fields.Datetime(
        string='Check Date',
        required=True,
        default=fields.Datetime.now,
        readonly=True,
    )

    check_type = fields.Selection(
        [
            ('startup', 'Startup Validation'),
            ('periodic', 'Periodic Check (Cron)'),
            ('manual', 'Manual Verification'),
            ('file_hash', 'File Hash Validation'),
        ],
        string='Check Type',
        required=True,
        default='manual',
    )

    status = fields.Selection(
        [
            ('valid', 'Valid License'),
            ('warning', 'Warning (Grace Period)'),
            ('invalid', 'Invalid License'),
            ('expired', 'Expired'),
            ('tampered', 'File Tampering Detected'),
            ('hardware_mismatch', 'Hardware Mismatch'),
        ],
        string='Status',
        required=True,
        default='invalid',
    )

    hardware_fingerprint = fields.Char(
        string='Current Hardware Fingerprint',
        readonly=True,
        help='SHA-256 fingerprint of current hardware',
    )

    license_fingerprint = fields.Char(
        string='License Hardware Fingerprint',
        readonly=True,
        help='SHA-256 fingerprint from license file',
    )

    fingerprint_match = fields.Boolean(
        string='Fingerprint Match',
        compute='_compute_fingerprint_match',
        store=True,
    )

    license_expiry = fields.Date(
        string='License Expiry Date',
        readonly=True,
    )

    days_until_expiry = fields.Integer(
        string='Days Until Expiry',
        compute='_compute_days_until_expiry',
        store=True,
    )

    grace_period_active = fields.Boolean(
        string='Grace Period Active',
        default=False,
        help='True if license has issues but grace period allows operation',
    )

    grace_period_ends = fields.Datetime(
        string='Grace Period Ends',
        help='When grace period expires (30 days from first violation)',
    )

    validation_message = fields.Text(
        string='Validation Message',
        readonly=True,
        help='Detailed validation result and recommendations',
    )

    error_details = fields.Text(
        string='Error Details',
        readonly=True,
        help='Technical error details for debugging',
    )

    # Hardware information
    machine_id = fields.Char(string='Machine ID', readonly=True)
    cpu_model = fields.Char(string='CPU Model', readonly=True)
    cpu_cores = fields.Integer(string='CPU Cores', readonly=True)
    mac_address = fields.Char(string='MAC Address', readonly=True)
    is_docker = fields.Boolean(string='Running in Docker', readonly=True)
    is_vm = fields.Boolean(string='Running in VM', readonly=True)

    # File integrity
    files_checked = fields.Integer(string='Files Checked', default=0)
    files_modified = fields.Integer(string='Files Modified', default=0)
    modified_files = fields.Text(string='Modified Files List', readonly=True)

    # ========================================================================
    # COMPUTE METHODS
    # ========================================================================

    @api.depends('hardware_fingerprint', 'license_fingerprint')
    def _compute_fingerprint_match(self):
        """Check if hardware and license fingerprints match"""
        for record in self:
            if record.hardware_fingerprint and record.license_fingerprint:
                record.fingerprint_match = (
                    record.hardware_fingerprint == record.license_fingerprint
                )
            else:
                record.fingerprint_match = False

    @api.depends('license_expiry')
    def _compute_days_until_expiry(self):
        """Calculate days until license expires"""
        for record in self:
            if record.license_expiry:
                today = fields.Date.today()
                delta = record.license_expiry - today
                record.days_until_expiry = delta.days
            else:
                record.days_until_expiry = 0

    def _generate_check_reference(self):
        """Generate unique check reference"""
        return f"CHK-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # ========================================================================
    # CORE LICENSE VALIDATION METHODS
    # ========================================================================

    @api.model
    def verify_license(self, check_type='manual'):
        """
        Main license validation entry point

        This method orchestrates the complete license validation process:
        1. Hardware fingerprint validation
        2. License file verification
        3. Expiration date checking
        4. File integrity validation (optional, for periodic checks)

        Args:
            check_type (str): Type of check ('startup', 'periodic', 'manual', 'file_hash')

        Returns:
            dict: Validation result with keys:
                - valid (bool): Overall validation status
                - status (str): Detailed status code
                - message (str): Human-readable message
                - check_id (int): ID of created license.check record
                - grace_period (bool): Whether grace period is active

        Raises:
            ValidationError: If license validation fails critically
        """
        _logger.info(f"🔐 Starting license validation (type: {check_type})")

        validation_result = {
            'valid': False,
            'status': 'invalid',
            'message': '',
            'check_id': None,
            'grace_period': False,
        }

        # Create check record
        check_record = self.create({
            'check_type': check_type,
            'status': 'invalid',
        })
        validation_result['check_id'] = check_record.id

        try:
            # Step 1: Check hardware fingerprint
            _logger.info("Step 1: Checking hardware fingerprint...")
            hardware_valid = check_record.check_hardware()

            if not hardware_valid:
                validation_result['status'] = 'hardware_mismatch'
                validation_result['message'] = (
                    "Hardware mismatch detected. License is bound to different hardware."
                )
                check_record.write({
                    'status': 'hardware_mismatch',
                    'validation_message': validation_result['message'],
                })

                # Check if grace period applies
                if check_record._check_grace_period():
                    validation_result['grace_period'] = True
                    validation_result['message'] += "\n⚠️  Grace period active - system will continue operating."
                    return validation_result
                else:
                    raise ValidationError(validation_result['message'])

            # Step 2: Check license expiration
            _logger.info("Step 2: Checking license expiration...")
            expiry_valid = check_record.check_expiry()

            if not expiry_valid:
                validation_result['status'] = 'expired'
                validation_result['message'] = (
                    f"License expired on {check_record.license_expiry}. "
                    f"Please contact ITX for license renewal."
                )
                check_record.write({
                    'status': 'expired',
                    'validation_message': validation_result['message'],
                })

                if check_record._check_grace_period():
                    validation_result['grace_period'] = True
                    validation_result['message'] += "\n⚠️  Grace period active - system will continue operating."
                    return validation_result
                else:
                    raise ValidationError(validation_result['message'])

            # Step 3: Check file integrity (for periodic checks)
            if check_type in ('periodic', 'file_hash'):
                _logger.info("Step 3: Checking file integrity...")
                integrity_valid = check_record.check_file_hashes()

                if not integrity_valid:
                    validation_result['status'] = 'tampered'
                    validation_result['message'] = (
                        f"⚠️  File tampering detected! "
                        f"{check_record.files_modified} files have been modified.\n"
                        f"Modified files:\n{check_record.modified_files}"
                    )
                    check_record.write({
                        'status': 'tampered',
                        'validation_message': validation_result['message'],
                    })

                    # File tampering gets grace period
                    if check_record._check_grace_period():
                        validation_result['grace_period'] = True
                        validation_result['message'] += "\n⚠️  Grace period active - system will continue operating."
                        return validation_result
                    else:
                        raise ValidationError(validation_result['message'])

            # All checks passed!
            validation_result['valid'] = True
            validation_result['status'] = 'valid'
            validation_result['message'] = (
                f"✓ License valid\n"
                f"✓ Hardware fingerprint matches\n"
                f"✓ License expires in {check_record.days_until_expiry} days\n"
            )

            if check_type in ('periodic', 'file_hash'):
                validation_result['message'] += (
                    f"✓ File integrity verified ({check_record.files_checked} files checked)"
                )

            check_record.write({
                'status': 'valid',
                'validation_message': validation_result['message'],
            })

            _logger.info("✓ License validation successful")
            return validation_result

        except (ITXSecurityError, ValidationError, UserError) as e:
            # Known errors - log and re-raise
            error_msg = str(e)
            _logger.error(f"License validation failed: {error_msg}")
            check_record.write({
                'error_details': error_msg,
            })
            raise

        except Exception as e:
            # Unexpected errors
            error_msg = f"Unexpected error during license validation: {e}"
            _logger.exception(error_msg)
            check_record.write({
                'status': 'invalid',
                'error_details': error_msg,
                'validation_message': "License validation failed due to system error.",
            })
            raise ValidationError(f"License validation failed: {e}")

    def check_hardware(self):
        """
        Verify hardware fingerprint matches license

        Returns:
            bool: True if hardware matches, False otherwise

        Raises:
            LibraryError: If C library fails to load
            HardwareDetectionError: If hardware detection fails
        """
        _logger.info("Checking hardware fingerprint against license...")

        try:
            # Initialize ITX Security Verifier
            verifier = ITXSecurityVerifier(debug=False)

            # Get current hardware info
            hw_info = verifier.get_hardware_info()

            # DEBUG: Log all hardware info
            _logger.info(f"DEBUG hw_info keys: {list(hw_info.keys())}")
            _logger.info(f"DEBUG machine_id: {hw_info.get('machine_id', 'N/A')}")
            _logger.info(f"DEBUG cpu_model: {hw_info.get('cpu_model', 'N/A')[:50]}...")
            _logger.info(f"DEBUG mac_address: {hw_info.get('mac_address', 'N/A')}")
            _logger.info(f"DEBUG dmi_uuid: {hw_info.get('dmi_uuid', 'N/A')}")
            _logger.info(f"DEBUG disk_uuid: {hw_info.get('disk_uuid', 'N/A')}")
            _logger.info(f"DEBUG fingerprint from hw_info: {hw_info.get('fingerprint', 'EMPTY')}")

            # Store hardware details
            self.write({
                'machine_id': hw_info.get('machine_id', 'unknown'),
                'cpu_model': hw_info.get('cpu_model', 'unknown'),
                'cpu_cores': hw_info.get('cpu_cores', 0),
                'mac_address': hw_info.get('mac_address', 'unknown'),
                'is_docker': hw_info.get('is_docker', False),
                'is_vm': hw_info.get('is_vm', False),
            })

            # Get current hardware fingerprint from hw_info struct
            # Use fingerprint from struct (populated by C library)
            current_fingerprint = hw_info.get('fingerprint', '')

            # Fallback: if fingerprint not in struct, call get_fingerprint() separately
            if not current_fingerprint:
                _logger.warning("Fingerprint not found in struct, calling get_fingerprint() separately")
                current_fingerprint = verifier.get_fingerprint()

            self.hardware_fingerprint = current_fingerprint

            _logger.info(f"Current hardware fingerprint: {current_fingerprint[:16]}...")

            # Load license fingerprint from file
            license_fingerprint = self._load_license_fingerprint()
            self.license_fingerprint = license_fingerprint

            if not license_fingerprint:
                _logger.warning("No license file found - treating as invalid")
                return False

            _logger.info(f"License hardware fingerprint: {license_fingerprint[:16]}...")

            # Compare fingerprints
            match = (current_fingerprint == license_fingerprint)

            if match:
                _logger.info("✓ Hardware fingerprint matches license")
            else:
                _logger.warning("✗ Hardware fingerprint does NOT match license")
                _logger.warning(f"  Current:  {current_fingerprint}")
                _logger.warning(f"  Expected: {license_fingerprint}")

            return match

        except HardwareDetectionError as e:
            _logger.error(f"Hardware detection failed: {e}")
            if e.missing_fields:
                _logger.error(f"Missing hardware fields: {', '.join(e.missing_fields)}")
            self.error_details = str(e)
            raise

        except ITXSecurityError as e:
            _logger.error(f"ITX Security error: {e}")
            self.error_details = str(e)
            raise

        except Exception as e:
            _logger.exception(f"Unexpected error checking hardware: {e}")
            self.error_details = str(e)
            raise ValidationError(f"Hardware check failed: {e}")

    def check_expiry(self):
        """
        Check license expiration date and grace period

        Returns:
            bool: True if license is not expired, False if expired
        """
        _logger.info("Checking license expiration date...")

        try:
            # Load license expiry from file
            expiry_date = self._load_license_expiry()

            if not expiry_date:
                _logger.warning("No license expiry date found")
                return False

            self.license_expiry = expiry_date

            today = fields.Date.today()
            days_left = (expiry_date - today).days

            _logger.info(f"License expiry: {expiry_date} ({days_left} days remaining)")

            if days_left < 0:
                _logger.warning(f"✗ License expired {abs(days_left)} days ago")
                return False
            elif days_left < 30:
                _logger.warning(f"⚠️  License expires soon ({days_left} days)")
                # Still valid, but show warning
                return True
            else:
                _logger.info(f"✓ License valid for {days_left} days")
                return True

        except Exception as e:
            _logger.exception(f"Error checking license expiry: {e}")
            self.error_details = str(e)
            raise ValidationError(f"Expiry check failed: {e}")

    def check_file_hashes(self, sample_percentage=10):
        """
        Detect file tampering by comparing file hashes

        From design document Phase 6:
        - Randomly sample 10% of addon files every 6 hours
        - Compare SHA-256 hashes against production.lic
        - Log violations

        Args:
            sample_percentage (int): Percentage of files to check (1-100)

        Returns:
            bool: True if all checked files match, False if tampering detected
        """
        _logger.info(f"Checking file integrity (sampling {sample_percentage}% of files)...")

        try:
            # Load file hashes from license
            license_hashes = self._load_license_file_hashes()

            if not license_hashes:
                _logger.warning("No file hashes found in license - skipping integrity check")
                return True  # No hashes = can't verify, assume OK

            # Get list of addon files
            addon_path = Path(__file__).parent.parent
            addon_files = self._get_addon_files(addon_path)

            # Sample files
            import random
            sample_size = max(1, len(addon_files) * sample_percentage // 100)
            sampled_files = random.sample(addon_files, min(sample_size, len(addon_files)))

            _logger.info(f"Sampling {len(sampled_files)} of {len(addon_files)} files")

            modified_files = []

            # Check each sampled file
            for file_path in sampled_files:
                relative_path = file_path.relative_to(addon_path)

                # Calculate current hash
                current_hash = self._calculate_file_hash(file_path)

                # Get expected hash from license
                expected_hash = license_hashes.get(str(relative_path))

                if not expected_hash:
                    _logger.warning(f"File not in license: {relative_path}")
                    modified_files.append(f"{relative_path} (not in license)")
                elif current_hash != expected_hash:
                    _logger.warning(f"Hash mismatch: {relative_path}")
                    _logger.warning(f"  Current:  {current_hash}")
                    _logger.warning(f"  Expected: {expected_hash}")
                    modified_files.append(f"{relative_path} (hash mismatch)")

            # Update check record
            self.write({
                'files_checked': len(sampled_files),
                'files_modified': len(modified_files),
                'modified_files': '\n'.join(modified_files) if modified_files else None,
            })

            if modified_files:
                _logger.error(f"✗ File tampering detected: {len(modified_files)} files modified")
                return False
            else:
                _logger.info(f"✓ File integrity verified: all {len(sampled_files)} files match")
                return True

        except Exception as e:
            _logger.exception(f"Error checking file hashes: {e}")
            self.error_details = str(e)
            # Don't fail on hash check errors - log and continue
            return True

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _check_grace_period(self):
        """
        Check if grace period is active

        From design document:
        - 30 days grace period after first violation
        - System continues operating but logs warnings

        Returns:
            bool: True if grace period allows operation, False otherwise
        """
        # TODO: Implement grace period logic
        # This requires a persistent configuration to track first violation date
        _logger.warning("Grace period check not yet implemented - defaulting to no grace")
        return False

    def _load_license_fingerprint(self):
        """
        Load hardware fingerprint from production.lic file

        Returns:
            str: Hardware fingerprint from license, or None if not found
        """
        try:
            if not os.path.exists(LICENSE_FILE_PATH):
                _logger.warning(f"License file not found: {LICENSE_FILE_PATH}")
                return None

            # Load and decrypt license file
            license_data = load_license_file(LICENSE_FILE_PATH)

            # Get registered instances
            if license_data.registered_instances:
                # Return fingerprint from first active instance
                for instance in license_data.registered_instances:
                    if instance.get('status') == 'active':
                        fingerprint = instance.get('hardware_fingerprint')
                        _logger.info(f"Loaded license fingerprint from instance {instance.get('instance_id')}")
                        return fingerprint

            _logger.warning("No active instances found in license file")
            return None

        except Exception as e:
            _logger.error(f"Error loading license fingerprint: {e}")
            return None

    def _load_license_expiry(self):
        """
        Load expiry date from production.lic file

        Returns:
            date: Expiry date from license, or None if not found
        """
        try:
            if not os.path.exists(LICENSE_FILE_PATH):
                _logger.warning(f"License file not found: {LICENSE_FILE_PATH}")
                return None

            # Load and decrypt license file
            license_data = load_license_file(LICENSE_FILE_PATH)

            # Parse expiry date
            if license_data.expiry_date:
                expiry_date = datetime.strptime(license_data.expiry_date, '%Y-%m-%d').date()
                _logger.info(f"Loaded license expiry date: {expiry_date}")
                return expiry_date
            else:
                _logger.warning("No expiry date found in license file")
                return None

        except Exception as e:
            _logger.error(f"Error loading license expiry: {e}")
            return None

    def _load_license_file_hashes(self):
        """
        Load file hashes from production.lic file

        Returns:
            dict: Mapping of relative file paths to SHA-256 hashes
        """
        try:
            if not os.path.exists(LICENSE_FILE_PATH):
                _logger.warning(f"License file not found: {LICENSE_FILE_PATH}")
                return {}

            # Load and decrypt license file
            license_data = load_license_file(LICENSE_FILE_PATH)

            # Return file hashes
            if license_data.file_hashes:
                _logger.info(f"Loaded {len(license_data.file_hashes)} file hashes from license")
                return license_data.file_hashes
            else:
                _logger.warning("No file hashes found in license file")
                return {}

        except Exception as e:
            _logger.error(f"Error loading license file hashes: {e}")
            return {}

    def _get_addon_files(self, addon_path):
        """
        Get list of all Python files in addon

        Args:
            addon_path (Path): Root path of addon

        Returns:
            list[Path]: List of Python file paths
        """
        addon_files = []

        # Scan for .py files, excluding certain directories
        exclude_dirs = {'__pycache__', '.git', 'tests', 'native'}

        for py_file in addon_path.rglob('*.py'):
            # Skip excluded directories
            if any(excluded in py_file.parts for excluded in exclude_dirs):
                continue
            addon_files.append(py_file)

        return addon_files

    def _calculate_file_hash(self, file_path):
        """
        Calculate SHA-256 hash of file

        Args:
            file_path (Path): Path to file

        Returns:
            str: Hex-encoded SHA-256 hash
        """
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)

        return sha256.hexdigest()

    # ========================================================================
    # UI ACTIONS
    # ========================================================================

    def action_recheck(self):
        """Manual recheck button action"""
        self.ensure_one()
        return self.env['license.check'].verify_license(check_type='manual')

    def action_view_hardware_info(self):
        """View detailed hardware information"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': 'Hardware Information',
            'res_model': 'license.check',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
