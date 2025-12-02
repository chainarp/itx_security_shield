# -*- coding: utf-8 -*-
"""
ITX Security Shield - License Configuration Management
Stores license parameters, grace periods, and system configuration
"""

import logging
from datetime import datetime, timedelta

from odoo import models, fields, api
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class LicenseConfig(models.Model):
    """
    License Configuration and Settings

    Singleton model (only one record exists) that stores:
    - License file path and status
    - Grace period settings and tracking
    - Validation schedule (cron settings)
    - File integrity check settings
    - Emergency unlock codes
    """

    _name = 'license.config'
    _description = 'ITX License Configuration'

    # ========================================================================
    # FIELDS
    # ========================================================================

    name = fields.Char(
        string='Configuration Name',
        required=True,
        default='ITX License Configuration',
    )

    # License file information
    license_file_path = fields.Char(
        string='License File Path',
        default='/opt/odoo19/production.lic',
        help='Full path to production.lic file',
    )

    license_file_exists = fields.Boolean(
        string='License File Exists',
        compute='_compute_license_file_exists',
        help='Whether the license file is present',
    )

    license_installed = fields.Boolean(
        string='License Installed',
        default=False,
        help='Whether a valid license has been installed',
    )

    license_installed_date = fields.Datetime(
        string='License Installed Date',
        readonly=True,
        help='When the license was first installed',
    )

    # License details (cached from file)
    license_fingerprint = fields.Char(
        string='License Hardware Fingerprint',
        readonly=True,
        help='Hardware fingerprint from license file',
    )

    license_expiry = fields.Date(
        string='License Expiry Date',
        readonly=True,
        help='License expiration date',
    )

    licensed_addons = fields.Text(
        string='Licensed Addons',
        readonly=True,
        help='Comma-separated list of addons covered by license',
    )

    # Grace period settings
    grace_period_enabled = fields.Boolean(
        string='Grace Period Enabled',
        default=True,
        help='Allow 30-day grace period after license violations',
    )

    grace_period_days = fields.Integer(
        string='Grace Period (Days)',
        default=30,
        help='Number of days grace period lasts (default: 30)',
    )

    grace_period_active = fields.Boolean(
        string='Grace Period Currently Active',
        default=False,
        help='Whether grace period is currently in effect',
    )

    grace_period_started = fields.Datetime(
        string='Grace Period Started',
        help='When grace period was activated',
    )

    grace_period_ends = fields.Datetime(
        string='Grace Period Ends',
        compute='_compute_grace_period_ends',
        store=True,
        help='When grace period expires',
    )

    grace_period_reason = fields.Text(
        string='Grace Period Reason',
        help='Why grace period was activated (violation details)',
    )

    # Validation settings
    periodic_check_enabled = fields.Boolean(
        string='Periodic Validation Enabled',
        default=True,
        help='Enable automatic periodic license checks via cron',
    )

    periodic_check_interval = fields.Integer(
        string='Check Interval (Hours)',
        default=6,
        help='How often to run periodic license checks (default: 6 hours)',
    )

    file_integrity_enabled = fields.Boolean(
        string='File Integrity Checks Enabled',
        default=True,
        help='Enable file hash validation during periodic checks',
    )

    file_integrity_sample_pct = fields.Integer(
        string='File Sample Percentage',
        default=10,
        help='Percentage of files to sample during integrity checks (1-100)',
    )

    # Startup validation
    startup_check_enabled = fields.Boolean(
        string='Startup Validation Enabled',
        default=True,
        help='Validate license when Odoo starts',
    )

    startup_check_blocking = fields.Boolean(
        string='Block Startup on Failure',
        default=True,
        help='Prevent Odoo from starting if license validation fails',
    )

    # Statistics
    last_check_date = fields.Datetime(
        string='Last Validation',
        readonly=True,
        help='When license was last validated',
    )

    last_check_status = fields.Selection(
        [
            ('valid', 'Valid'),
            ('warning', 'Warning'),
            ('invalid', 'Invalid'),
        ],
        string='Last Check Status',
        readonly=True,
    )

    total_checks = fields.Integer(
        string='Total Checks',
        default=0,
        readonly=True,
        help='Total number of license validations performed',
    )

    total_violations = fields.Integer(
        string='Total Violations',
        default=0,
        readonly=True,
        help='Total number of license violations detected',
    )

    # Emergency unlock
    emergency_unlock_enabled = fields.Boolean(
        string='Emergency Unlock Active',
        default=False,
        help='Temporary bypass of license checks (DANGEROUS - for emergency use only)',
    )

    emergency_unlock_code = fields.Char(
        string='Emergency Unlock Code',
        help='Code required to enable emergency unlock',
    )

    emergency_unlock_expires = fields.Datetime(
        string='Emergency Unlock Expires',
        help='When emergency unlock automatically expires',
    )

    # ========================================================================
    # CONSTRAINTS
    # ========================================================================

    @api.constrains('grace_period_days')
    def _check_grace_period_days(self):
        """Validate grace period days"""
        for record in self:
            if record.grace_period_days < 0:
                raise ValidationError("Grace period days cannot be negative")
            if record.grace_period_days > 365:
                raise ValidationError("Grace period days cannot exceed 365 days")

    @api.constrains('periodic_check_interval')
    def _check_periodic_check_interval(self):
        """Validate periodic check interval"""
        for record in self:
            if record.periodic_check_interval < 1:
                raise ValidationError("Check interval must be at least 1 hour")
            if record.periodic_check_interval > 168:  # 1 week
                raise ValidationError("Check interval cannot exceed 168 hours (1 week)")

    @api.constrains('file_integrity_sample_pct')
    def _check_file_integrity_sample_pct(self):
        """Validate file sampling percentage"""
        for record in self:
            if not (1 <= record.file_integrity_sample_pct <= 100):
                raise ValidationError("File sample percentage must be between 1 and 100")

    # ========================================================================
    # COMPUTE METHODS
    # ========================================================================

    @api.depends('license_file_path')
    def _compute_license_file_exists(self):
        """Check if license file exists on disk"""
        import os
        for record in self:
            if record.license_file_path:
                record.license_file_exists = os.path.isfile(record.license_file_path)
            else:
                record.license_file_exists = False

    @api.depends('grace_period_started', 'grace_period_days')
    def _compute_grace_period_ends(self):
        """Calculate when grace period expires"""
        for record in self:
            if record.grace_period_started and record.grace_period_days:
                end_date = record.grace_period_started + timedelta(days=record.grace_period_days)
                record.grace_period_ends = end_date
            else:
                record.grace_period_ends = False

    # ========================================================================
    # SINGLETON PATTERN
    # ========================================================================

    @api.model
    def get_config(self):
        """
        Get the singleton configuration record

        Returns:
            license.config: The configuration record (creates if doesn't exist)
        """
        config = self.search([], limit=1)
        if not config:
            config = self.create({
                'name': 'ITX License Configuration',
            })
            _logger.info("Created new license configuration record")
        return config

    # ========================================================================
    # GRACE PERIOD MANAGEMENT
    # ========================================================================

    def start_grace_period(self, reason):
        """
        Activate grace period

        Args:
            reason (str): Reason for activating grace period (violation details)

        Returns:
            datetime: When grace period expires
        """
        self.ensure_one()

        if not self.grace_period_enabled:
            _logger.warning("Grace period is disabled - cannot activate")
            return False

        if self.grace_period_active:
            _logger.info(f"Grace period already active (ends: {self.grace_period_ends})")
            return self.grace_period_ends

        now = fields.Datetime.now()
        self.write({
            'grace_period_active': True,
            'grace_period_started': now,
            'grace_period_reason': reason,
        })

        _logger.warning(
            f"⚠️  Grace period activated: {reason}\n"
            f"Grace period ends: {self.grace_period_ends}"
        )

        # Log to license.log
        self.env['license.log'].log_grace_period_start(
            None,
            reason,
            self.grace_period_ends,
        )

        return self.grace_period_ends

    def end_grace_period(self):
        """Deactivate grace period"""
        self.ensure_one()

        if not self.grace_period_active:
            return

        self.write({
            'grace_period_active': False,
            'grace_period_started': False,
            'grace_period_reason': False,
        })

        _logger.warning("Grace period has ended")

        # Log to license.log
        self.env['license.log'].log_grace_period_end(None)

    def check_grace_period_expired(self):
        """
        Check if grace period has expired and deactivate if needed

        Returns:
            bool: True if grace period is still active, False if expired
        """
        self.ensure_one()

        if not self.grace_period_active:
            return False

        if not self.grace_period_ends:
            return True

        now = fields.Datetime.now()
        if now > self.grace_period_ends:
            _logger.warning("Grace period has expired - deactivating")
            self.end_grace_period()
            return False

        return True

    # ========================================================================
    # LICENSE FILE MANAGEMENT
    # ========================================================================

    def reload_license_info(self):
        """
        Reload license information from production.lic file

        Returns:
            dict: License information
        """
        self.ensure_one()

        # TODO: Implement license file decryption and parsing
        _logger.warning("License file parsing not yet implemented")

        return {
            'fingerprint': None,
            'expiry': None,
            'addons': [],
        }

    def install_license(self, license_file_content):
        """
        Install new license file

        Args:
            license_file_content (bytes): Content of production.lic file

        Raises:
            ValidationError: If license file is invalid
        """
        self.ensure_one()

        # TODO: Implement license file installation
        # 1. Validate license file format
        # 2. Decrypt and parse
        # 3. Verify hardware fingerprint
        # 4. Write to license_file_path
        # 5. Update configuration

        _logger.warning("License installation not yet implemented")
        raise ValidationError("License installation not yet implemented")

    # ========================================================================
    # STATISTICS
    # ========================================================================

    def record_check(self, status):
        """
        Record a validation check

        Args:
            status (str): Check status ('valid', 'warning', 'invalid')
        """
        self.ensure_one()

        values = {
            'last_check_date': fields.Datetime.now(),
            'last_check_status': status,
            'total_checks': self.total_checks + 1,
        }

        if status == 'invalid':
            values['total_violations'] = self.total_violations + 1

        self.write(values)

    # ========================================================================
    # EMERGENCY UNLOCK
    # ========================================================================

    def enable_emergency_unlock(self, unlock_code, hours=24):
        """
        Enable emergency unlock (DANGEROUS - bypasses all license checks)

        Args:
            unlock_code (str): Secret unlock code
            hours (int): How many hours emergency unlock lasts

        Raises:
            ValidationError: If unlock code is incorrect
        """
        self.ensure_one()

        # TODO: Implement proper unlock code verification
        # For now, accept any non-empty code
        if not unlock_code:
            raise ValidationError("Unlock code is required")

        expires = fields.Datetime.now() + timedelta(hours=hours)

        self.write({
            'emergency_unlock_enabled': True,
            'emergency_unlock_code': unlock_code,
            'emergency_unlock_expires': expires,
        })

        _logger.critical(
            f"⚠️⚠️⚠️  EMERGENCY UNLOCK ENABLED  ⚠️⚠️⚠️\n"
            f"All license checks bypassed until {expires}\n"
            f"This should only be used in emergency situations!"
        )

        self.env['license.log'].log_event(
            'system_error',
            f"Emergency unlock enabled (expires: {expires})",
            severity='critical',
            details=f"Unlock code: {unlock_code[:4]}***\nExpires: {expires}",
        )

    def disable_emergency_unlock(self):
        """Disable emergency unlock"""
        self.ensure_one()

        self.write({
            'emergency_unlock_enabled': False,
            'emergency_unlock_code': False,
            'emergency_unlock_expires': False,
        })

        _logger.warning("Emergency unlock disabled")

    def check_emergency_unlock_expired(self):
        """
        Check if emergency unlock has expired

        Returns:
            bool: True if emergency unlock is active and valid
        """
        self.ensure_one()

        if not self.emergency_unlock_enabled:
            return False

        if not self.emergency_unlock_expires:
            return True

        now = fields.Datetime.now()
        if now > self.emergency_unlock_expires:
            _logger.warning("Emergency unlock has expired - disabling")
            self.disable_emergency_unlock()
            return False

        return True

    # ========================================================================
    # UI ACTIONS
    # ========================================================================

    def action_reload_license(self):
        """Reload license information from file"""
        self.ensure_one()
        self.reload_license_info()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': 'License information reloaded',
                'type': 'success',
                'sticky': False,
            }
        }

    def action_run_validation(self):
        """Run manual license validation"""
        self.ensure_one()

        result = self.env['license.check'].verify_license(check_type='manual')

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'message': result['message'],
                'type': 'success' if result['valid'] else 'warning',
                'sticky': True,
            }
        }

    def action_view_recent_checks(self):
        """View recent license validation checks"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': 'Recent License Checks',
            'res_model': 'license.check',
            'view_mode': 'tree,form',
            'domain': [],
            'context': {},
            'limit': 50,
        }

    def action_view_violation_logs(self):
        """View recent license violations"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': 'License Violations',
            'res_model': 'license.log',
            'view_mode': 'tree,form',
            'domain': [('severity', 'in', ['error', 'critical'])],
            'context': {},
            'limit': 100,
        }
