# -*- coding: utf-8 -*-
"""
ITX Security Shield - License Event Logging
Tracks all license validation events, violations, and warnings
"""

import logging
from datetime import datetime

from odoo import models, fields, api
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class LicenseLog(models.Model):
    """
    License Event Logging

    Records all license-related events for audit trail:
    - Validation checks (startup, periodic, manual)
    - Violations (hardware mismatch, expiry, tampering)
    - Warnings (approaching expiry, grace period)
    - System events (license installation, updates)
    """

    _name = 'license.log'
    _description = 'ITX License Event Log'
    _order = 'create_date desc'
    _rec_name = 'event_type'

    # ========================================================================
    # FIELDS
    # ========================================================================

    event_type = fields.Selection(
        [
            # Validation events
            ('check_success', 'Validation Success'),
            ('check_warning', 'Validation Warning'),
            ('check_failure', 'Validation Failure'),

            # Violation events
            ('hardware_mismatch', 'Hardware Mismatch'),
            ('license_expired', 'License Expired'),
            ('file_tampered', 'File Tampering Detected'),

            # Warning events
            ('expiry_warning', 'Expiry Warning'),
            ('grace_period_start', 'Grace Period Started'),
            ('grace_period_end', 'Grace Period Ended'),

            # System events
            ('license_installed', 'License Installed'),
            ('license_updated', 'License Updated'),
            ('license_removed', 'License Removed'),

            # Error events
            ('library_error', 'C Library Error'),
            ('system_error', 'System Error'),
        ],
        string='Event Type',
        required=True,
        index=True,
    )

    severity = fields.Selection(
        [
            ('info', 'Info'),
            ('warning', 'Warning'),
            ('error', 'Error'),
            ('critical', 'Critical'),
        ],
        string='Severity',
        required=True,
        default='info',
        index=True,
    )

    message = fields.Text(
        string='Message',
        required=True,
        help='Human-readable event message',
    )

    details = fields.Text(
        string='Technical Details',
        help='Technical details, stack traces, debugging information',
    )

    # Related license check (if applicable)
    license_check_id = fields.Many2one(
        'license.check',
        string='Related License Check',
        ondelete='set null',
        index=True,
    )

    # Hardware information at time of event
    hardware_fingerprint = fields.Char(
        string='Hardware Fingerprint',
        help='SHA-256 fingerprint at time of event',
    )

    machine_id = fields.Char(string='Machine ID')
    is_docker = fields.Boolean(string='Docker Environment')
    is_vm = fields.Boolean(string='VM Environment')

    # User information
    user_id = fields.Many2one(
        'res.users',
        string='User',
        default=lambda self: self.env.user,
        help='User who triggered the event (if manual)',
    )

    # Additional context
    check_type = fields.Selection(
        [
            ('startup', 'Startup'),
            ('periodic', 'Periodic (Cron)'),
            ('manual', 'Manual'),
            ('file_hash', 'File Hash Check'),
        ],
        string='Check Type',
        help='Type of check that generated this event',
    )

    files_affected = fields.Text(
        string='Affected Files',
        help='List of files affected (for tampering events)',
    )

    grace_period_active = fields.Boolean(
        string='Grace Period Active',
        default=False,
        help='Whether grace period was active during this event',
    )

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    @api.model
    def log_event(self, event_type, message, severity='info', details=None, **kwargs):
        """
        Create a log entry

        Args:
            event_type (str): Event type (must match selection values)
            message (str): Human-readable message
            severity (str): Severity level ('info', 'warning', 'error', 'critical')
            details (str, optional): Technical details
            **kwargs: Additional field values (license_check_id, hardware_fingerprint, etc.)

        Returns:
            license.log: Created log record

        Example:
            self.env['license.log'].log_event(
                'hardware_mismatch',
                'Hardware fingerprint does not match license',
                severity='error',
                details='Expected: abc123..., Got: def456...',
                license_check_id=check.id,
                hardware_fingerprint='def456...',
            )
        """
        # Prepare values
        values = {
            'event_type': event_type,
            'message': message,
            'severity': severity,
            'details': details,
        }

        # Add any additional fields from kwargs
        for key, value in kwargs.items():
            if key in self._fields:
                values[key] = value

        # Create log record
        log_record = self.create(values)

        # Also log to Python logger
        logger_method = getattr(_logger, severity, _logger.info)
        logger_method(f"[LICENSE] {event_type.upper()}: {message}")

        if details:
            _logger.debug(f"[LICENSE] Details: {details}")

        return log_record

    @api.model
    def log_check_success(self, check_id, message="License validation successful"):
        """Log successful validation"""
        return self.log_event(
            'check_success',
            message,
            severity='info',
            license_check_id=check_id,
        )

    @api.model
    def log_check_warning(self, check_id, message, details=None):
        """Log validation warning"""
        return self.log_event(
            'check_warning',
            message,
            severity='warning',
            details=details,
            license_check_id=check_id,
        )

    @api.model
    def log_check_failure(self, check_id, message, details=None):
        """Log validation failure"""
        return self.log_event(
            'check_failure',
            message,
            severity='error',
            details=details,
            license_check_id=check_id,
        )

    @api.model
    def log_hardware_mismatch(self, check_id, current_fp, license_fp):
        """Log hardware mismatch violation"""
        return self.log_event(
            'hardware_mismatch',
            f"Hardware fingerprint mismatch detected",
            severity='error',
            details=f"Current fingerprint: {current_fp}\nLicense fingerprint: {license_fp}",
            license_check_id=check_id,
            hardware_fingerprint=current_fp,
        )

    @api.model
    def log_license_expired(self, check_id, expiry_date):
        """Log license expiration violation"""
        return self.log_event(
            'license_expired',
            f"License expired on {expiry_date}",
            severity='error',
            details=f"Expiry date: {expiry_date}\nCurrent date: {fields.Date.today()}",
            license_check_id=check_id,
        )

    @api.model
    def log_file_tampering(self, check_id, modified_files):
        """Log file tampering detection"""
        files_list = '\n'.join(modified_files) if isinstance(modified_files, list) else modified_files

        return self.log_event(
            'file_tampered',
            f"File tampering detected: {len(modified_files) if isinstance(modified_files, list) else 'unknown'} files modified",
            severity='critical',
            details=f"Modified files:\n{files_list}",
            license_check_id=check_id,
            files_affected=files_list,
        )

    @api.model
    def log_expiry_warning(self, check_id, days_left):
        """Log approaching expiry warning"""
        return self.log_event(
            'expiry_warning',
            f"License expires in {days_left} days",
            severity='warning',
            license_check_id=check_id,
        )

    @api.model
    def log_grace_period_start(self, check_id, violation_type, grace_ends):
        """Log grace period activation"""
        return self.log_event(
            'grace_period_start',
            f"Grace period started due to {violation_type}. Ends: {grace_ends}",
            severity='warning',
            details=f"Violation type: {violation_type}\nGrace period ends: {grace_ends}",
            license_check_id=check_id,
            grace_period_active=True,
        )

    @api.model
    def log_grace_period_end(self, check_id):
        """Log grace period expiration"""
        return self.log_event(
            'grace_period_end',
            "Grace period has expired - license violations will now block operation",
            severity='critical',
            license_check_id=check_id,
        )

    @api.model
    def log_license_installed(self, fingerprint, expiry_date):
        """Log license installation"""
        return self.log_event(
            'license_installed',
            f"New license installed (expires: {expiry_date})",
            severity='info',
            details=f"Hardware fingerprint: {fingerprint}\nExpiry date: {expiry_date}",
            hardware_fingerprint=fingerprint,
        )

    @api.model
    def log_library_error(self, error_message, details=None):
        """Log C library error"""
        return self.log_event(
            'library_error',
            f"ITX Security library error: {error_message}",
            severity='error',
            details=details,
        )

    @api.model
    def log_system_error(self, error_message, details=None):
        """Log system error"""
        return self.log_event(
            'system_error',
            f"System error during license validation: {error_message}",
            severity='error',
            details=details,
        )

    # ========================================================================
    # REPORTING METHODS
    # ========================================================================

    @api.model
    def get_recent_violations(self, limit=50):
        """
        Get recent license violations

        Args:
            limit (int): Maximum number of records to return

        Returns:
            recordset: Recent violation records
        """
        violation_types = [
            'hardware_mismatch',
            'license_expired',
            'file_tampered',
            'check_failure',
        ]

        return self.search(
            [('event_type', 'in', violation_types)],
            order='create_date desc',
            limit=limit,
        )

    @api.model
    def get_violation_summary(self, days=30):
        """
        Get summary of violations in last N days

        Args:
            days (int): Number of days to look back

        Returns:
            dict: Summary with counts by violation type
        """
        from datetime import timedelta

        cutoff_date = datetime.now() - timedelta(days=days)

        violations = self.search([
            ('create_date', '>=', cutoff_date),
            ('severity', 'in', ['error', 'critical']),
        ])

        summary = {}
        for violation in violations:
            event_type = violation.event_type
            if event_type not in summary:
                summary[event_type] = 0
            summary[event_type] += 1

        return {
            'period_days': days,
            'total_violations': len(violations),
            'by_type': summary,
        }

    @api.model
    def cleanup_old_logs(self, days=90):
        """
        Clean up old log entries

        Args:
            days (int): Delete logs older than this many days

        Returns:
            int: Number of deleted records
        """
        from datetime import timedelta

        cutoff_date = datetime.now() - timedelta(days=days)

        old_logs = self.search([
            ('create_date', '<', cutoff_date),
            ('severity', '=', 'info'),  # Only delete info logs
        ])

        count = len(old_logs)
        old_logs.unlink()

        _logger.info(f"Cleaned up {count} old license log entries (older than {days} days)")
        return count

    # ========================================================================
    # UI ACTIONS
    # ========================================================================

    def action_view_related_check(self):
        """View related license check record"""
        self.ensure_one()

        if not self.license_check_id:
            return {'type': 'ir.actions.act_window_close'}

        return {
            'type': 'ir.actions.act_window',
            'name': 'License Check',
            'res_model': 'license.check',
            'res_id': self.license_check_id.id,
            'view_mode': 'form',
            'target': 'new',
        }
