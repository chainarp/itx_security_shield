# -*- coding: utf-8 -*-
"""
ITX Security Shield - License API Controllers
HTTP/JSON endpoints for license management and monitoring
"""

import json
import logging
from datetime import datetime

from odoo import http
from odoo.http import request, Response
from odoo.exceptions import ValidationError, AccessDenied

_logger = logging.getLogger(__name__)


class LicenseAPIController(http.Controller):
    """
    License Management API Endpoints

    Provides HTTP/JSON endpoints for:
    - License status and information
    - Manual validation triggers
    - Hardware information
    - Violation logs and statistics
    """

    # ========================================================================
    # PUBLIC ENDPOINTS (require authentication)
    # ========================================================================

    @http.route('/license/status', type='json', auth='user', methods=['GET', 'POST'])
    def get_license_status(self, **kwargs):
        """
        Get current license status

        Returns JSON with:
        - valid (bool): Whether license is currently valid
        - status (str): Status code
        - message (str): Human-readable status message
        - expiry_days (int): Days until expiry
        - grace_period (bool): Whether grace period is active
        - last_check (str): When license was last validated

        Example:
            curl -X POST http://localhost:8069/license/status \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {}}'

        Returns:
            {
                "valid": true,
                "status": "valid",
                "message": "License is valid",
                "expiry_days": 365,
                "grace_period": false,
                "last_check": "2025-12-02 10:30:00"
            }
        """
        try:
            # Get configuration
            config = request.env['license.config'].sudo().get_config()

            # Get most recent check
            recent_check = request.env['license.check'].sudo().search(
                [],
                order='check_date desc',
                limit=1
            )

            if not recent_check:
                return {
                    'valid': False,
                    'status': 'no_checks',
                    'message': 'No license validations have been performed yet',
                    'expiry_days': 0,
                    'grace_period': False,
                    'last_check': None,
                }

            # Check if grace period is active
            grace_active = config.grace_period_active and config.check_grace_period_expired()

            # Check if emergency unlock is active
            emergency_unlock = config.emergency_unlock_enabled and config.check_emergency_unlock_expired()

            response = {
                'valid': recent_check.status == 'valid' or grace_active or emergency_unlock,
                'status': recent_check.status,
                'message': recent_check.validation_message or 'No validation message',
                'expiry_days': recent_check.days_until_expiry,
                'grace_period': grace_active,
                'emergency_unlock': emergency_unlock,
                'last_check': recent_check.check_date.strftime('%Y-%m-%d %H:%M:%S') if recent_check.check_date else None,
            }

            _logger.info(f"License status request: {response['status']}")
            return response

        except Exception as e:
            _logger.exception(f"Error getting license status: {e}")
            return {
                'valid': False,
                'status': 'error',
                'message': f'Error retrieving license status: {str(e)}',
                'expiry_days': 0,
                'grace_period': False,
                'last_check': None,
            }

    @http.route('/license/info', type='json', auth='user', methods=['GET', 'POST'])
    def get_license_info(self, **kwargs):
        """
        Get detailed license information

        Returns JSON with:
        - hardware_fingerprint (str): Current hardware fingerprint
        - license_fingerprint (str): License hardware fingerprint
        - fingerprint_match (bool): Whether fingerprints match
        - expiry_date (str): License expiration date
        - days_until_expiry (int): Days remaining
        - licensed_addons (list): List of licensed addons
        - machine_info (dict): Hardware details
        - grace_period (dict): Grace period information

        Example:
            curl -X POST http://localhost:8069/license/info \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {}}'

        Returns:
            {
                "hardware_fingerprint": "a1b2c3...",
                "license_fingerprint": "a1b2c3...",
                "fingerprint_match": true,
                "expiry_date": "2026-12-01",
                "days_until_expiry": 365,
                "licensed_addons": ["itx_helloworld", "itx_security_shield"],
                "machine_info": {...},
                "grace_period": {...}
            }
        """
        try:
            # Get configuration
            config = request.env['license.config'].sudo().get_config()

            # Get most recent check
            recent_check = request.env['license.check'].sudo().search(
                [],
                order='check_date desc',
                limit=1
            )

            if not recent_check:
                return {
                    'error': 'No license information available',
                    'message': 'No license validations have been performed yet',
                }

            # Hardware information
            machine_info = {
                'machine_id': recent_check.machine_id,
                'cpu_model': recent_check.cpu_model,
                'cpu_cores': recent_check.cpu_cores,
                'mac_address': recent_check.mac_address,
                'is_docker': recent_check.is_docker,
                'is_vm': recent_check.is_vm,
            }

            # Grace period information
            grace_info = {
                'enabled': config.grace_period_enabled,
                'active': config.grace_period_active,
                'started': config.grace_period_started.strftime('%Y-%m-%d %H:%M:%S') if config.grace_period_started else None,
                'ends': config.grace_period_ends.strftime('%Y-%m-%d %H:%M:%S') if config.grace_period_ends else None,
                'reason': config.grace_period_reason,
            }

            response = {
                'hardware_fingerprint': recent_check.hardware_fingerprint,
                'license_fingerprint': recent_check.license_fingerprint,
                'fingerprint_match': recent_check.fingerprint_match,
                'expiry_date': recent_check.license_expiry.strftime('%Y-%m-%d') if recent_check.license_expiry else None,
                'days_until_expiry': recent_check.days_until_expiry,
                'licensed_addons': config.licensed_addons.split(',') if config.licensed_addons else [],
                'machine_info': machine_info,
                'grace_period': grace_info,
            }

            _logger.info("License info request completed")
            return response

        except Exception as e:
            _logger.exception(f"Error getting license info: {e}")
            return {
                'error': 'Error retrieving license information',
                'message': str(e),
            }

    @http.route('/license/hardware', type='json', auth='user', methods=['GET', 'POST'])
    def get_hardware_info(self, **kwargs):
        """
        Get current hardware information

        Returns JSON with complete hardware details from ITX Security library

        Example:
            curl -X POST http://localhost:8069/license/hardware \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {}}'

        Returns:
            {
                "machine_id": "abc123...",
                "cpu_model": "Intel(R) Core(TM) i7-9750H",
                "cpu_cores": 12,
                "mac_address": "00:11:22:33:44:55",
                "dmi_uuid": "xyz789...",
                "disk_uuid": "def456...",
                "is_docker": false,
                "is_vm": false,
                "is_debugger": false,
                "fingerprint": "sha256_hash..."
            }
        """
        try:
            # Import wrapper
            from ..lib import ITXSecurityVerifier
            from ..lib.exceptions import ITXSecurityError

            # Initialize verifier
            verifier = ITXSecurityVerifier(debug=False)

            # Get hardware info
            hw_info = verifier.get_hardware_info()

            # Get fingerprint
            fingerprint = verifier.get_fingerprint()
            hw_info['fingerprint'] = fingerprint

            _logger.info("Hardware info request completed")
            return hw_info

        except ITXSecurityError as e:
            _logger.error(f"ITX Security error: {e}")
            return {
                'error': 'Hardware detection failed',
                'message': str(e),
            }
        except Exception as e:
            _logger.exception(f"Error getting hardware info: {e}")
            return {
                'error': 'System error',
                'message': str(e),
            }

    @http.route('/license/verify', type='json', auth='user', methods=['POST'])
    def verify_license(self, **kwargs):
        """
        Trigger manual license verification

        Performs complete license validation and returns detailed results

        Example:
            curl -X POST http://localhost:8069/license/verify \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {}}'

        Returns:
            {
                "valid": true,
                "status": "valid",
                "message": "License validation successful",
                "check_id": 123,
                "grace_period": false,
                "timestamp": "2025-12-02 10:30:00"
            }
        """
        try:
            _logger.info("Manual license verification requested")

            # Run verification
            result = request.env['license.check'].sudo().verify_license(check_type='manual')

            # Add timestamp
            result['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            _logger.info(f"Manual verification completed: {result['status']}")
            return result

        except ValidationError as e:
            _logger.error(f"Validation error: {e}")
            return {
                'valid': False,
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        except Exception as e:
            _logger.exception(f"Error during verification: {e}")
            return {
                'valid': False,
                'status': 'error',
                'message': f'Verification failed: {str(e)}',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }

    @http.route('/license/violations', type='json', auth='user', methods=['GET', 'POST'])
    def get_violations(self, limit=50, **kwargs):
        """
        Get recent license violations

        Args:
            limit (int): Maximum number of violations to return (default: 50)

        Example:
            curl -X POST http://localhost:8069/license/violations \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {"limit": 20}}'

        Returns:
            {
                "count": 5,
                "violations": [
                    {
                        "event_type": "hardware_mismatch",
                        "severity": "error",
                        "message": "...",
                        "timestamp": "2025-12-02 10:00:00"
                    },
                    ...
                ]
            }
        """
        try:
            # Get recent violations
            violations = request.env['license.log'].sudo().get_recent_violations(limit=limit)

            violation_list = []
            for v in violations:
                violation_list.append({
                    'event_type': v.event_type,
                    'severity': v.severity,
                    'message': v.message,
                    'details': v.details,
                    'timestamp': v.create_date.strftime('%Y-%m-%d %H:%M:%S') if v.create_date else None,
                    'grace_period_active': v.grace_period_active,
                })

            return {
                'count': len(violation_list),
                'violations': violation_list,
            }

        except Exception as e:
            _logger.exception(f"Error getting violations: {e}")
            return {
                'count': 0,
                'violations': [],
                'error': str(e),
            }

    @http.route('/license/statistics', type='json', auth='user', methods=['GET', 'POST'])
    def get_statistics(self, days=30, **kwargs):
        """
        Get license validation statistics

        Args:
            days (int): Number of days to look back (default: 30)

        Example:
            curl -X POST http://localhost:8069/license/statistics \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {"days": 7}}'

        Returns:
            {
                "period_days": 30,
                "total_checks": 120,
                "total_violations": 5,
                "by_type": {
                    "hardware_mismatch": 2,
                    "file_tampered": 3
                },
                "config": {
                    "periodic_checks": true,
                    "check_interval": 6,
                    "grace_period": true
                }
            }
        """
        try:
            # Get configuration
            config = request.env['license.config'].sudo().get_config()

            # Get violation summary
            summary = request.env['license.log'].sudo().get_violation_summary(days=days)

            # Get total checks in period
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=days)

            total_checks = request.env['license.check'].sudo().search_count([
                ('check_date', '>=', cutoff_date)
            ])

            return {
                'period_days': days,
                'total_checks': total_checks,
                'total_violations': summary['total_violations'],
                'by_type': summary['by_type'],
                'config': {
                    'periodic_checks': config.periodic_check_enabled,
                    'check_interval': config.periodic_check_interval,
                    'grace_period': config.grace_period_enabled,
                    'grace_period_days': config.grace_period_days,
                    'file_integrity': config.file_integrity_enabled,
                },
            }

        except Exception as e:
            _logger.exception(f"Error getting statistics: {e}")
            return {
                'error': str(e),
            }

    # ========================================================================
    # ADMIN ENDPOINTS (require admin access)
    # ========================================================================

    @http.route('/license/admin/emergency_unlock', type='json', auth='user', methods=['POST'])
    def emergency_unlock(self, unlock_code, hours=24, **kwargs):
        """
        Enable emergency unlock (ADMIN ONLY - DANGEROUS)

        Bypasses all license checks for specified hours

        Args:
            unlock_code (str): Secret emergency unlock code
            hours (int): Hours to keep unlock active (default: 24)

        Example:
            curl -X POST http://localhost:8069/license/admin/emergency_unlock \\
                -H "Content-Type: application/json" \\
                -d '{"jsonrpc": "2.0", "method": "call", "params": {"unlock_code": "SECRET", "hours": 24}}'

        Returns:
            {
                "success": true,
                "message": "Emergency unlock enabled",
                "expires": "2025-12-03 10:00:00"
            }
        """
        try:
            # Check admin access
            if not request.env.user.has_group('base.group_system'):
                raise AccessDenied("Admin access required for emergency unlock")

            _logger.critical("⚠️  Emergency unlock requested by admin user")

            # Enable emergency unlock
            config = request.env['license.config'].sudo().get_config()
            config.enable_emergency_unlock(unlock_code, hours)

            return {
                'success': True,
                'message': 'Emergency unlock enabled',
                'expires': config.emergency_unlock_expires.strftime('%Y-%m-%d %H:%M:%S'),
            }

        except AccessDenied as e:
            _logger.warning(f"Unauthorized emergency unlock attempt: {e}")
            return {
                'success': False,
                'error': 'Access denied',
                'message': str(e),
            }
        except ValidationError as e:
            _logger.error(f"Emergency unlock validation error: {e}")
            return {
                'success': False,
                'error': 'Validation error',
                'message': str(e),
            }
        except Exception as e:
            _logger.exception(f"Error enabling emergency unlock: {e}")
            return {
                'success': False,
                'error': 'System error',
                'message': str(e),
            }

    @http.route('/license/admin/config', type='json', auth='user', methods=['GET', 'POST'])
    def get_config(self, **kwargs):
        """
        Get license configuration (ADMIN ONLY)

        Returns complete configuration including sensitive information

        Returns:
            {
                "license_file_path": "/opt/odoo19/production.lic",
                "license_file_exists": true,
                "grace_period_enabled": true,
                "periodic_check_enabled": true,
                ...
            }
        """
        try:
            # Check admin access
            if not request.env.user.has_group('base.group_system'):
                raise AccessDenied("Admin access required")

            config = request.env['license.config'].sudo().get_config()

            return {
                'license_file_path': config.license_file_path,
                'license_file_exists': config.license_file_exists,
                'license_installed': config.license_installed,
                'grace_period_enabled': config.grace_period_enabled,
                'grace_period_days': config.grace_period_days,
                'grace_period_active': config.grace_period_active,
                'periodic_check_enabled': config.periodic_check_enabled,
                'periodic_check_interval': config.periodic_check_interval,
                'file_integrity_enabled': config.file_integrity_enabled,
                'file_integrity_sample_pct': config.file_integrity_sample_pct,
                'startup_check_enabled': config.startup_check_enabled,
                'startup_check_blocking': config.startup_check_blocking,
                'emergency_unlock_enabled': config.emergency_unlock_enabled,
                'total_checks': config.total_checks,
                'total_violations': config.total_violations,
            }

        except AccessDenied as e:
            return {
                'error': 'Access denied',
                'message': str(e),
            }
        except Exception as e:
            _logger.exception(f"Error getting config: {e}")
            return {
                'error': 'System error',
                'message': str(e),
            }
