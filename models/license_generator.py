"""
ITX Security Shield - License Generator

Wizard for generating encrypted license files with hybrid RSA+AES encryption.
"""

import base64
import os
import tempfile
from datetime import datetime, timedelta
from odoo import models, fields, api
from odoo.exceptions import UserError, ValidationError
import logging

_logger = logging.getLogger(__name__)


class LicenseGenerator(models.TransientModel):
    """Wizard for generating license files."""

    _name = 'itxss.license.generator'
    _description = 'License Generator'

    # ========================================================================
    # Customer Information
    # ========================================================================
    customer_name = fields.Char(
        string='Customer Name',
        required=True,
        help='Name of the customer or company'
    )
    po_number = fields.Char(
        string='PO Number',
        help='Purchase Order number'
    )
    contract_number = fields.Char(
        string='Contract Number',
        help='Contract reference number'
    )
    contact_email = fields.Char(
        string='Contact Email',
        help='Customer contact email'
    )
    contact_phone = fields.Char(
        string='Contact Phone',
        help='Customer contact phone number'
    )

    # ========================================================================
    # License Rights
    # ========================================================================
    licensed_addons = fields.Text(
        string='Licensed Addons',
        required=True,
        default='',
        help='Comma-separated list of addon names (e.g., itx_helloworld, itx_sales)'
    )
    max_instances = fields.Integer(
        string='Max Instances',
        required=True,
        default=1,
        help='Maximum number of installations allowed'
    )
    concurrent_users = fields.Integer(
        string='Concurrent Users',
        default=0,
        help='Maximum concurrent users (0 = unlimited)'
    )

    # ========================================================================
    # Dates & Validity
    # ========================================================================
    issue_date = fields.Date(
        string='Issue Date',
        default=fields.Date.today,
        required=True,
        help='License issue date'
    )
    expiry_date = fields.Date(
        string='Expiry Date',
        required=True,
        help='License expiry date'
    )
    grace_period_days = fields.Integer(
        string='Grace Period (Days)',
        default=30,
        help='Days after expiry before enforcement'
    )
    maintenance_until = fields.Date(
        string='Maintenance Until',
        help='Support/maintenance end date'
    )

    # ========================================================================
    # Hardware Binding
    # ========================================================================
    bind_hardware = fields.Boolean(
        string='Bind to Current Hardware',
        default=True,
        help='Automatically bind license to current machine hardware'
    )

    # ========================================================================
    # RSA Key Upload
    # ========================================================================
    private_key_file = fields.Binary(
        string='Private Key File',
        help='Upload RSA private key (PEM format). This authorizes license creation.'
    )
    private_key_filename = fields.Char(string='Key Filename')
    private_key_passphrase = fields.Char(
        string='Key Passphrase',
        help='Passphrase for encrypted private key (leave empty if not encrypted)'
    )

    # ========================================================================
    # Generated License (Result)
    # ========================================================================
    license_generated = fields.Boolean(
        string='License Generated',
        default=False,
        readonly=True
    )
    license_file = fields.Binary(
        string='Generated License File',
        readonly=True,
        attachment=True
    )
    license_filename = fields.Char(
        string='License Filename',
        readonly=True
    )
    generation_log = fields.Text(
        string='Generation Log',
        readonly=True
    )

    # ========================================================================
    # Validation
    # ========================================================================
    @api.constrains('max_instances')
    def _check_max_instances(self):
        for record in self:
            if record.max_instances < 1:
                raise ValidationError('Max instances must be at least 1')

    @api.constrains('expiry_date', 'issue_date')
    def _check_expiry_date(self):
        for record in self:
            if record.expiry_date and record.issue_date:
                if record.expiry_date <= record.issue_date:
                    raise ValidationError('Expiry date must be after issue date')

    @api.constrains('grace_period_days')
    def _check_grace_period(self):
        for record in self:
            if record.grace_period_days < 0:
                raise ValidationError('Grace period cannot be negative')

    # ========================================================================
    # Actions
    # ========================================================================
    def action_generate_license(self):
        """Generate license file with hybrid encryption."""
        self.ensure_one()

        try:
            # Import license tools
            from ..tools.license_format import LicenseData, InstanceInfo
            from ..tools.license_crypto import encrypt_license_hybrid
            from ..lib.verifier import get_hardware_info

            log_lines = []
            log_lines.append(f"=== License Generation Started ===")
            log_lines.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            log_lines.append(f"Customer: {self.customer_name}")
            log_lines.append("")

            # Validate private key is provided
            if not self.private_key_file:
                raise UserError('Private key file is required to generate license!')

            # Save private key to temporary file
            key_temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
            try:
                key_data = base64.b64decode(self.private_key_file)
                key_temp_file.write(key_data)
                key_temp_file.close()
                private_key_path = key_temp_file.name

                log_lines.append(f"✓ Private key loaded: {len(key_data)} bytes")

                # Collect hardware information if binding enabled
                registered_instances = []
                if self.bind_hardware:
                    log_lines.append("")
                    log_lines.append("Collecting hardware information...")

                    hw_info = get_hardware_info()

                    log_lines.append(f"  - Machine ID: {hw_info.get('machine_id', 'N/A')}")
                    log_lines.append(f"  - CPU: {hw_info.get('cpu_model', 'N/A')[:50]}...")
                    log_lines.append(f"  - MAC: {hw_info.get('mac_address', 'N/A')}")
                    log_lines.append(f"  - Fingerprint: {hw_info.get('fingerprint', 'N/A')[:16]}...")

                    instance = InstanceInfo(
                        instance_id=1,
                        hardware_fingerprint=hw_info.get('fingerprint', ''),
                        machine_id=hw_info.get('machine_id', ''),
                        hostname=os.uname().nodename,
                        registered_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        status='active',
                    )
                    registered_instances.append(instance.to_dict())
                    log_lines.append(f"✓ Hardware binding enabled (1 instance registered)")
                else:
                    log_lines.append("⚠ Hardware binding disabled (not recommended)")

                # Parse addon list
                addons = [a.strip() for a in self.licensed_addons.split(',') if a.strip()]
                if not addons:
                    raise UserError('At least one addon must be specified!')

                log_lines.append("")
                log_lines.append(f"Licensed addons: {', '.join(addons)}")
                log_lines.append(f"Max instances: {self.max_instances}")
                log_lines.append(f"Concurrent users: {self.concurrent_users or 'unlimited'}")

                # Create license data
                license_data = LicenseData(
                    customer_name=self.customer_name,
                    po_number=self.po_number or '',
                    contract_number=self.contract_number or '',
                    contact_email=self.contact_email or '',
                    contact_phone=self.contact_phone or '',
                    licensed_addons=addons,
                    max_instances=self.max_instances,
                    concurrent_users=self.concurrent_users,
                    registered_instances=registered_instances,
                    issue_date=self.issue_date.strftime('%Y-%m-%d'),
                    expiry_date=self.expiry_date.strftime('%Y-%m-%d'),
                    grace_period_days=self.grace_period_days,
                    maintenance_until=self.maintenance_until.strftime('%Y-%m-%d') if self.maintenance_until else '',
                    license_type='production',
                    license_version='1.0',
                    features={
                        'hardware_binding': self.bind_hardware,
                        'file_integrity_check': False,
                        'debug_detection': False,
                    },
                )

                log_lines.append("")
                log_lines.append("Encrypting license with hybrid RSA+AES...")

                # Encrypt license
                passphrase = self.private_key_passphrase.encode('utf-8') if self.private_key_passphrase else None
                encrypted_data = encrypt_license_hybrid(
                    license_data,
                    private_key_path=private_key_path,
                    private_key_passphrase=passphrase
                )

                log_lines.append(f"✓ License encrypted: {len(encrypted_data)} bytes")
                log_lines.append(f"  - Encryption: Hybrid (RSA-4096 + AES-256-GCM)")
                log_lines.append(f"  - File format: ODLI v1.0")

                # Save to model
                filename = f"{self.customer_name.replace(' ', '_')}_license.lic"
                self.write({
                    'license_generated': True,
                    'license_file': base64.b64encode(encrypted_data),
                    'license_filename': filename,
                    'generation_log': '\n'.join(log_lines) + '\n\n✓ License generation completed successfully!'
                })

                log_lines.append("")
                log_lines.append("=== Generation Successful ===")

                # Create permanent record
                self.env['itxss.license.generated'].create({
                    'customer_name': self.customer_name,
                    'po_number': self.po_number,
                    'contract_number': self.contract_number,
                    'licensed_addons': ', '.join(addons),
                    'max_instances': self.max_instances,
                    'hardware_fingerprint': hw_info.get('fingerprint', '') if self.bind_hardware else '',
                    'issue_date': self.issue_date,
                    'expiry_date': self.expiry_date,
                    'license_file': base64.b64encode(encrypted_data),
                    'license_filename': filename,
                    'file_size': len(encrypted_data),
                })

                _logger.info(f"License generated successfully for {self.customer_name}")

                # Return to same form to show result
                return {
                    'type': 'ir.actions.act_window',
                    'res_model': 'itxss.license.generator',
                    'res_id': self.id,
                    'view_mode': 'form',
                    'target': 'new',
                }

            finally:
                # Clean up temp file
                try:
                    os.unlink(private_key_path)
                except:
                    pass

        except Exception as e:
            _logger.error(f"License generation failed: {e}", exc_info=True)
            raise UserError(f'License generation failed: {str(e)}')

    def action_download_license(self):
        """Download generated license file."""
        self.ensure_one()

        if not self.license_file:
            raise UserError('No license file to download!')

        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content?model=itxss.license.generator&id={self.id}&field=license_file&filename={self.license_filename}&download=true',
            'target': 'self',
        }

    def action_reset(self):
        """Reset wizard for new generation."""
        self.ensure_one()
        self.write({
            'license_generated': False,
            'license_file': False,
            'license_filename': False,
            'generation_log': False,
        })
        return {'type': 'ir.actions.act_window_close'}
