"""
ITX Security Shield - Generated License Storage

Model for storing all generated license files.
"""

import base64
from odoo import models, fields, api
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)


class LicenseGenerated(models.Model):
    """Storage for generated license files."""

    _name = 'itxss.license.generated'
    _description = 'Generated Licenses'
    _order = 'create_date desc'
    _rec_name = 'customer_name'

    # ========================================================================
    # Fields
    # ========================================================================
    customer_name = fields.Char(
        string='Customer Name',
        required=True,
        index=True,
        help='Name of the customer or company'
    )
    po_number = fields.Char(
        string='PO Number',
        index=True,
        help='Purchase Order number'
    )
    contract_number = fields.Char(
        string='Contract Number',
        index=True,
        help='Contract reference number'
    )
    licensed_addons = fields.Text(
        string='Licensed Addons',
        help='Comma-separated list of licensed addons'
    )
    max_instances = fields.Integer(
        string='Max Instances',
        help='Maximum number of installations allowed'
    )
    hardware_fingerprint = fields.Char(
        string='Hardware Fingerprint',
        help='Bound hardware fingerprint (if any)'
    )

    # Dates
    issue_date = fields.Date(
        string='Issue Date',
        required=True,
        help='License issue date'
    )
    expiry_date = fields.Date(
        string='Expiry Date',
        required=True,
        help='License expiry date'
    )
    days_until_expiry = fields.Integer(
        string='Days Until Expiry',
        compute='_compute_days_until_expiry',
        store=False
    )
    is_expired = fields.Boolean(
        string='Expired',
        compute='_compute_is_expired',
        store=False
    )

    # License file
    license_file = fields.Binary(
        string='License File',
        required=True,
        attachment=True,
        help='Encrypted license file (RSA+AES)'
    )
    license_filename = fields.Char(
        string='Filename',
        required=True
    )
    file_size = fields.Integer(
        string='File Size (bytes)',
        help='Size of encrypted license file'
    )

    # Metadata
    state = fields.Selection([
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
    ], string='State', default='active', required=True)

    notes = fields.Text(string='Notes')

    # ========================================================================
    # Computed Fields
    # ========================================================================
    @api.depends('expiry_date')
    def _compute_days_until_expiry(self):
        """Calculate days until license expires."""
        today = fields.Date.today()
        for record in self:
            if record.expiry_date:
                delta = (record.expiry_date - today).days
                record.days_until_expiry = delta
            else:
                record.days_until_expiry = 0

    @api.depends('expiry_date')
    def _compute_is_expired(self):
        """Check if license is expired."""
        today = fields.Date.today()
        for record in self:
            record.is_expired = record.expiry_date < today if record.expiry_date else False

    # ========================================================================
    # Actions
    # ========================================================================
    def action_download_license(self):
        """Download the license file."""
        self.ensure_one()

        if not self.license_file:
            raise UserError('No license file available!')

        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content?model=itxss.license.generated&id={self.id}&field=license_file&filename={self.license_filename}&download=true',
            'target': 'self',
        }

    def action_view_details(self):
        """View decrypted license details."""
        self.ensure_one()

        try:
            from ..tools.license_crypto import decrypt_license_hybrid

            # Decrypt license
            license_data_bytes = base64.b64decode(self.license_file)
            license_data = decrypt_license_hybrid(license_data_bytes)

            # Format details for display
            details = []
            details.append("=== License Details ===\n")
            details.append(f"Customer: {license_data.customer_name}")
            details.append(f"PO Number: {license_data.po_number}")
            details.append(f"Contract: {license_data.contract_number}")
            details.append(f"Contact: {license_data.contact_email}")
            details.append("")
            details.append(f"Licensed Addons: {', '.join(license_data.licensed_addons)}")
            details.append(f"Max Instances: {license_data.max_instances}")
            details.append(f"Concurrent Users: {license_data.concurrent_users or 'unlimited'}")
            details.append("")
            details.append(f"Issue Date: {license_data.issue_date}")
            details.append(f"Expiry Date: {license_data.expiry_date}")
            details.append(f"Grace Period: {license_data.grace_period_days} days")
            details.append(f"Maintenance Until: {license_data.maintenance_until or 'N/A'}")
            details.append("")

            if license_data.registered_instances:
                details.append(f"Registered Instances ({len(license_data.registered_instances)}):")
                for inst in license_data.registered_instances:
                    details.append(f"  - Instance #{inst['instance_id']}: {inst['hostname']}")
                    details.append(f"    Machine ID: {inst['machine_id']}")
                    details.append(f"    Fingerprint: {inst['hardware_fingerprint'][:32]}...")
                    details.append(f"    Status: {inst['status']}")
                    details.append("")

            details.append(f"License Type: {license_data.license_type}")
            details.append(f"Version: {license_data.version}")
            details.append(f"Notes: {license_data.notes}")

            details_text = '\n'.join(details)

            return {
                'name': 'License Details',
                'type': 'ir.actions.act_window',
                'res_model': 'itxss.license.details.wizard',
                'view_mode': 'form',
                'target': 'new',
                'context': {'default_details': details_text}
            }

        except Exception as e:
            raise UserError(f'Failed to decrypt license: {str(e)}')

    def action_revoke(self):
        """Revoke license."""
        self.ensure_one()
        self.write({'state': 'revoked'})
        _logger.info(f"License revoked for customer: {self.customer_name}")

    def action_activate(self):
        """Reactivate license."""
        self.ensure_one()
        self.write({'state': 'active'})
        _logger.info(f"License reactivated for customer: {self.customer_name}")

    # ========================================================================
    # Cron Jobs
    # ========================================================================
    @api.model
    def cron_update_expired_licenses(self):
        """Cron job to update expired licenses state."""
        today = fields.Date.today()
        expired_licenses = self.search([
            ('expiry_date', '<', today),
            ('state', '=', 'active')
        ])

        if expired_licenses:
            expired_licenses.write({'state': 'expired'})
            _logger.info(f"Updated {len(expired_licenses)} licenses to expired state")


class LicenseDetailsWizard(models.TransientModel):
    """Wizard to display license details."""

    _name = 'itxss.license.details.wizard'
    _description = 'License Details'

    details = fields.Text(
        string='License Details',
        readonly=True
    )
