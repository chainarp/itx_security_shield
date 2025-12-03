{
    'name': 'ITX Security Shield',
    'version': '19.0.1.0.0',
    'category': 'Security',
    'summary': 'Hardware-based License Protection and Fingerprinting',
    'description': """
ITX Security Shield - Hardware Fingerprinting & License Protection
==================================================================

Advanced hardware-based license protection system using C library for
secure hardware fingerprinting and addon license management.

Features:
---------
* Hardware fingerprinting (Machine ID, CPU, MAC, DMI UUID, Disk UUID)
* Docker and VM detection
* Debugger detection for anti-tampering
* Secure SHA-256 hardware fingerprints
* License validation and management
* Runtime integrity checking
* License Generator with hybrid RSA+AES encryption
* Automated hardware binding
* License file storage and management

Technical Details:
------------------
* Native C library for performance and security
* Python wrapper with comprehensive error handling
* Hybrid encryption (RSA-4096 + AES-256-GCM)
* Zero-overhead production builds
* Debug mode for troubleshooting

Security:
---------
* Hardware-bound licenses
* Anti-debugging protection
* Fingerprint-based validation
* Tamper detection
* RSA digital signatures for license authorization
* AES-256-GCM authenticated encryption

    """,
    'author': 'ITX Corporation',
    'website': 'https://www.itxcorp.com',
    'license': 'LGPL-3',
    'depends': ['base'],
    'external_dependencies': {
        'python': [],
        'bin': [],
    },
    'data': [
        # Security
        'security/ir.model.access.csv',
        # Views
        'views/license_check_views.xml',
        'views/license_log_views.xml',
        'views/license_config_views.xml',
        'views/license_generator_views.xml',
        'views/menu_views.xml',
    ],
    'demo': [],
    'installable': True,
    'application': True,
    'auto_install': False,
    'pre_init_hook': 'pre_init_hook',
    'post_init_hook': 'post_init_hook',
    'uninstall_hook': 'uninstall_hook',
}
