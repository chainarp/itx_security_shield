"""ITX Security Shield - Hardware-based License Protection"""

from . import models
from . import controllers
from . import lib

import logging
_logger = logging.getLogger(__name__)


def pre_init_hook(env):
    """
    Pre-initialization hook.
    Called before the module is installed.
    """
    _logger.info("ITX Security Shield: Starting pre-installation checks...")

    try:
        from .lib import ITXSecurityVerifier

        # Test library loading
        verifier = ITXSecurityVerifier()
        _logger.info("✓ Native C library loaded successfully")

        # Test hardware detection
        fingerprint = verifier.get_fingerprint()
        _logger.info(f"✓ Hardware fingerprint: {fingerprint[:16]}...")

        _logger.info("ITX Security Shield: Pre-installation checks passed")

    except Exception as e:
        _logger.error(f"ITX Security Shield: Pre-installation check failed: {e}")
        _logger.warning("The module will still install, but license verification may not work")


def post_init_hook(env):
    """
    Post-initialization hook.
    Called after the module is installed.
    """
    _logger.info("ITX Security Shield: Post-installation setup...")

    try:
        from .lib import ITXSecurityVerifier

        verifier = ITXSecurityVerifier()
        hw_info = verifier.get_hardware_info()

        _logger.info("=" * 60)
        _logger.info("ITX Security Shield - Hardware Information")
        _logger.info("=" * 60)
        _logger.info(f"Machine ID:    {hw_info['machine_id']}")
        _logger.info(f"CPU Model:     {hw_info['cpu_model']}")
        _logger.info(f"CPU Cores:     {hw_info['cpu_cores']}")
        _logger.info(f"MAC Address:   {hw_info['mac_address']}")
        _logger.info(f"DMI UUID:      {hw_info['dmi_uuid']}")
        _logger.info(f"Disk UUID:     {hw_info['disk_uuid']}")
        _logger.info(f"Docker:        {'YES' if hw_info['is_docker'] else 'NO'}")
        _logger.info(f"VM:            {'YES' if hw_info['is_vm'] else 'NO'}")
        _logger.info(f"Debugger:      {'DETECTED!' if hw_info['debugger_detected'] else 'None'}")
        _logger.info(f"Fingerprint:   {verifier.get_fingerprint()}")
        _logger.info("=" * 60)

        _logger.info("✓ ITX Security Shield installed successfully")

    except Exception as e:
        _logger.error(f"ITX Security Shield: Post-installation setup failed: {e}")


def uninstall_hook(env):
    """
    Uninstallation hook.
    Called when the module is uninstalled.
    """
    _logger.info("ITX Security Shield: Module uninstalled")
