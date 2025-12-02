"""
ITX Security Shield - Python Wrapper for C Library

Provides a high-level Python interface to the hardware fingerprinting C library
with comprehensive error handling and exception management.
"""

import os
import sys
import ctypes
import platform
from pathlib import Path
from typing import Dict, Optional, Any

from .exceptions import (
    LibraryError,
    HardwareDetectionError,
    FingerprintError,
    PermissionError,
    PlatformError,
)


# C structure definition matching itx_hardware_info_t
class HardwareInfo(ctypes.Structure):
    """C structure for hardware information (must match C struct exactly!)."""
    _fields_ = [
        ("fingerprint", ctypes.c_char * 65),   # Added: fingerprint field first!
        ("machine_id", ctypes.c_char * 128),   # Fixed: 128 not 256
        ("cpu_model", ctypes.c_char * 256),    # Correct
        ("mac_address", ctypes.c_char * 32),   # Fixed: 32 not 64
        ("dmi_uuid", ctypes.c_char * 128),     # Fixed: 128 not 256
        ("disk_uuid", ctypes.c_char * 128),    # Fixed: 128 not 256
        ("cpu_cores", ctypes.c_int),           # Moved to correct position
        ("is_docker", ctypes.c_bool),          # Correct
        ("is_vm", ctypes.c_bool),              # Correct
        ("debugger_detected", ctypes.c_bool),  # Correct
    ]


class ITXSecurityVerifier:
    """
    Hardware fingerprinting and license verification interface.

    This class provides a Python wrapper around the C library for hardware
    detection and fingerprinting with comprehensive error handling.
    """

    # Constants from C library
    ITX_OK = 0
    ITX_ERROR = -1

    def __init__(self, library_path: Optional[str] = None, debug: bool = False):
        """
        Initialize the security verifier.

        Args:
            library_path: Path to libintegrity.so (auto-detected if None)
            debug: Enable debug logging in C library (requires debug build)

        Raises:
            LibraryError: If the C library cannot be loaded
            PlatformError: If running on an unsupported platform
        """
        self.debug = debug
        self._lib = None
        self._library_path = library_path

        # Set debug environment variable if requested
        if self.debug:
            os.environ['ITX_DEBUG'] = '1'
        else:
            os.environ.pop('ITX_DEBUG', None)

        # Check platform
        self._check_platform()

        # Load library
        self._load_library(library_path)

        # Configure function signatures
        self._configure_library()

    def _check_platform(self):
        """Check if running on a supported platform."""
        current_platform = platform.system()
        if current_platform != 'Linux':
            raise PlatformError(
                f"ITX Security Shield only supports Linux platforms",
                current_platform=current_platform
            )

    def _find_library(self) -> str:
        """
        Auto-detect library path.

        Returns:
            Path to libintegrity.so

        Raises:
            LibraryError: If library cannot be found
        """
        # Get the directory where this Python file is located
        current_dir = Path(__file__).parent.absolute()

        # Possible library locations
        search_paths = [
            # In native/ directory (Odoo addon structure)
            current_dir.parent / 'native' / 'libintegrity.so',
            # In same directory as this file
            current_dir / 'libintegrity.so',
            # In parent directory
            current_dir.parent / 'libintegrity.so',
            # System-wide installation
            Path('/usr/local/lib/libintegrity.so'),
            Path('/usr/lib/libintegrity.so'),
        ]

        for path in search_paths:
            if path.exists():
                return str(path)

        raise LibraryError(
            "Could not find libintegrity.so. Please ensure the C library is compiled.\n"
            f"Searched locations:\n" + "\n".join(f"  - {p}" for p in search_paths) +
            "\n\nTo compile the library, run:\n"
            "  cd native/\n"
            "  ./dev.sh prod"
        )

    def _load_library(self, library_path: Optional[str] = None):
        """
        Load the C library.

        Args:
            library_path: Path to libintegrity.so (auto-detected if None)

        Raises:
            LibraryError: If library cannot be loaded
        """
        try:
            # Determine library path
            if library_path is None:
                library_path = self._find_library()

            self._library_path = library_path

            # Load the library
            self._lib = ctypes.CDLL(library_path)

        except OSError as e:
            raise LibraryError(
                f"Failed to load native library: {e}\n"
                f"Library path: {library_path}\n"
                f"This may indicate:\n"
                f"  - Library not compiled (run: cd native/ && ./dev.sh prod)\n"
                f"  - Missing dependencies (check: ldd {library_path})\n"
                f"  - Architecture mismatch (32-bit vs 64-bit)\n"
                f"  - Missing libssl/libcrypto (install: apt-get install libssl-dev)",
                library_path=library_path
            ) from e

    def _configure_library(self):
        """Configure C function signatures."""
        try:
            # itx_get_hardware_info(itx_hardware_info_t *info) -> int
            self._lib.itx_get_hardware_info.argtypes = [ctypes.POINTER(HardwareInfo)]
            self._lib.itx_get_hardware_info.restype = ctypes.c_int

            # itx_get_fingerprint() -> char*
            self._lib.itx_get_fingerprint.argtypes = []
            self._lib.itx_get_fingerprint.restype = ctypes.c_char_p

            # itx_is_docker() -> int
            self._lib.itx_is_docker.argtypes = []
            self._lib.itx_is_docker.restype = ctypes.c_int

            # itx_is_vm() -> int
            self._lib.itx_is_vm.argtypes = []
            self._lib.itx_is_vm.restype = ctypes.c_int

            # itx_is_debugger() -> int
            self._lib.itx_is_debugger.argtypes = []
            self._lib.itx_is_debugger.restype = ctypes.c_int

        except AttributeError as e:
            raise LibraryError(
                f"Invalid library: missing required functions\n"
                f"Error: {e}\n"
                f"This may indicate:\n"
                f"  - Wrong library file\n"
                f"  - Corrupted compilation\n"
                f"  - Version mismatch\n"
                f"Please recompile the library: cd native/ && ./dev.sh prod",
                library_path=self._library_path
            ) from e

    def get_hardware_info(self) -> Dict[str, Any]:
        """
        Get comprehensive hardware information.

        Returns:
            Dictionary containing hardware information:
            {
                'machine_id': str,
                'cpu_model': str,
                'cpu_cores': int,
                'mac_address': str,
                'dmi_uuid': str,
                'disk_uuid': str,
                'is_docker': bool,
                'is_vm': bool,
                'debugger_detected': bool
            }

        Raises:
            HardwareDetectionError: If hardware information cannot be retrieved
            PermissionError: If insufficient permissions
        """
        try:
            # Allocate structure
            info = HardwareInfo()

            # Call C function
            result = self._lib.itx_get_hardware_info(ctypes.byref(info))

            if result != self.ITX_OK:
                raise HardwareDetectionError(
                    "Failed to retrieve hardware information from C library.\n"
                    "This may indicate:\n"
                    "  - Insufficient permissions (try: sudo)\n"
                    "  - Missing system files (/proc/cpuinfo, /sys/class/dmi/...)\n"
                    "  - Unsupported hardware platform\n"
                    "\nFor detailed debugging, run with debug=True:\n"
                    "  verifier = ITXSecurityVerifier(debug=True)"
                )

            # Convert to Python dict
            hw_dict = {
                'fingerprint': info.fingerprint.decode('utf-8'),  # Added: fingerprint field
                'machine_id': info.machine_id.decode('utf-8'),
                'cpu_model': info.cpu_model.decode('utf-8'),
                'cpu_cores': info.cpu_cores,
                'mac_address': info.mac_address.decode('utf-8'),
                'dmi_uuid': info.dmi_uuid.decode('utf-8'),
                'disk_uuid': info.disk_uuid.decode('utf-8'),
                'is_docker': info.is_docker,
                'is_vm': info.is_vm,
                'debugger_detected': info.debugger_detected,
            }

            # Check for 'unknown' values
            missing_fields = [
                key for key, value in hw_dict.items()
                if isinstance(value, str) and value == 'unknown'
            ]

            if missing_fields:
                raise HardwareDetectionError(
                    f"Some hardware information is unavailable: {', '.join(missing_fields)}\n"
                    f"This may affect fingerprint uniqueness and stability.\n"
                    f"Common causes:\n"
                    f"  - Insufficient permissions (some fields require root)\n"
                    f"  - Running in container or VM (limited hardware access)\n"
                    f"  - Unsupported hardware or platform\n"
                    f"\nFor detailed debugging, run with debug=True",
                    missing_fields=missing_fields
                )

            return hw_dict

        except ctypes.ArgumentError as e:
            raise HardwareDetectionError(
                f"Internal error: Invalid arguments to C function: {e}"
            ) from e
        except Exception as e:
            if isinstance(e, HardwareDetectionError):
                raise
            raise HardwareDetectionError(
                f"Unexpected error during hardware detection: {e}"
            ) from e

    def get_fingerprint(self) -> str:
        """
        Generate hardware fingerprint (SHA-256 hash).

        Returns:
            64-character hexadecimal fingerprint string

        Raises:
            FingerprintError: If fingerprint cannot be generated
            PermissionError: If insufficient permissions
        """
        try:
            # Call C function
            result = self._lib.itx_get_fingerprint()

            if result is None:
                raise FingerprintError(
                    "Failed to generate hardware fingerprint.\n"
                    "This should not happen if hardware info was collected successfully.\n"
                    "Please report this issue with debug output:\n"
                    "  verifier = ITXSecurityVerifier(debug=True)\n"
                    "  verifier.get_fingerprint()"
                )

            # Convert to Python string
            fingerprint = result.decode('utf-8')

            # Validate fingerprint format
            if len(fingerprint) != 64:
                raise FingerprintError(
                    f"Invalid fingerprint format: expected 64 characters, got {len(fingerprint)}"
                )

            return fingerprint

        except UnicodeDecodeError as e:
            raise FingerprintError(
                f"Failed to decode fingerprint from C library: {e}"
            ) from e
        except Exception as e:
            if isinstance(e, FingerprintError):
                raise
            raise FingerprintError(
                f"Unexpected error during fingerprint generation: {e}"
            ) from e

    def is_docker(self) -> bool:
        """
        Check if running inside a Docker container.

        Returns:
            True if running in Docker, False otherwise

        Raises:
            HardwareDetectionError: If detection fails
        """
        try:
            result = self._lib.itx_is_docker()
            return result == 1
        except Exception as e:
            raise HardwareDetectionError(
                f"Failed to detect Docker environment: {e}"
            ) from e

    def is_vm(self) -> bool:
        """
        Check if running inside a virtual machine.

        Returns:
            True if running in VM, False otherwise

        Raises:
            HardwareDetectionError: If detection fails
        """
        try:
            result = self._lib.itx_is_vm()
            return result == 1
        except Exception as e:
            raise HardwareDetectionError(
                f"Failed to detect VM environment: {e}"
            ) from e

    def is_debugger_attached(self) -> bool:
        """
        Check if a debugger is attached to the process.

        Returns:
            True if debugger detected, False otherwise

        Raises:
            HardwareDetectionError: If detection fails
        """
        try:
            result = self._lib.itx_is_debugger()
            return result == 1
        except Exception as e:
            raise HardwareDetectionError(
                f"Failed to detect debugger: {e}"
            ) from e

    def verify(self) -> Dict[str, Any]:
        """
        Comprehensive verification with all information.

        Returns:
            Dictionary containing:
            {
                'hardware': {...},      # Hardware information
                'fingerprint': str,     # Hardware fingerprint
                'environment': {        # Environment checks
                    'is_docker': bool,
                    'is_vm': bool,
                    'debugger_detected': bool
                }
            }

        Raises:
            ITXSecurityError: If verification fails
        """
        return {
            'hardware': self.get_hardware_info(),
            'fingerprint': self.get_fingerprint(),
            'environment': {
                'is_docker': self.is_docker(),
                'is_vm': self.is_vm(),
                'debugger_detected': self.is_debugger_attached(),
            }
        }

    def __repr__(self):
        return f"ITXSecurityVerifier(library_path='{self._library_path}', debug={self.debug})"
