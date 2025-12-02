"""
ITX Security Shield - Hardware Fingerprinting Library

Python wrapper for C-based hardware fingerprinting with comprehensive
error handling and exception management.
"""

from .verifier import ITXSecurityVerifier, HardwareInfo
from .exceptions import (
    ITXSecurityError,
    LibraryError,
    HardwareDetectionError,
    FingerprintError,
    PermissionError,
    PlatformError,
)

__version__ = '1.0.0'
__all__ = [
    'ITXSecurityVerifier',
    'HardwareInfo',
    'ITXSecurityError',
    'LibraryError',
    'HardwareDetectionError',
    'FingerprintError',
    'PermissionError',
    'PlatformError',
]
