"""
ITX Security Shield - Custom Exceptions

Exception hierarchy for hardware fingerprinting and license validation.
"""


class ITXSecurityError(Exception):
    """Base exception for all ITX Security Shield errors."""
    pass


class LibraryError(ITXSecurityError):
    """Raised when the native C library cannot be loaded or initialized."""

    def __init__(self, message, library_path=None):
        self.library_path = library_path
        super().__init__(message)

    def __str__(self):
        if self.library_path:
            return f"{super().__str__()} (Library path: {self.library_path})"
        return super().__str__()


class HardwareDetectionError(ITXSecurityError):
    """Raised when hardware information cannot be retrieved."""

    def __init__(self, message, missing_fields=None):
        self.missing_fields = missing_fields or []
        super().__init__(message)

    def __str__(self):
        base_msg = super().__str__()
        if self.missing_fields:
            return f"{base_msg} (Missing: {', '.join(self.missing_fields)})"
        return base_msg


class FingerprintError(ITXSecurityError):
    """Raised when hardware fingerprint cannot be generated."""
    pass


class PermissionError(ITXSecurityError):
    """Raised when insufficient permissions to access hardware information."""

    def __init__(self, message, required_permissions=None):
        self.required_permissions = required_permissions or []
        super().__init__(message)

    def __str__(self):
        base_msg = super().__str__()
        if self.required_permissions:
            return f"{base_msg} (Required: {', '.join(self.required_permissions)})"
        return base_msg


class PlatformError(ITXSecurityError):
    """Raised when running on an unsupported platform."""

    def __init__(self, message, current_platform=None):
        self.current_platform = current_platform
        super().__init__(message)

    def __str__(self):
        if self.current_platform:
            return f"{super().__str__()} (Current platform: {self.current_platform})"
        return super().__str__()
