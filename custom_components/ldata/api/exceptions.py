"""Exceptions for LDATA API."""

class TwoFactorRequired(Exception):
    """Raised when 2FA code is required."""

class LDATAAuthError(Exception):
    """Raised for authentication failures that require re-auth."""