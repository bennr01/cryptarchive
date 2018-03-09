"""error definitions."""

class AuthenticationError(Exception):
    """An Error to indication a problem with the authentication"""
    pass

class VersionError(Exception):
    """An Error to indication a problem with versions"""
    pass

class FileNotFound(Exception):
    """Exception raised when a file was not found."""
    pass
