"""PhishGuard Mail Scanner package."""

from .scanner import scan_email, scan_email_file, ScanResult, Finding

__all__ = ["scan_email", "scan_email_file", "ScanResult", "Finding"]
