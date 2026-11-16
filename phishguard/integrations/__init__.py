"""Optional integration interfaces for PhishGuard.

All external integrations are optional and disabled by default. Core scanning must work
without them. The built-in local export provider is used by the GUI/CLI for case JSON.
Implementations should be original and avoid copying AGPL-licensed code.
"""

from .base import (
    IntegrationProvider,
    IntegrationCapability,
    IntegrationResult,
    IntegrationStatus,
)
from .local_export import LocalCaseExportProvider
from .null_providers import NullExportProvider
from .registry import DEFAULT_REGISTRY, ProviderRegistry, default_registry

__all__ = [
    "IntegrationProvider",
    "IntegrationCapability",
    "IntegrationResult",
    "IntegrationStatus",
    "LocalCaseExportProvider",
    "NullExportProvider",
    "ProviderRegistry",
    "DEFAULT_REGISTRY",
    "default_registry",
]
