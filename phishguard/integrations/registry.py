"""Small provider registry used by the GUI and CLI for local export actions."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .base import IntegrationCapability, IntegrationProvider, IntegrationResult, IntegrationStatus
from .local_export import LocalCaseExportProvider
from .null_providers import NullExportProvider


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: Dict[str, IntegrationProvider] = {}

    def register(self, provider: IntegrationProvider) -> None:
        self._providers[provider.capability.provider_id] = provider

    def get(self, provider_id: str) -> Optional[IntegrationProvider]:
        return self._providers.get(provider_id)

    def providers(self) -> Iterable[IntegrationProvider]:
        return self._providers.values()

    def capabilities(self) -> List[IntegrationCapability]:
        return [p.capability for p in self._providers.values()]

    def export_case(self, case: dict, path: str) -> IntegrationResult:
        provider = self.get("phishguard.local_case_export")
        if provider is None:
            return IntegrationResult(
                provider_id="phishguard.local_case_export",
                status=IntegrationStatus.DISABLED,
                summary="Local case export provider is not registered.",
            )
        return provider.run({"case": case, "path": path})


def default_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(NullExportProvider())
    registry.register(LocalCaseExportProvider())
    return registry


DEFAULT_REGISTRY = default_registry()
