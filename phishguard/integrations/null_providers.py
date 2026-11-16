"""Built-in null/stub providers for testing and safe defaults."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from .base import IntegrationCapability, IntegrationProvider, IntegrationResult, IntegrationStatus


@dataclass
class NullExportProvider:
    capability: IntegrationCapability = None  # type: ignore

    def __post_init__(self):
        if self.capability is None:
            self.capability = IntegrationCapability(
                provider_id="phishguard.null_export",
                name="Null Export Provider",
                kind="export",
                supported_types=["case", "ioc", "report"],
                local_only=True,
                requires_network=False,
                description="No-op provider used when no external export integration is configured.",
            )

    def is_configured(self) -> bool:
        return False

    def run(self, payload: Dict[str, Any]) -> IntegrationResult:
        return IntegrationResult(
            provider_id=self.capability.provider_id,
            status=IntegrationStatus.SKIPPED,
            summary="No external export provider configured; local-only mode preserved.",
            data={"accepted": False, "payload_keys": sorted(list((payload or {}).keys()))},
        )
