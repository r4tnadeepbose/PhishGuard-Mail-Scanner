"""Provider-agnostic integration contracts (optional, additive)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol


class IntegrationStatus(str, Enum):
    DISABLED = "disabled"
    READY = "ready"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


@dataclass
class IntegrationCapability:
    provider_id: str
    name: str
    kind: str  # ingestion, analyzer, case, export, notification
    supported_types: List[str] = field(default_factory=list)
    local_only: bool = False
    requires_network: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IntegrationResult:
    provider_id: str
    status: IntegrationStatus
    summary: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, IntegrationStatus) else str(self.status)
        return d


class IntegrationProvider(Protocol):
    capability: IntegrationCapability

    def is_configured(self) -> bool:
        ...

    def run(self, payload: Dict[str, Any]) -> IntegrationResult:
        ...
