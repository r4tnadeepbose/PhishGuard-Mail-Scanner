"""Local-only export providers.

These providers never contact the network. They exist so the GUI/CLI can use the same
provider contract for local case/report export that future opt-in integrations would use.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from .base import IntegrationCapability, IntegrationResult, IntegrationStatus


@dataclass
class LocalCaseExportProvider:
    """Write an investigation case to a local JSON file."""

    capability: IntegrationCapability = None  # type: ignore

    def __post_init__(self):
        if self.capability is None:
            self.capability = IntegrationCapability(
                provider_id="phishguard.local_case_export",
                name="Local Case JSON Export",
                kind="export",
                supported_types=["case"],
                local_only=True,
                requires_network=False,
                description="Writes investigation cases to a local JSON file. No data leaves the machine.",
            )

    def is_configured(self) -> bool:
        return True

    def run(self, payload: Dict[str, Any]) -> IntegrationResult:
        case = (payload or {}).get("case")
        path = (payload or {}).get("path")
        if not case or not path:
            return IntegrationResult(
                provider_id=self.capability.provider_id,
                status=IntegrationStatus.FAILED,
                summary="Case export requires both 'case' and 'path'.",
                errors=["missing case or path"],
            )
        try:
            text = json.dumps(case, indent=2, ensure_ascii=False)
            p = Path(str(path))
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
        except Exception as exc:
            return IntegrationResult(
                provider_id=self.capability.provider_id,
                status=IntegrationStatus.FAILED,
                summary="Failed to write local case JSON.",
                errors=[str(exc)],
            )
        return IntegrationResult(
            provider_id=self.capability.provider_id,
            status=IntegrationStatus.SUCCEEDED,
            summary=f"Case exported locally to {p}",
            data={"path": str(p), "bytes": len(text.encode("utf-8"))},
        )
