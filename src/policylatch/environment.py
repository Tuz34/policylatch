"""Environment compatibility helpers for the PolicyLatch transition."""

from __future__ import annotations

import os
from collections.abc import Mapping


def windows_integration_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether opt-in Windows integration checks are enabled.

    The PolicyLatch variable is authoritative when both names are present. The
    legacy MCP_GUARD name remains available for one compatibility release.
    """

    values = os.environ if environ is None else environ
    configured = values.get("POLICYLATCH_WINDOWS_INTEGRATION")
    if configured is None:
        configured = values.get("MCP_GUARD_WINDOWS_INTEGRATION")
    return configured == "1"
