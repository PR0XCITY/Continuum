"""What every page needs: the API client, settings and a way to switch pages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from continuum.common.config import Settings
from continuum.dashboard.api import ConnectorClient


@dataclass
class AppContext:
    client: ConnectorClient
    settings: Settings
    # Switch to the Ask page with this question filled in.
    ask_about: Callable[[str], None] = field(default=lambda question: None)
    # Start the elevated runtime (shows the Windows prompt).
    start_protection: Callable[[], None] = field(default=lambda: None)
