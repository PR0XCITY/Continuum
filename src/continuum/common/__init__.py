"""Shared building blocks used by every other Continuum subpackage.

Responsibility: pydantic schemas for events, incidents and API payloads
(schemas.py), layered YAML plus environment config loading (config.py), and
a single structured logging setup that every entry point imports instead of
configuring logging itself (logging.py).

Nothing in this package may import from capture, detection, response,
connector, rag or dashboard. It is the dependency floor of the project.
"""

from continuum.common.config import (
    ConnectorSettings,
    DashboardSettings,
    DetectionSettings,
    LoggingSettings,
    RagSettings,
    ResponseSettings,
    Settings,
    get_settings,
    load_settings,
)
from continuum.common.schemas import (
    ActionTaken,
    AttackPattern,
    DetectionResult,
    DeviceInfo,
    FeatureWindow,
    IncidentRecord,
    KeyEvent,
    RecommendedFollowup,
)

__all__ = [
    "ActionTaken",
    "AttackPattern",
    "ConnectorSettings",
    "DashboardSettings",
    "DetectionResult",
    "DetectionSettings",
    "DeviceInfo",
    "FeatureWindow",
    "IncidentRecord",
    "KeyEvent",
    "LoggingSettings",
    "RagSettings",
    "RecommendedFollowup",
    "ResponseSettings",
    "Settings",
    "get_settings",
    "load_settings",
]
