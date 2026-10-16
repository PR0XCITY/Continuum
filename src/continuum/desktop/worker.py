"""Run connector calls off the UI thread and hand the result back to it.

Every API call goes through run_async, so a slow answer from IncidentRAG
or a model training run never freezes the window. Results and errors
are delivered on the UI thread through a QObject relay that lives there,
which makes the cross-thread signal a queued connection.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from continuum.dashboard.api import ApiError

logger = logging.getLogger(__name__)

# Relays still waiting for their task, kept alive until it reports back.
_pending: set[_Relay] = set()


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)


class _Relay(QObject):
    def __init__(
        self,
        on_done: Callable[[Any], None],
        on_error: Callable[[str], None] | None,
    ) -> None:
        super().__init__()
        self._on_done = on_done
        self._on_error = on_error

    @Slot(object)
    def deliver(self, result: object) -> None:
        _pending.discard(self)
        self._on_done(result)

    @Slot(str)
    def fail(self, message: str) -> None:
        _pending.discard(self)
        if self._on_error is not None:
            self._on_error(message)


class _Task(QRunnable):
    def __init__(self, function: Callable[[], Any]) -> None:
        super().__init__()
        self.function = function
        self.signals = _Signals()

    def run(self) -> None:
        try:
            result = self.function()
        except ApiError as error:
            self.signals.failed.emit(str(error))
        except Exception as error:  # noqa: BLE001 - shown to the user, never swallowed silently
            logger.exception("background task failed")
            self.signals.failed.emit(f"Unexpected error: {error}")
        else:
            self.signals.done.emit(result)


def run_async(
    function: Callable[[], Any],
    on_done: Callable[[Any], None],
    on_error: Callable[[str], None] | None = None,
) -> None:
    """Run function on the thread pool; call on_done or on_error on the UI thread."""
    relay = _Relay(on_done, on_error)
    _pending.add(relay)
    task = _Task(function)
    task.signals.done.connect(relay.deliver)
    task.signals.failed.connect(relay.fail)
    QThreadPool.globalInstance().start(task)
