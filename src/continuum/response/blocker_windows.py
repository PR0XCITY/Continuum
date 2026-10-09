"""Device disable/enable via pnputil, with safety rails.

Responsibility: the only place in Continuum allowed to disable or
re-enable a physical HID device. Wraps pnputil device enable/disable calls
and enforces, before every disable:

    - never disable a device if doing so would leave zero enabled
      keyboards attached,
    - never disable a device on the configured allowlist,
    - schedule an automatic re-enable after the configured auto-release
      timeout,
    - provide a single release-everything operation that re-enables every
      device this module has disabled, callable at any time regardless of
      individual timeouts.

All pnputil and device-enumeration calls in this module must be mockable
so tests can run without touching real hardware or an elevated session.
"""
