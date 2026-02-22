"""
Operation Modes
===============
Defines safe, bounded operation modes for the SQL injection testing engine.

Modes
-----
OperationMode.DETECT
    Passive detection only.  Payloads are sent and responses are analysed, but
    no data exfiltration or further exploitation is attempted.  This is the
    **default and safest** mode.

OperationMode.VERIFY
    Confirms a candidate finding by repeating the probe with benign controls.
    Still no data exfiltration; confirms reproducibility.

OperationMode.DEMONSTRATE
    Shows exploitability with a strictly bounded, redacted query.  The
    demonstration is limited to retrieving the database version string —
    a piece of information that proves exploitability without exfiltrating
    sensitive user/business data.  All retrieved content is redacted before
    being included in the report.

The :class:`ModePolicy` class encapsulates per-mode constraints so that engine
callers cannot accidentally escalate privileges.

Usage::

    from sql_attacker.engine.modes import OperationMode, ModePolicy

    policy = ModePolicy(OperationMode.DETECT)
    policy.assert_may_exfiltrate()  # → ModeViolationError
    policy.assert_may_verify()      # → ModeViolationError
    policy.assert_may_detect()      # → OK
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# OperationMode
# ---------------------------------------------------------------------------


class OperationMode(Enum):
    """Safe operation modes for the SQLi engine, ordered by invasiveness.

    Attributes
    ----------
    DETECT:
        Send probes and analyse responses for injection signals.  No
        exploitation, confirmation loops, or data retrieval.
    VERIFY:
        Repeat the best candidate probe and a benign control to confirm
        reproducibility.  No data exfiltration.
    DEMONSTRATE:
        Retrieve the database version string (only) to prove exploitability.
        All retrieved values are redacted before reporting.
    """

    DETECT = "detect"
    VERIFY = "verify"
    DEMONSTRATE = "demonstrate"

    @classmethod
    def from_string(cls, value: str) -> "OperationMode":
        """Parse a mode name (case-insensitive).

        Raises
        ------
        ValueError: If *value* is not a valid mode name.
        """
        try:
            return cls(value.lower().strip())
        except ValueError:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(
                f"Unknown operation mode '{value}'. Valid modes: {valid}"
            )


# ---------------------------------------------------------------------------
# ModeViolationError
# ---------------------------------------------------------------------------


class ModeViolationError(Exception):
    """Raised when an operation is not permitted under the current mode."""


# ---------------------------------------------------------------------------
# ModePolicy
# ---------------------------------------------------------------------------

# Privilege level for each mode (higher = more invasive)
_MODE_LEVEL: dict = {
    OperationMode.DETECT: 0,
    OperationMode.VERIFY: 1,
    OperationMode.DEMONSTRATE: 2,
}

# Human-readable capability labels for error messages
_MODE_CAPABILITIES: dict = {
    OperationMode.DETECT: "detection only",
    OperationMode.VERIFY: "detection + verification",
    OperationMode.DEMONSTRATE: "detection + verification + bounded demonstration",
}


class ModePolicy:
    """Encapsulates the constraints associated with an :class:`OperationMode`.

    Parameters
    ----------
    mode:
        The current operation mode.  Defaults to :attr:`OperationMode.DETECT`.
    max_demonstrate_bytes:
        Maximum number of bytes that may be retrieved (and redacted) in
        DEMONSTRATE mode.  Default: 128.
    redact_char:
        Character used to replace sensitive characters in demonstration output.
    """

    DEFAULT_MAX_DEMONSTRATE_BYTES: int = 128
    DEFAULT_REDACT_CHAR: str = "*"

    def __init__(
        self,
        mode: OperationMode = OperationMode.DETECT,
        max_demonstrate_bytes: int = DEFAULT_MAX_DEMONSTRATE_BYTES,
        redact_char: str = DEFAULT_REDACT_CHAR,
    ) -> None:
        self._mode = mode
        self._max_demonstrate_bytes = max(1, max_demonstrate_bytes)
        self._redact_char = redact_char

    @property
    def mode(self) -> OperationMode:
        """The active operation mode."""
        return self._mode

    # ------------------------------------------------------------------
    # Assertion helpers – call these before performing any privileged op
    # ------------------------------------------------------------------

    def assert_may_detect(self) -> None:
        """Assert that detection probes are permitted (always true)."""
        # Detection is always allowed; this method exists for symmetry
        # and future extensibility (e.g. a "passive-only" mode).
        pass

    def assert_may_verify(self) -> None:
        """Assert that verification loops are permitted.

        Raises
        ------
        ModeViolationError: If the current mode is DETECT.
        """
        if _MODE_LEVEL[self._mode] < _MODE_LEVEL[OperationMode.VERIFY]:
            raise ModeViolationError(
                f"Verification is not permitted in mode '{self._mode.value}'. "
                f"Use mode '{OperationMode.VERIFY.value}' or higher."
            )

    def assert_may_demonstrate(self) -> None:
        """Assert that bounded demonstration is permitted.

        Raises
        ------
        ModeViolationError: If the current mode is not DEMONSTRATE.
        """
        if _MODE_LEVEL[self._mode] < _MODE_LEVEL[OperationMode.DEMONSTRATE]:
            raise ModeViolationError(
                f"Demonstration is not permitted in mode '{self._mode.value}'. "
                f"Use mode '{OperationMode.DEMONSTRATE.value}'."
            )

    def assert_may_exfiltrate(self) -> None:
        """Assert that *unrestricted* data exfiltration is permitted.

        This method **always raises** :class:`ModeViolationError` regardless
        of the current mode, because unrestricted exfiltration is never
        allowed by this engine.
        """
        raise ModeViolationError(
            "Unrestricted data exfiltration is not permitted. "
            "The engine supports only bounded, redacted demonstrations "
            f"in mode '{OperationMode.DEMONSTRATE.value}'."
        )

    # ------------------------------------------------------------------
    # Boolean helpers
    # ------------------------------------------------------------------

    def may_detect(self) -> bool:
        """Return ``True`` when detection is allowed (always)."""
        return True

    def may_verify(self) -> bool:
        """Return ``True`` when verification is allowed."""
        return _MODE_LEVEL[self._mode] >= _MODE_LEVEL[OperationMode.VERIFY]

    def may_demonstrate(self) -> bool:
        """Return ``True`` when bounded demonstration is allowed."""
        return _MODE_LEVEL[self._mode] >= _MODE_LEVEL[OperationMode.DEMONSTRATE]

    # ------------------------------------------------------------------
    # Redaction helper
    # ------------------------------------------------------------------

    def redact(self, value: str, *, keep_prefix: int = 0) -> str:
        """Return a redacted version of *value*.

        Only the first *keep_prefix* characters are preserved; the remainder
        is replaced by the redact character followed by ``[REDACTED]``.  The
        total length is bounded by :attr:`max_demonstrate_bytes`.

        Parameters
        ----------
        value:
            The string to redact.
        keep_prefix:
            How many leading characters to keep (useful for showing the DB
            vendor name without revealing version details).  Defaults to 0
            (full redaction).
        """
        truncated = value[:self._max_demonstrate_bytes]
        if keep_prefix <= 0:
            return self._redact_char * min(len(truncated), 8) + "[REDACTED]"
        prefix = truncated[:keep_prefix]
        remainder_len = max(0, len(truncated) - keep_prefix)
        if remainder_len == 0:
            return prefix
        return prefix + self._redact_char * min(remainder_len, 8) + "[REDACTED]"

    @property
    def max_demonstrate_bytes(self) -> int:
        """Maximum bytes retrievable in DEMONSTRATE mode."""
        return self._max_demonstrate_bytes

    # ------------------------------------------------------------------
    # Description
    # ------------------------------------------------------------------

    def describe(self) -> str:
        """Return a human-readable description of the current policy."""
        caps = _MODE_CAPABILITIES[self._mode]
        return (
            f"OperationMode={self._mode.value} ({caps}), "
            f"max_demonstrate_bytes={self._max_demonstrate_bytes}"
        )

    def __repr__(self) -> str:
        return (
            f"ModePolicy(mode={self._mode!r}, "
            f"max_demonstrate_bytes={self._max_demonstrate_bytes})"
        )
