"""
WebSocket Notifier for SQL Attacker

Provides helper utilities to broadcast real-time scan progress updates
to connected WebSocket clients via Django Channels.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _get_channel_layer():
    """Lazily import and return the Django Channels channel layer."""
    try:
        from channels.layers import get_channel_layer
        return get_channel_layer()
    except ImportError:
        logger.warning("Django Channels is not installed; WebSocket notifications disabled.")
        return None


def _run_async(coro):
    """Run a coroutine from synchronous code using asyncio."""
    import asyncio

    async def _safe_wrapper():
        try:
            await coro
        except Exception as exc:
            logger.warning("WebSocket notification failed: %s", exc)

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Schedule without blocking (fire-and-forget with error logging)
            loop.create_task(_safe_wrapper())
        else:
            loop.run_until_complete(_safe_wrapper())
    except RuntimeError:
        asyncio.run(_safe_wrapper())


# ---------------------------------------------------------------------------
# Public notification helpers
# ---------------------------------------------------------------------------

def send_scan_progress(
    task_id: str,
    current_payload: str,
    progress_percent: float,
    vulnerabilities_found: int,
    status: str = "running",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Broadcast a scan progress update to all WebSocket clients subscribed to
    the given ``task_id`` group.

    Args:
        task_id: Celery / scan task identifier.
        current_payload: The payload currently being tested.
        progress_percent: Progress percentage (0–100).
        vulnerabilities_found: Number of vulnerabilities found so far.
        status: Scan status string (running | complete | error).
        extra: Optional additional metadata to include in the message.
    """
    channel_layer = _get_channel_layer()
    if channel_layer is None:
        return

    group_name = f"scan_{task_id}"
    message: Dict[str, Any] = {
        "type": "scan_update",
        "payload": {
            "type": "progress",
            "task_id": task_id,
            "current_payload": current_payload,
            "progress_percent": progress_percent,
            "vulnerabilities_found": vulnerabilities_found,
            "status": status,
        },
    }
    if extra:
        message["payload"].update(extra)

    async def _send():
        await channel_layer.group_send(group_name, message)

    _run_async(_send())
    logger.debug("Sent scan progress update for task %s (%.1f%%)", task_id, progress_percent)


def send_vulnerability_found(
    task_id: str,
    vulnerability: Dict[str, Any],
) -> None:
    """
    Broadcast an instant vulnerability-found notification.

    Args:
        task_id: Task identifier.
        vulnerability: Dict describing the vulnerability.
    """
    channel_layer = _get_channel_layer()
    if channel_layer is None:
        return

    group_name = f"scan_{task_id}"
    message = {
        "type": "scan_update",
        "payload": {
            "type": "vulnerability_found",
            "task_id": task_id,
            "vulnerability": vulnerability,
        },
    }

    async def _send():
        await channel_layer.group_send(group_name, message)

    _run_async(_send())
    logger.info("Vulnerability found notification sent for task %s", task_id)


def send_scan_complete(
    task_id: str,
    summary: Dict[str, Any],
) -> None:
    """
    Broadcast a scan-complete notification.

    Args:
        task_id: Task identifier.
        summary: Summary dict with total findings, duration, etc.
    """
    channel_layer = _get_channel_layer()
    if channel_layer is None:
        return

    group_name = f"scan_{task_id}"
    message = {
        "type": "scan_update",
        "payload": {
            "type": "scan_complete",
            "task_id": task_id,
            "summary": summary,
        },
    }

    async def _send():
        await channel_layer.group_send(group_name, message)

    _run_async(_send())
    logger.info("Scan complete notification sent for task %s", task_id)


# ---------------------------------------------------------------------------
# Batch notifier helper
# ---------------------------------------------------------------------------

class ScanProgressNotifier:
    """
    Stateful helper that tracks scan progress and sends batched WebSocket
    updates to avoid flooding the channel layer.

    Usage::

        notifier = ScanProgressNotifier(task_id="abc123", total_payloads=100)
        for payload in payloads:
            # … test payload …
            notifier.update(payload, vulnerabilities_found=vulns)
        notifier.complete(summary)
    """

    def __init__(
        self,
        task_id: str,
        total_payloads: int,
        update_interval: int = 5,
    ) -> None:
        """
        Args:
            task_id: Task identifier.
            total_payloads: Total number of payloads to test.
            update_interval: Send a WebSocket update every N payloads.
        """
        self.task_id = task_id
        self.total_payloads = max(1, total_payloads)
        self.update_interval = max(1, update_interval)
        self._tested = 0
        self._vulnerabilities: List[Dict[str, Any]] = []

    def update(
        self,
        current_payload: str,
        vulnerabilities_found: int = 0,
        vulnerability: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a tested payload and optionally broadcast a progress update.

        Args:
            current_payload: Payload just tested.
            vulnerabilities_found: Running total of vulnerabilities.
            vulnerability: Optional dict for an instantly-notified finding.
        """
        self._tested += 1
        progress = (self._tested / self.total_payloads) * 100

        if vulnerability:
            self._vulnerabilities.append(vulnerability)
            send_vulnerability_found(self.task_id, vulnerability)

        if self._tested % self.update_interval == 0 or self._tested == self.total_payloads:
            send_scan_progress(
                task_id=self.task_id,
                current_payload=current_payload,
                progress_percent=progress,
                vulnerabilities_found=vulnerabilities_found,
            )

    def complete(self, summary: Optional[Dict[str, Any]] = None) -> None:
        """Send the scan-complete notification."""
        final_summary = summary or {
            "total_payloads_tested": self._tested,
            "vulnerabilities_found": len(self._vulnerabilities),
        }
        send_scan_complete(self.task_id, final_summary)
