"""
WebSocket consumers for SQL Attacker real-time scan progress.

Clients connect to ws://server/ws/sql_attacker/scan/<task_id>/
to receive live updates about payload testing and vulnerabilities.
"""

import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time SQL Attacker scan progress.

    Receives updates broadcast by :func:`~sql_attacker.websocket_notifier.send_scan_progress`
    and forwards them to the connected browser client.
    """

    async def connect(self):
        """Handle WebSocket connection."""
        self.task_id = self.scope["url_route"]["kwargs"]["task_id"]
        self.group_name = f"scan_{self.task_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        logger.info("SQL Attacker WebSocket connected for task %s", self.task_id)

        # Confirm connection to the client
        await self.send(
            text_data=json.dumps(
                {
                    "type": "connection",
                    "status": "connected",
                    "task_id": self.task_id,
                }
            )
        )

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        logger.info(
            "SQL Attacker WebSocket disconnected for task %s (code: %s)",
            self.task_id,
            close_code,
        )
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        """Handle messages from the client (reserved for future use)."""
        if text_data:
            try:
                data = json.loads(text_data)
                logger.debug("Received client message: %s", data)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON from client: %s", text_data)

    async def scan_update(self, event):
        """
        Forward a scan update event to the WebSocket client.

        This method is called automatically by the channel layer when a message
        of type ``scan_update`` is sent to the group.
        """
        payload = event.get("payload", {})
        await self.send(text_data=json.dumps(payload))
