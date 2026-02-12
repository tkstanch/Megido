"""
Real-Time Scan Streaming

Provides WebSocket and Server-Sent Events (SSE) support for live scan updates.
Allows clients to receive real-time progress updates during scans.
"""

import json
import logging
import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class ScanEventBus:
    """
    Event bus for broadcasting scan events to multiple listeners.
    
    Supports both synchronous and asynchronous event handlers.
    """
    
    def __init__(self):
        """Initialize the event bus"""
        self._listeners = defaultdict(list)
        self._scan_states = {}
    
    def subscribe(self, event_type: str, callback: Callable):
        """
        Subscribe to an event type.
        
        Args:
            event_type: Type of event (scan_started, scan_progress, scan_completed, etc.)
            callback: Function to call when event occurs
        """
        self._listeners[event_type].append(callback)
        logger.debug(f"Subscribed to {event_type}")
    
    def unsubscribe(self, event_type: str, callback: Callable):
        """
        Unsubscribe from an event type.
        
        Args:
            event_type: Type of event
            callback: Callback function to remove
        """
        if callback in self._listeners[event_type]:
            self._listeners[event_type].remove(callback)
    
    def emit(self, event_type: str, data: Dict[str, Any]):
        """
        Emit an event to all subscribers.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        scan_id = data.get('scan_id')
        
        # Update scan state
        if scan_id:
            if event_type == 'scan_started':
                self._scan_states[scan_id] = {
                    'status': 'running',
                    'started_at': datetime.now(),
                    'progress': 0,
                    'engines_completed': 0,
                    'total_engines': data.get('total_engines', 0)
                }
            elif event_type == 'engine_completed':
                if scan_id in self._scan_states:
                    self._scan_states[scan_id]['engines_completed'] += 1
                    total = self._scan_states[scan_id]['total_engines']
                    if total > 0:
                        self._scan_states[scan_id]['progress'] = \
                            (self._scan_states[scan_id]['engines_completed'] / total) * 100
            elif event_type == 'scan_completed':
                if scan_id in self._scan_states:
                    self._scan_states[scan_id]['status'] = 'completed'
                    self._scan_states[scan_id]['progress'] = 100
        
        # Notify all listeners
        event_data = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        for callback in self._listeners[event_type]:
            try:
                callback(event_data)
            except Exception as e:
                logger.error(f"Error in event callback: {e}", exc_info=True)
    
    def get_scan_state(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get current state of a scan"""
        return self._scan_states.get(scan_id)


# Global event bus instance
_event_bus = ScanEventBus()


def get_event_bus() -> ScanEventBus:
    """Get the global event bus instance"""
    return _event_bus


class SSEManager:
    """
    Server-Sent Events manager for streaming scan updates to web clients.
    
    Provides a simple way to push real-time updates to browsers without WebSockets.
    """
    
    def __init__(self):
        """Initialize SSE manager"""
        self.clients = {}  # scan_id -> list of response objects
    
    def register_client(self, scan_id: int, response):
        """
        Register a client for SSE updates.
        
        Args:
            scan_id: Scan ID to monitor
            response: HTTP response object (Django StreamingHttpResponse)
        """
        if scan_id not in self.clients:
            self.clients[scan_id] = []
        
        self.clients[scan_id].append(response)
        logger.info(f"Registered SSE client for scan {scan_id}")
    
    def unregister_client(self, scan_id: int, response):
        """Unregister a client"""
        if scan_id in self.clients and response in self.clients[scan_id]:
            self.clients[scan_id].remove(response)
    
    def send_event(self, scan_id: int, event_type: str, data: Dict[str, Any]):
        """
        Send event to all clients monitoring this scan.
        
        Args:
            scan_id: Scan ID
            event_type: Type of event
            data: Event data
        """
        if scan_id not in self.clients:
            return
        
        # Format SSE message
        message = self._format_sse_message(event_type, data)
        
        # Send to all clients
        for client in self.clients[scan_id]:
            try:
                client.write(message)
            except Exception as e:
                logger.error(f"Error sending SSE: {e}")
    
    def _format_sse_message(self, event_type: str, data: Dict[str, Any]) -> str:
        """Format data as SSE message"""
        json_data = json.dumps(data, default=str)
        return f"event: {event_type}\ndata: {json_data}\n\n"


# Global SSE manager
_sse_manager = SSEManager()


def get_sse_manager() -> SSEManager:
    """Get the global SSE manager instance"""
    return _sse_manager


class StreamingOrchestrator:
    """
    Enhanced orchestrator with real-time event streaming.
    
    Wraps the standard orchestrator to emit events during scan execution.
    """
    
    def __init__(self, orchestrator):
        """
        Initialize with base orchestrator.
        
        Args:
            orchestrator: Base EngineOrchestrator instance
        """
        self.orchestrator = orchestrator
        self.event_bus = get_event_bus()
    
    def run_scan_with_streaming(self, scan_id: int, target: str, **kwargs):
        """
        Run scan with real-time event streaming.
        
        Args:
            scan_id: Scan ID
            target: Target to scan
            **kwargs: Additional arguments for orchestrator
        
        Returns:
            Scan results
        """
        # Emit scan started event
        self.event_bus.emit('scan_started', {
            'scan_id': scan_id,
            'target': target,
            'total_engines': kwargs.get('engine_ids', [])
        })
        
        try:
            # Get engines to run
            from scanner.engine_plugins import get_engine_registry
            registry = get_engine_registry()
            
            engine_ids = kwargs.get('engine_ids')
            if engine_ids:
                total_engines = len(engine_ids)
            else:
                total_engines = len(registry.get_all_engines())
            
            self.event_bus.emit('scan_started', {
                'scan_id': scan_id,
                'target': target,
                'total_engines': total_engines
            })
            
            # Run scan
            results = self.orchestrator.run_scan(target, **kwargs)
            
            # Emit engine completion events
            for engine_result in results.get('engine_results', []):
                self.event_bus.emit('engine_completed', {
                    'scan_id': scan_id,
                    'engine_id': engine_result.engine_id,
                    'engine_name': engine_result.engine_name,
                    'success': engine_result.success,
                    'findings_count': len(engine_result.findings) if engine_result.success else 0
                })
            
            # Emit scan completed event
            summary = results.get('summary')
            self.event_bus.emit('scan_completed', {
                'scan_id': scan_id,
                'status': 'completed',
                'total_findings': summary.total_findings if summary else 0,
                'execution_time': summary.execution_time if summary else 0
            })
            
            return results
        
        except Exception as e:
            # Emit scan failed event
            self.event_bus.emit('scan_failed', {
                'scan_id': scan_id,
                'error': str(e)
            })
            raise


def create_sse_response(scan_id: int):
    """
    Create a Django StreamingHttpResponse for SSE.
    
    Args:
        scan_id: Scan ID to monitor
    
    Returns:
        Generator function for streaming
    """
    def event_generator():
        """Generate SSE events"""
        event_bus = get_event_bus()
        
        # Send initial connection message
        yield f"data: {json.dumps({'message': 'Connected', 'scan_id': scan_id})}\n\n"
        
        # Get initial state
        state = event_bus.get_scan_state(scan_id)
        if state:
            yield f"event: scan_progress\ndata: {json.dumps(state, default=str)}\n\n"
        
        # Setup event listener
        received_events = []
        
        def event_callback(event_data):
            if event_data['data'].get('scan_id') == scan_id:
                received_events.append(event_data)
        
        # Subscribe to all event types
        for event_type in ['scan_started', 'engine_completed', 'scan_completed', 'scan_failed']:
            event_bus.subscribe(event_type, event_callback)
        
        try:
            # Stream events as they arrive
            import time
            timeout = 300  # 5 minutes
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                # Check for new events
                if received_events:
                    event = received_events.pop(0)
                    yield f"event: {event['event_type']}\ndata: {json.dumps(event['data'], default=str)}\n\n"
                
                # Check if scan is complete
                state = event_bus.get_scan_state(scan_id)
                if state and state.get('status') == 'completed':
                    break
                
                time.sleep(0.5)  # Poll every 500ms
        
        finally:
            # Cleanup
            for event_type in ['scan_started', 'engine_completed', 'scan_completed', 'scan_failed']:
                event_bus.unsubscribe(event_type, event_callback)
    
    return event_generator


# WebSocket support (if channels is available)
try:
    from channels.generic.websocket import AsyncWebsocketConsumer
    
    class ScanWebSocketConsumer(AsyncWebsocketConsumer):
        """
        WebSocket consumer for real-time scan updates.
        
        Usage:
            ws://localhost:8000/ws/scans/<scan_id>/
        """
        
        async def connect(self):
            """Handle WebSocket connection"""
            self.scan_id = self.scope['url_route']['kwargs']['scan_id']
            self.room_group_name = f'scan_{self.scan_id}'
            
            # Join room group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            
            await self.accept()
            
            # Send initial state
            event_bus = get_event_bus()
            state = event_bus.get_scan_state(int(self.scan_id))
            
            if state:
                await self.send(text_data=json.dumps({
                    'type': 'scan_state',
                    'state': state
                }, default=str))
        
        async def disconnect(self, close_code):
            """Handle WebSocket disconnection"""
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        
        async def receive(self, text_data):
            """Handle messages from WebSocket"""
            pass
        
        async def scan_event(self, event):
            """Handle scan events from event bus"""
            await self.send(text_data=json.dumps(event))

except ImportError:
    # Channels not available
    logger.warning("Django Channels not available. WebSocket support disabled.")
    ScanWebSocketConsumer = None
