"""
Logging utilities for the proxy app.
Provides file-based logging and structured log management.
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class ProxyLogger:
    """Enhanced logger for proxy traffic with file-based storage"""
    
    def __init__(self, log_directory: str = 'logs/proxy'):
        """
        Initialize proxy logger
        
        Args:
            log_directory: Directory to store log files
        """
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Setup Python logger
        self.logger = logging.getLogger('proxy')
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Add file handler for general logs
        general_log = self.log_directory / 'proxy_general.log'
        file_handler = logging.FileHandler(general_log)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(file_handler)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(console_handler)
        
        # Create subdirectories for different log types
        (self.log_directory / 'requests').mkdir(exist_ok=True)
        (self.log_directory / 'responses').mkdir(exist_ok=True)
        (self.log_directory / 'websockets').mkdir(exist_ok=True)
        (self.log_directory / 'errors').mkdir(exist_ok=True)
        (self.log_directory / 'auth').mkdir(exist_ok=True)
    
    def log_request(self, request_data: Dict[str, Any]) -> str:
        """
        Log a request to structured file
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            Path to the log file created
        """
        timestamp = datetime.now()
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S_%f')
        
        # Create daily subdirectory
        daily_dir = self.log_directory / 'requests' / date_str
        daily_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename with timestamp and method
        method = request_data.get('method', 'UNKNOWN')
        filename = f"{time_str}_{method}.json"
        filepath = daily_dir / filename
        
        # Add timestamp to data
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'type': 'request',
            **request_data
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        self.logger.info(f"Request logged: {method} {request_data.get('url', 'N/A')}")
        return str(filepath)
    
    def log_response(self, response_data: Dict[str, Any]) -> str:
        """
        Log a response to structured file
        
        Args:
            response_data: Dictionary containing response information
            
        Returns:
            Path to the log file created
        """
        timestamp = datetime.now()
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S_%f')
        
        # Create daily subdirectory
        daily_dir = self.log_directory / 'responses' / date_str
        daily_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        status = response_data.get('status_code', 'UNKNOWN')
        filename = f"{time_str}_{status}.json"
        filepath = daily_dir / filename
        
        # Add timestamp to data
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'type': 'response',
            **response_data
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        self.logger.info(f"Response logged: {status} (Time: {response_data.get('response_time', 0)}ms)")
        return str(filepath)
    
    def log_websocket(self, ws_data: Dict[str, Any]) -> str:
        """
        Log a WebSocket message to structured file
        
        Args:
            ws_data: Dictionary containing WebSocket message information
            
        Returns:
            Path to the log file created
        """
        timestamp = datetime.now()
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S_%f')
        
        # Create connection-specific subdirectory
        conn_id = ws_data.get('connection_id', 'unknown')
        conn_dir = self.log_directory / 'websockets' / conn_id
        conn_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        direction = ws_data.get('direction', 'UNKNOWN')
        msg_type = ws_data.get('message_type', 'UNKNOWN')
        filename = f"{time_str}_{direction}_{msg_type}.json"
        filepath = conn_dir / filename
        
        # Add timestamp to data
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'type': 'websocket',
            **ws_data
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        self.logger.info(f"WebSocket message logged: {direction} {msg_type} on {conn_id}")
        return str(filepath)
    
    def log_error(self, error_data: Dict[str, Any]) -> str:
        """
        Log an error to structured file
        
        Args:
            error_data: Dictionary containing error information
            
        Returns:
            Path to the log file created
        """
        timestamp = datetime.now()
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S_%f')
        
        # Create daily subdirectory
        daily_dir = self.log_directory / 'errors' / date_str
        daily_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        error_type = error_data.get('error_type', 'UNKNOWN')
        filename = f"{time_str}_{error_type}.json"
        filepath = daily_dir / filename
        
        # Add timestamp to data
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'type': 'error',
            **error_data
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        self.logger.error(f"Error logged: {error_type} - {error_data.get('error_message', 'N/A')}")
        return str(filepath)
    
    def log_auth_attempt(self, auth_data: Dict[str, Any]) -> str:
        """
        Log an authentication attempt
        
        Args:
            auth_data: Dictionary containing authentication attempt information
            
        Returns:
            Path to the log file created
        """
        timestamp = datetime.now()
        date_str = timestamp.strftime('%Y%m%d')
        time_str = timestamp.strftime('%H%M%S_%f')
        
        # Create daily subdirectory
        daily_dir = self.log_directory / 'auth' / date_str
        daily_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        success = 'SUCCESS' if auth_data.get('success') else 'FAILED'
        filename = f"{time_str}_{success}.json"
        filepath = daily_dir / filename
        
        # Add timestamp to data
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'type': 'auth_attempt',
            **auth_data
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        self.logger.info(f"Auth attempt logged: {success} from {auth_data.get('source_ip', 'N/A')}")
        return str(filepath)
    
    def get_recent_logs(self, log_type: str = 'requests', limit: int = 100) -> list:
        """
        Get recent logs of a specific type
        
        Args:
            log_type: Type of logs to retrieve (requests, responses, errors, etc.)
            limit: Maximum number of logs to return
            
        Returns:
            List of log entries
        """
        log_dir = self.log_directory / log_type
        if not log_dir.exists():
            return []
        
        # Get all JSON files, sorted by modification time (newest first)
        log_files = []
        for root, dirs, files in os.walk(log_dir):
            for file in files:
                if file.endswith('.json'):
                    filepath = Path(root) / file
                    log_files.append(filepath)
        
        log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        log_files = log_files[:limit]
        
        # Read and parse log files
        logs = []
        for filepath in log_files:
            try:
                with open(filepath, 'r') as f:
                    logs.append(json.load(f))
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Failed to read log file {filepath}: {e}")
        
        return logs
    
    def cleanup_old_logs(self, days_to_keep: int = 30):
        """
        Remove log files older than specified days
        
        Args:
            days_to_keep: Number of days to keep logs
        """
        from datetime import timedelta
        cutoff_time = datetime.now() - timedelta(days=days_to_keep)
        cutoff_timestamp = cutoff_time.timestamp()
        
        removed_count = 0
        for root, dirs, files in os.walk(self.log_directory):
            for file in files:
                if file.endswith('.json'):
                    filepath = Path(root) / file
                    if filepath.stat().st_mtime < cutoff_timestamp:
                        try:
                            filepath.unlink()
                            removed_count += 1
                        except OSError as e:
                            self.logger.warning(f"Failed to remove old log {filepath}: {e}")
        
        self.logger.info(f"Cleanup completed: Removed {removed_count} old log files")
        return removed_count
