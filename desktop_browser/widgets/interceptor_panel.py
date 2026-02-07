"""
Interceptor Panel Widget for Desktop Browser
Displays real-time intercepted requests/responses
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTableWidget, QTableWidgetItem, QLabel, QComboBox,
    QHeaderView, QMessageBox
)
from PyQt6.QtCore import QTimer, Qt
import requests


class InterceptorPanel(QWidget):
    """
    Panel showing intercepted requests in real-time
    """
    
    def __init__(self, django_url, parent=None):
        super().__init__(parent)
        
        self.django_url = django_url
        self.api_url = f"{django_url}/interceptor/api"
        self.last_request_id = 0
        
        self.setup_ui()
        
        # Setup auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_requests)
        self.refresh_timer.start(2000)  # Refresh every 2 seconds
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("<b>Intercepted Requests</b>")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.clicked.connect(self.refresh_requests)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        filter_label = QLabel("App:")
        filter_layout.addWidget(filter_label)
        
        self.app_filter = QComboBox()
        self.app_filter.addItems([
            "All",
            "browser",
            "scanner",
            "spider",
            "sql_attacker",
            "repeater",
            "mapper"
        ])
        self.app_filter.currentTextChanged.connect(self.refresh_requests)
        filter_layout.addWidget(self.app_filter)
        
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Requests table
        self.requests_table = QTableWidget()
        self.requests_table.setColumnCount(4)
        self.requests_table.setHorizontalHeaderLabels(["Method", "URL", "Status", "Time"])
        
        # Configure table
        header = self.requests_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        self.requests_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.requests_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.requests_table.itemDoubleClicked.connect(self.show_request_detail)
        
        layout.addWidget(self.requests_table)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(self.status_label)
    
    def refresh_requests(self):
        """Refresh the list of intercepted requests"""
        try:
            # Build URL with filters
            url = f"{self.api_url}/history/"
            params = {}
            
            app_filter = self.app_filter.currentText()
            if app_filter != "All":
                params['source_app'] = app_filter
            
            # Fetch requests
            response = requests.get(url, params=params, timeout=5)
            
            if response.status_code == 200:
                requests_data = response.json()
                self.update_table(requests_data)
                self.status_label.setText(f"Last updated: {self.get_current_time()}")
            else:
                self.status_label.setText(f"Error: HTTP {response.status_code}")
                
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)[:50]}")
    
    def update_table(self, requests_data):
        """Update the requests table with new data"""
        # Store current selection
        current_row = self.requests_table.currentRow()
        
        # Clear table
        self.requests_table.setRowCount(0)
        
        # Add requests
        for idx, req in enumerate(requests_data[:50]):  # Limit to 50 most recent
            row = self.requests_table.rowCount()
            self.requests_table.insertRow(row)
            
            # Method
            method_item = QTableWidgetItem(req.get('method', 'GET'))
            self.requests_table.setItem(row, 0, method_item)
            
            # URL (truncated)
            url = req.get('url', '')
            if len(url) > 60:
                url = url[:60] + "..."
            url_item = QTableWidgetItem(url)
            url_item.setData(Qt.ItemDataRole.UserRole, req)  # Store full data
            self.requests_table.setItem(row, 1, url_item)
            
            # Status (check if response exists)
            status_item = QTableWidgetItem("-")
            self.requests_table.setItem(row, 2, status_item)
            
            # Time
            timestamp = req.get('timestamp', '')
            if timestamp:
                # Format timestamp
                from datetime import datetime
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime('%H:%M:%S')
                except Exception:
                    time_str = timestamp[:8]
            else:
                time_str = ""
            
            time_item = QTableWidgetItem(time_str)
            self.requests_table.setItem(row, 3, time_item)
        
        # Restore selection
        if current_row >= 0 and current_row < self.requests_table.rowCount():
            self.requests_table.selectRow(current_row)
    
    def show_request_detail(self, item):
        """Show detailed view of a request"""
        row = item.row()
        url_item = self.requests_table.item(row, 1)
        
        if url_item:
            req_data = url_item.data(Qt.ItemDataRole.UserRole)
            
            if req_data:
                # Show details in a message box (could be improved with a custom dialog)
                details = (
                    f"Method: {req_data.get('method', 'N/A')}\n"
                    f"URL: {req_data.get('url', 'N/A')}\n"
                    f"Source App: {req_data.get('source_app', 'N/A')}\n"
                    f"Timestamp: {req_data.get('timestamp', 'N/A')}\n\n"
                    f"Headers:\n{self.format_headers(req_data.get('headers', {}))}"
                )
                
                QMessageBox.information(self, "Request Details", details)
    
    def format_headers(self, headers):
        """Format headers dictionary for display"""
        if not headers:
            return "None"
        
        lines = []
        for key, value in headers.items():
            lines.append(f"  {key}: {value}")
        
        return "\n".join(lines[:10])  # Limit to 10 headers
    
    def get_current_time(self):
        """Get current time as string"""
        from datetime import datetime
        return datetime.now().strftime('%H:%M:%S')
