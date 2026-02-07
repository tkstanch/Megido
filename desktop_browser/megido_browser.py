#!/usr/bin/env python3
"""
Megido Security - PyQt6 Browser with mitmproxy Integration

A modern desktop browser for the Megido security testing platform
with built-in traffic interception through mitmproxy.
"""

import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QToolBar, QStatusBar, QSplitter, QTabWidget,
    QMessageBox
)
from PyQt6.QtCore import QUrl, Qt, QTimer
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineSettings
from PyQt6.QtGui import QIcon, QAction
import requests


class MegidoBrowser(QMainWindow):
    """
    Main browser window with mitmproxy integration
    """
    
    def __init__(self, django_url="http://localhost:8000", proxy_port=8080):
        super().__init__()
        
        self.django_url = django_url
        self.proxy_port = proxy_port
        self.proxy_url = f"http://localhost:{proxy_port}"
        
        self.setWindowTitle("Megido Security - Desktop Browser")
        self.setGeometry(100, 100, 1400, 900)
        
        # Setup UI
        self.setup_ui()
        
        # Configure proxy
        self.configure_proxy()
        
        # Load home page
        self.navigate_home()
    
    def setup_ui(self):
        """Setup the user interface"""
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create toolbar
        self.create_toolbar()
        
        # Create navigation bar
        nav_layout = QHBoxLayout()
        
        # Back button
        self.back_btn = QPushButton("←")
        self.back_btn.setMaximumWidth(40)
        self.back_btn.clicked.connect(self.navigate_back)
        nav_layout.addWidget(self.back_btn)
        
        # Forward button
        self.forward_btn = QPushButton("→")
        self.forward_btn.setMaximumWidth(40)
        self.forward_btn.clicked.connect(self.navigate_forward)
        nav_layout.addWidget(self.forward_btn)
        
        # Reload button
        self.reload_btn = QPushButton("⟳")
        self.reload_btn.setMaximumWidth(40)
        self.reload_btn.clicked.connect(self.reload_page)
        nav_layout.addWidget(self.reload_btn)
        
        # Home button
        self.home_btn = QPushButton("⌂")
        self.home_btn.setMaximumWidth(40)
        self.home_btn.clicked.connect(self.navigate_home)
        nav_layout.addWidget(self.home_btn)
        
        # URL bar
        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        nav_layout.addWidget(self.url_bar)
        
        # Go button
        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.navigate_to_url)
        nav_layout.addWidget(self.go_btn)
        
        main_layout.addLayout(nav_layout)
        
        # Create splitter for browser and interceptor panel
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Browser view
        self.browser = QWebEngineView()
        self.browser.urlChanged.connect(self.update_url_bar)
        self.browser.loadProgress.connect(self.update_load_progress)
        
        # Enable developer tools
        settings = self.browser.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, True)
        
        splitter.addWidget(self.browser)
        
        # Interceptor panel (placeholder for now)
        self.interceptor_tabs = QTabWidget()
        self.interceptor_tabs.setMaximumWidth(400)
        
        # Request history tab
        from desktop_browser.widgets.interceptor_panel import InterceptorPanel
        self.interceptor_panel = InterceptorPanel(self.django_url)
        self.interceptor_tabs.addTab(self.interceptor_panel, "Interceptor")
        
        splitter.addWidget(self.interceptor_tabs)
        
        # Set initial sizes
        splitter.setSizes([1000, 400])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Connected to: {self.django_url} | Proxy: {self.proxy_url}")
    
    def create_toolbar(self):
        """Create application toolbar"""
        toolbar = QToolBar("Apps")
        self.addToolBar(toolbar)
        
        # Quick access to Megido apps
        apps = [
            ("Scanner", "scanner"),
            ("Spider", "spider"),
            ("SQL Attacker", "sql_attacker"),
            ("Repeater", "repeater"),
            ("Interceptor", "interceptor"),
            ("Mapper", "mapper"),
        ]
        
        for app_name, app_path in apps:
            action = QAction(app_name, self)
            action.triggered.connect(lambda checked, path=app_path: self.navigate_to_app(path))
            toolbar.addAction(action)
    
    def configure_proxy(self):
        """Configure browser to use mitmproxy"""
        try:
            profile = QWebEngineProfile.defaultProfile()
            profile.setHttpCacheType(QWebEngineProfile.CacheType.NoCache)
            
            # Set proxy
            from PyQt6.QtNetwork import QNetworkProxy
            proxy = QNetworkProxy()
            proxy.setType(QNetworkProxy.ProxyType.HttpProxy)
            proxy.setHostName("localhost")
            proxy.setPort(self.proxy_port)
            
            QNetworkProxy.setApplicationProxy(proxy)
            
            print(f"Browser configured to use proxy: {self.proxy_url}")
            
        except Exception as e:
            print(f"Warning: Could not configure proxy: {e}")
            QMessageBox.warning(
                self,
                "Proxy Configuration",
                f"Could not configure proxy. Traffic may not be intercepted.\n\nError: {e}"
            )
    
    def navigate_to_url(self):
        """Navigate to URL from address bar"""
        url = self.url_bar.text()
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        self.browser.setUrl(QUrl(url))
    
    def navigate_back(self):
        """Navigate back in history"""
        self.browser.back()
    
    def navigate_forward(self):
        """Navigate forward in history"""
        self.browser.forward()
    
    def reload_page(self):
        """Reload current page"""
        self.browser.reload()
    
    def navigate_home(self):
        """Navigate to home (Django app)"""
        self.browser.setUrl(QUrl(self.django_url))
    
    def navigate_to_app(self, app_path):
        """Navigate to a specific Megido app"""
        url = f"{self.django_url}/{app_path}/"
        self.browser.setUrl(QUrl(url))
    
    def update_url_bar(self, url):
        """Update URL bar when page changes"""
        self.url_bar.setText(url.toString())
        self.url_bar.setCursorPosition(0)
    
    def update_load_progress(self, progress):
        """Update status bar with load progress"""
        if progress < 100:
            self.status_bar.showMessage(f"Loading... {progress}%")
        else:
            self.status_bar.showMessage(f"Connected to: {self.django_url} | Proxy: {self.proxy_url}")
    
    def check_django_server(self):
        """Check if Django server is running"""
        try:
            response = requests.get(self.django_url, timeout=2)
            return response.status_code == 200
        except Exception:
            return False
    
    def check_proxy_server(self):
        """Check if mitmproxy is running"""
        try:
            # Try to connect to proxy
            proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            # Note: SSL verification is disabled here for testing with self-signed mitmproxy certs
            # This is acceptable for local development but should NOT be used in production
            # without proper certificate validation
            response = requests.get(
                "http://mitm.it",  # mitmproxy cert page
                proxies=proxies,
                timeout=2,
                verify=False  # Disable SSL verification for mitmproxy self-signed cert
            )
            return True
        except Exception:
            return False
    
    def show_cert_install_dialog(self):
        """Show dialog for installing mitmproxy certificate"""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("mitmproxy Certificate Installation")
        msg.setText("To intercept HTTPS traffic, you need to install the mitmproxy certificate.")
        msg.setInformativeText(
            "Steps:\n"
            "1. Navigate to http://mitm.it in this browser\n"
            "2. Download the certificate for your platform\n"
            "3. Install it as a trusted root certificate\n\n"
            "Would you like to open the certificate page now?"
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if msg.exec() == QMessageBox.StandardButton.Yes:
            self.browser.setUrl(QUrl("http://mitm.it"))


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Megido Security - Desktop Browser")
    parser.add_argument(
        '--django-url',
        default='http://localhost:8000',
        help='Django server URL (default: http://localhost:8000)'
    )
    parser.add_argument(
        '--proxy-port',
        type=int,
        default=8080,
        help='mitmproxy port (default: 8080)'
    )
    
    args = parser.parse_args()
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("Megido Security Browser")
    
    # Create and show browser
    browser = MegidoBrowser(args.django_url, args.proxy_port)
    
    # Check if servers are running
    if not browser.check_django_server():
        QMessageBox.warning(
            browser,
            "Django Server",
            f"Django server is not accessible at {args.django_url}.\n"
            "Please start it with: python manage.py runserver"
        )
    
    if not browser.check_proxy_server():
        reply = QMessageBox.question(
            browser,
            "mitmproxy",
            f"mitmproxy is not running on port {args.proxy_port}.\n"
            "Would you like to see certificate installation instructions?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            browser.show_cert_install_dialog()
    
    browser.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
