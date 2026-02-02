#!/usr/bin/env python3
"""
Megido Security - Desktop Application
Cross-platform desktop wrapper for the Django-based security testing platform
"""

import sys
import os
import threading
import time
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QMessageBox
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtCore import QUrl, QTimer
from PySide6.QtGui import QIcon
import django
from django.core.management import call_command
from django.core.wsgi import get_wsgi_application


class MegidoDesktopApp(QMainWindow):
    """Main desktop application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Megido Security - Web Security Testing Platform")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create web view
        self.web_view = QWebEngineView()
        layout.addWidget(self.web_view)
        
        # Start Django server in background thread
        self.django_thread = None
        self.server_port = 8000
        self.start_django_server()
        
        # Wait a moment for server to start, then load the app
        QTimer.singleShot(2000, self.load_app)
    
    def start_django_server(self):
        """Start Django development server in a background thread"""
        def run_server():
            try:
                # Set up Django
                os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'megido_security.settings')
                django.setup()
                
                # Run migrations
                call_command('migrate', '--noinput')
                
                # Start server
                from django.core.management.commands.runserver import Command as RunserverCommand
                server = RunserverCommand()
                server.handle(addrport=f'127.0.0.1:{self.server_port}', use_reloader=False, verbosity=0)
            except Exception as e:
                print(f"Error starting Django server: {e}")
        
        self.django_thread = threading.Thread(target=run_server, daemon=True)
        self.django_thread.start()
    
    def load_app(self):
        """Load the Django application in the web view"""
        url = f"http://127.0.0.1:{self.server_port}/"
        self.web_view.setUrl(QUrl(url))
    
    def closeEvent(self, event):
        """Handle application close event"""
        reply = QMessageBox.question(
            self, 
            'Exit Megido Security',
            'Are you sure you want to exit?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()


def main():
    """Main entry point for the desktop application"""
    app = QApplication(sys.argv)
    app.setApplicationName("Megido Security")
    app.setOrganizationName("Megido")
    
    # Create and show main window
    window = MegidoDesktopApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
