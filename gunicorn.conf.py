"""
Gunicorn Configuration for Megido Security Platform

This configuration is optimized for handling long-running exploit and scanning operations,
particularly for plugins like XSS that perform smart crawling and DOM-based exploitation.
"""

import multiprocessing

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
# For CPU-bound security scanning tasks (like XSS exploitation), use CPU cores
# without oversubscription to avoid context switching overhead
workers = multiprocessing.cpu_count() + 1
worker_class = "sync"
worker_connections = 1000

# Timeout settings
# CRITICAL: Extended timeout for long-running exploit operations
# XSS plugin's smart crawl, DOM simulation, and exploitation phases can take 2-5+ minutes
# depending on crawl depth, number of pages, and external site response times.
# Setting this to 300 seconds (5 minutes) prevents premature worker termination.
timeout = 300

# Graceful timeout for worker restart/shutdown
graceful_timeout = 30

# Keep-alive for persistent connections
keepalive = 5

# Server mechanics
daemon = False
pidfile = None
umask = 0o022  # Secure file permissions (0755 for directories, 0644 for files)
user = None
group = None
tmp_upload_dir = None

# Logging
errorlog = "-"
loglevel = "info"
accesslog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "megido_gunicorn"

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting Megido Security Platform with Gunicorn")
    server.log.info(f"Worker timeout set to {timeout} seconds for long-running exploits")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("Gunicorn server is ready. Accepting connections.")

def on_exit(server):
    """Called just before exiting Gunicorn."""
    server.log.info("Shutting down Megido Security Platform")

def worker_int(worker):
    """Called when a worker receives the SIGINT or SIGQUIT signal."""
    worker.log.info(f"Worker {worker.pid} received interrupt signal")

def worker_abort(worker):
    """Called when a worker times out (exceeds timeout setting)."""
    worker.log.warning(f"Worker {worker.pid} exceeded timeout of {timeout}s and will be restarted")
    worker.log.warning("This may indicate an exploit operation taking too long")
    worker.log.warning("Consider increasing timeout or moving to async background tasks")
