"""
SQL Injection Web UI Module

A Flask-based web application for generating SQL injection payloads
with support for multiple DBMS types and injection contexts.

Components:
- sql_syntax_and_errors.py: Cheat sheet reference dictionary
- generate_sql_payloads.py: Payload generation utility
- app.py: Flask web application
- templates/index.html: Web UI frontend
"""

__version__ = '1.0.0'
__author__ = 'Megido Security Platform'

from .generate_sql_payloads import SQLPayloadGenerator, generate_payloads
from .sql_syntax_and_errors import SQL_CHEAT_SHEET, get_dbms_list, get_dbms_info

__all__ = [
    'SQLPayloadGenerator',
    'generate_payloads',
    'SQL_CHEAT_SHEET',
    'get_dbms_list',
    'get_dbms_info',
]
