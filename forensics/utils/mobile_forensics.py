"""Mobile forensics utilities."""
import sqlite3
import os


def analyze_android_backup(file_path: str) -> dict:
    """Analyze an Android backup file."""
    result = {
        'file_path': file_path,
        'type': 'android_backup',
        'apps': [],
        'sms': [],
        'call_logs': [],
        'error': None,
    }
    try:
        with open(file_path, 'rb') as f:
            header = f.read(24)
        if b'ANDROID BACKUP' in header:
            result['format_detected'] = True
        else:
            result['error'] = 'Not a recognised Android backup format'
    except Exception as e:
        result['error'] = str(e)
    return result


def analyze_ios_backup(backup_dir: str) -> dict:
    """Analyze an iOS backup directory."""
    result = {
        'backup_dir': backup_dir,
        'type': 'ios_backup',
        'files': [],
        'error': None,
    }
    try:
        if not os.path.isdir(backup_dir):
            result['error'] = 'Not a directory'
            return result
        for fname in os.listdir(backup_dir):
            result['files'].append(fname)
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_sms_messages(db_path: str) -> list:
    """Extract SMS messages from SQLite DB."""
    messages = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT address, body, date, type FROM sms ORDER BY date DESC LIMIT 500')
            for row in cursor.fetchall():
                messages.append({'address': row[0], 'body': row[1], 'date': row[2], 'type': row[3]})
        except sqlite3.OperationalError:
            pass
        conn.close()
    except Exception:
        pass
    return messages


def extract_call_logs(db_path: str) -> list:
    """Extract call logs from SQLite DB."""
    calls = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT number, date, duration, type FROM calls ORDER BY date DESC LIMIT 500')
            for row in cursor.fetchall():
                calls.append({'number': row[0], 'date': row[1], 'duration': row[2], 'type': row[3]})
        except sqlite3.OperationalError:
            pass
        conn.close()
    except Exception:
        pass
    return calls
