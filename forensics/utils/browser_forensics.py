"""Browser forensics - SQLite-based browser database analysis."""
import sqlite3
import os


def analyze_browser_db(file_path: str, browser_type: str = 'chrome') -> dict:
    """Analyze a browser database file."""
    result = {
        'file_path': file_path,
        'browser_type': browser_type,
        'history': [],
        'downloads': [],
        'cookies': [],
        'error': None,
    }
    if not os.path.exists(file_path):
        result['error'] = 'File not found'
        return result
    try:
        result['history'] = extract_history(file_path)
        result['downloads'] = extract_downloads(file_path)
        result['cookies'] = extract_cookies(file_path)
    except Exception as e:
        result['error'] = str(e)
    return result


def extract_history(db_path: str) -> list:
    """Extract browsing history from SQLite DB."""
    history = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Try Chrome/Chromium schema
        try:
            cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500')
            for row in cursor.fetchall():
                history.append({'url': row[0], 'title': row[1], 'visit_count': row[2], 'last_visit': row[3]})
        except sqlite3.OperationalError:
            pass
        # Try Firefox schema
        try:
            cursor.execute('SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 500')
            for row in cursor.fetchall():
                history.append({'url': row[0], 'title': row[1], 'visit_count': row[2], 'last_visit': row[3]})
        except sqlite3.OperationalError:
            pass
        conn.close()
    except Exception:
        pass
    return history


def extract_downloads(db_path: str) -> list:
    """Extract download history from SQLite DB."""
    downloads = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT target_path, url, total_bytes, start_time FROM downloads LIMIT 200')
            for row in cursor.fetchall():
                downloads.append({'path': row[0], 'url': row[1], 'size': row[2], 'start_time': row[3]})
        except sqlite3.OperationalError:
            pass
        conn.close()
    except Exception:
        pass
    return downloads


def extract_cookies(db_path: str) -> list:
    """Extract cookies from SQLite DB."""
    cookies = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT host_key, name, path, expires_utc FROM cookies LIMIT 500')
            for row in cursor.fetchall():
                cookies.append({'host': row[0], 'name': row[1], 'path': row[2], 'expires': row[3]})
        except sqlite3.OperationalError:
            pass
        conn.close()
    except Exception:
        pass
    return cookies
