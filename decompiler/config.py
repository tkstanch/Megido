"""
Configuration for the Decompiler app.

All settings are configurable via Django settings or environment variables.
"""
import os


def _get(setting_name, default):
    """Get a decompiler setting from Django settings or return default."""
    try:
        from django.conf import settings
        return getattr(settings, f'DECOMPILER_{setting_name}', default)
    except Exception:
        return default


# File size limits
MAX_UPLOAD_SIZE = _get('MAX_UPLOAD_SIZE', 100 * 1024 * 1024)  # 100 MB

# Supported extension formats
SUPPORTED_FORMATS = [
    'chrome_crx', 'firefox_xpi', 'edge_msix', 'safari_appex',
    'webextension', 'electron_asar', 'wasm', 'pwa',
    'java_applet', 'flash', 'silverlight', 'javascript',
    'browser_addon', 'userscript',
]

# Decompiler tool paths (can be overridden via settings)
TOOL_PATHS = {
    'cfr': _get('CFR_PATH', os.environ.get('CFR_PATH', 'cfr')),
    'jpexs': _get('JPEXS_PATH', os.environ.get('JPEXS_PATH', 'ffdec')),
    'ilspy': _get('ILSPY_PATH', os.environ.get('ILSPY_PATH', 'ilspycmd')),
    'javac': _get('JAVAC_PATH', os.environ.get('JAVAC_PATH', 'javac')),
    'jar': _get('JAR_PATH', os.environ.get('JAR_PATH', 'jar')),
    'mxmlc': _get('MXMLC_PATH', os.environ.get('MXMLC_PATH', 'mxmlc')),
    'dotnet': _get('DOTNET_PATH', os.environ.get('DOTNET_PATH', 'dotnet')),
    'wasm_tools': _get('WASM_TOOLS_PATH', os.environ.get('WASM_TOOLS_PATH', 'wasm-tools')),
}

# Analysis thresholds
ENTROPY_THRESHOLD = _get('ENTROPY_THRESHOLD', 4.5)
SHORT_NAME_RATIO_THRESHOLD = _get('SHORT_NAME_RATIO_THRESHOLD', 0.60)
OBFUSCATION_CONFIDENCE_THRESHOLD = _get('OBFUSCATION_CONFIDENCE_THRESHOLD', 0.5)

# Timeout settings (seconds)
DOWNLOAD_TIMEOUT = _get('DOWNLOAD_TIMEOUT', 60)
DECOMPILE_TIMEOUT = _get('DECOMPILE_TIMEOUT', 300)
ANALYSIS_TIMEOUT = _get('ANALYSIS_TIMEOUT', 120)

# Download settings
MAX_DOWNLOAD_RETRIES = _get('MAX_DOWNLOAD_RETRIES', 3)
DOWNLOAD_CHUNK_SIZE = _get('DOWNLOAD_CHUNK_SIZE', 8192)

# Pagination defaults
DEFAULT_PAGE_SIZE = _get('DEFAULT_PAGE_SIZE', 20)
MAX_PAGE_SIZE = _get('MAX_PAGE_SIZE', 100)
