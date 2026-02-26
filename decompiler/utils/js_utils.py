"""
JavaScript utility functions for the decompiler app.

Provides JavaScript beautification, source map parsing, minification
detection, and module system detection.
"""
import re
from typing import Optional

try:
    import jsbeautifier
    _JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    _JSBEAUTIFIER_AVAILABLE = False


def beautify_js(source: str, options: Optional[dict] = None) -> str:
    """
    Beautify/format JavaScript source code.

    Falls back to returning the original source if jsbeautifier is
    not installed.
    """
    if not _JSBEAUTIFIER_AVAILABLE:
        return source
    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.max_preserve_newlines = 2
    if options:
        for key, val in options.items():
            setattr(opts, key, val)
    try:
        return jsbeautifier.beautify(source, opts)
    except Exception:
        return source


def is_minified(source: str) -> bool:
    """
    Heuristically detect whether JavaScript source is minified.

    Checks average line length (minified code has very long lines).
    """
    if not source:
        return False
    lines = [l for l in source.splitlines() if l.strip()]
    if not lines:
        return False
    avg_len = sum(len(l) for l in lines) / len(lines)
    return avg_len > 200


def detect_module_system(source: str) -> str:
    """
    Detect the JavaScript module system in use.

    Returns one of: 'commonjs', 'esmodule', 'amd', 'iife', 'unknown'.
    """
    if re.search(r'\brequire\s*\(', source) and re.search(r'\bmodule\.exports\b', source):
        return 'commonjs'
    if re.search(r'\bimport\s+.*\bfrom\b|\bexport\s+(?:default|const|function|class)\b', source):
        return 'esmodule'
    if re.search(r'\bdefine\s*\(\s*(?:\[|function)', source):
        return 'amd'
    if re.search(r'^\s*\((?:function|\()', source, re.MULTILINE):
        return 'iife'
    return 'unknown'


def parse_userscript_metadata(source: str) -> dict:
    """
    Parse Tampermonkey/Greasemonkey metadata block.

    Returns a dict with metadata keys and their values.
    """
    metadata: dict = {}
    in_block = False
    for line in source.splitlines():
        stripped = line.strip()
        if stripped == '// ==UserScript==':
            in_block = True
            continue
        if stripped == '// ==/UserScript==':
            break
        if in_block and stripped.startswith('// @'):
            rest = stripped[4:].strip()
            parts = rest.split(None, 1)
            if parts:
                key = parts[0]
                value = parts[1] if len(parts) > 1 else ''
                if key in metadata:
                    existing = metadata[key]
                    if isinstance(existing, list):
                        existing.append(value)
                    else:
                        metadata[key] = [existing, value]
                else:
                    metadata[key] = value
    return metadata
