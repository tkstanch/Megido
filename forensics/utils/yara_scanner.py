"""YARA scanning utilities."""

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def compile_rule(rule_content: str):
    """Compile a YARA rule. Returns None if yara not available."""
    if not YARA_AVAILABLE:
        return None
    try:
        return yara.compile(source=rule_content)
    except Exception:
        return None


def scan_data(data: bytes, rules) -> list:
    """Scan bytes with compiled YARA rules."""
    if not YARA_AVAILABLE or rules is None:
        return []
    matches = []
    try:
        results = rules.match(data=data)
        for match in results:
            strings = []
            for s in match.strings:
                strings.append({
                    'identifier': s.identifier,
                    'offset': s.instances[0].offset if s.instances else 0,
                    'matched_data': s.instances[0].matched_data[:64].hex() if s.instances else '',
                })
            matches.append({
                'rule': match.rule,
                'tags': list(match.tags),
                'strings': strings,
            })
    except Exception:
        pass
    return matches


def scan_file(file_path: str, rules) -> list:
    """Scan a file with compiled YARA rules."""
    if not YARA_AVAILABLE or rules is None:
        return []
    matches = []
    try:
        results = rules.match(file_path)
        for match in results:
            matches.append({
                'rule': match.rule,
                'tags': list(match.tags),
                'strings': [],
            })
    except Exception:
        pass
    return matches
