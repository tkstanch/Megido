"""Windows event log parsing utilities."""

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


def analyze_evtx(file_path: str) -> list:
    """Parse Windows EVTX event log file."""
    events = []
    if not EVTX_AVAILABLE:
        return events
    try:
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    events.append({'record_id': record.record_num(), 'xml': xml[:500]})
                    if len(events) >= 1000:
                        break
                except Exception:
                    continue
    except Exception:
        pass
    return events


def extract_login_events(events: list) -> list:
    """Extract login events (EventID 4624, 4625) from parsed events."""
    login_events = []
    for ev in events:
        xml = ev.get('xml', '')
        if 'EventID>4624<' in xml or 'EventID>4625<' in xml:
            login_events.append(ev)
    return login_events


def extract_process_events(events: list) -> list:
    """Extract process creation events (EventID 4688) from parsed events."""
    process_events = []
    for ev in events:
        xml = ev.get('xml', '')
        if 'EventID>4688<' in xml:
            process_events.append(ev)
    return process_events
