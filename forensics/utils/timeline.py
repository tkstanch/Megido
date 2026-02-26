"""Timeline generation utilities."""
from django.utils import timezone


def generate_timeline(forensic_file) -> list:
    """Generate timeline events from a ForensicFile."""
    events = []
    events.append({
        'event_time': forensic_file.upload_date,
        'event_type': 'other',
        'source': 'upload',
        'description': f'File uploaded: {forensic_file.original_filename}',
        'artifact_path': forensic_file.original_filename,
    })
    return events


def merge_timelines(timeline_list: list) -> list:
    """Merge and sort multiple timelines."""
    merged = []
    for tl in timeline_list:
        merged.extend(tl)
    merged.sort(key=lambda x: x.get('event_time', timezone.now()))
    return merged


def format_timeline_for_display(events: list) -> list:
    """Format timeline events for display."""
    formatted = []
    for ev in events:
        formatted.append({
            'event_time': str(ev.get('event_time', '')),
            'event_type': ev.get('event_type', 'other'),
            'source': ev.get('source', ''),
            'description': ev.get('description', ''),
            'artifact_path': ev.get('artifact_path', ''),
        })
    return formatted
