"""Report generation utilities."""
import json
from django.utils import timezone

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as rl_canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def generate_pdf_report(case, output_path: str) -> str:
    """Generate a PDF report for a case. Returns path to PDF."""
    if not REPORTLAB_AVAILABLE:
        raise ImportError('reportlab not installed - install for PDF generation')
    c = rl_canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    c.setFont('Helvetica-Bold', 18)
    c.drawString(72, height - 72, f'Forensic Report: {case.case_number}')
    c.setFont('Helvetica', 12)
    c.drawString(72, height - 100, f'Title: {case.title}')
    c.drawString(72, height - 120, f'Status: {case.status}')
    c.drawString(72, height - 140, f'Classification: {case.classification}')
    c.drawString(72, height - 160, f'Generated: {timezone.now().strftime("%Y-%m-%d %H:%M")}')
    y = height - 200
    c.setFont('Helvetica-Bold', 14)
    c.drawString(72, y, 'Evidence Items')
    c.setFont('Helvetica', 10)
    y -= 20
    for ev in case.evidence_items.all()[:20]:
        c.drawString(90, y, f'- {ev.name} ({ev.acquisition_type})')
        y -= 14
        if y < 72:
            c.showPage()
            y = height - 72
    c.save()
    return output_path


def generate_html_report(case) -> str:
    """Generate an HTML report for a case."""
    evidence_rows = ''
    for ev in case.evidence_items.all():
        evidence_rows += f'<tr><td>{ev.name}</td><td>{ev.acquisition_type}</td><td>{ev.sha256_hash or "-"}</td></tr>\n'

    ioc_rows = ''
    from ..models import IOCIndicator
    from django.db.models import Q
    iocs = IOCIndicator.objects.filter(
        Q(forensic_file__case=case) | Q(evidence_item__case=case)
    ).distinct()[:100]
    for ioc in iocs:
        ioc_rows += f'<tr><td>{ioc.ioc_type}</td><td><code>{ioc.ioc_value[:80]}</code></td><td>{ioc.confidence}</td></tr>\n'

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Forensic Report: {case.case_number}</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#222;}}
h1{{color:#1a237e;}}h2{{color:#283593;border-bottom:1px solid #ccc;padding-bottom:4px;}}
table{{border-collapse:collapse;width:100%;margin-bottom:20px;}}
th,td{{border:1px solid #ccc;padding:8px;text-align:left;}}
th{{background:#e8eaf6;}}
.meta{{background:#f5f5f5;padding:16px;border-radius:4px;margin-bottom:20px;}}
</style></head><body>
<h1>Forensic Report: {case.case_number}</h1>
<div class="meta">
<strong>Title:</strong> {case.title}<br>
<strong>Status:</strong> {case.status}<br>
<strong>Classification:</strong> {case.classification}<br>
<strong>Description:</strong> {case.description or '-'}<br>
<strong>Generated:</strong> {timezone.now().strftime('%Y-%m-%d %H:%M UTC')}
</div>
<h2>Evidence Items</h2>
<table><tr><th>Name</th><th>Acquisition Type</th><th>SHA256</th></tr>
{evidence_rows or '<tr><td colspan="3">No evidence items</td></tr>'}
</table>
<h2>IOC Indicators</h2>
<table><tr><th>Type</th><th>Value</th><th>Confidence</th></tr>
{ioc_rows or '<tr><td colspan="3">No IOCs</td></tr>'}
</table>
</body></html>"""
    return html


def generate_json_report(case) -> dict:
    """Generate a JSON-serializable report dict for a case."""
    from ..models import IOCIndicator
    from django.db.models import Q
    iocs = list(IOCIndicator.objects.filter(
        Q(forensic_file__case=case) | Q(evidence_item__case=case)
    ).distinct().values('ioc_type', 'ioc_value', 'confidence', 'source')[:500])
    evidence = []
    for ev in case.evidence_items.all():
        evidence.append({
            'name': ev.name,
            'acquisition_type': ev.acquisition_type,
            'sha256_hash': ev.sha256_hash,
            'integrity_verified': ev.integrity_verified,
        })
    return {
        'case_number': case.case_number,
        'title': case.title,
        'status': case.status,
        'classification': case.classification,
        'description': case.description,
        'generated_at': timezone.now().isoformat(),
        'evidence': evidence,
        'iocs': iocs,
    }


def generate_csv_report(case) -> str:
    """Generate a CSV report for a case's IOCs."""
    import csv
    from io import StringIO
    from ..models import IOCIndicator
    from django.db.models import Q
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['type', 'value', 'confidence', 'source', 'mitre_technique'])
    iocs = IOCIndicator.objects.filter(
        Q(forensic_file__case=case) | Q(evidence_item__case=case)
    ).distinct()
    for ioc in iocs:
        writer.writerow([ioc.ioc_type, ioc.ioc_value, ioc.confidence,
                         ioc.source, ioc.mitre_technique])
    return output.getvalue()
