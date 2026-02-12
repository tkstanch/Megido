"""
Interactive Dashboard Generator

Creates interactive HTML dashboards with charts and visualizations for scan results.
Uses Chart.js for beautiful, interactive charts.
"""

import json
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict, Counter


class DashboardGenerator:
    """
    Generate interactive dashboards for scan results.
    
    Features:
    - Severity distribution pie chart
    - Findings timeline
    - Engine performance comparison
    - CWE category breakdown
    - Priority score distribution
    - Trend analysis
    """
    
    def __init__(self):
        """Initialize dashboard generator"""
        pass
    
    def generate_dashboard(
        self,
        scan_summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
        historical_scans: List[Dict[str, Any]] = None
    ) -> str:
        """
        Generate complete interactive dashboard HTML.
        
        Args:
            scan_summary: Scan summary dict
            findings: List of findings
            historical_scans: Optional list of historical scan summaries for trends
        
        Returns:
            str: Complete HTML dashboard
        """
        # Prepare chart data
        severity_data = self._prepare_severity_chart(findings)
        engine_data = self._prepare_engine_chart(findings)
        cwe_data = self._prepare_cwe_chart(findings)
        priority_data = self._prepare_priority_chart(findings)
        
        # Prepare trend data if historical scans provided
        trend_data = None
        if historical_scans:
            trend_data = self._prepare_trend_chart(historical_scans)
        
        # Generate HTML
        html = self._generate_html(
            scan_summary,
            findings,
            severity_data,
            engine_data,
            cwe_data,
            priority_data,
            trend_data
        )
        
        return html
    
    def _prepare_severity_chart(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare severity distribution data"""
        severity_counts = Counter(f.get('severity', 'unknown') for f in findings)
        
        return {
            'labels': list(severity_counts.keys()),
            'data': list(severity_counts.values()),
            'colors': [
                '#dc2626' if s == 'critical' else
                '#f59e0b' if s == 'high' else
                '#facc15' if s == 'medium' else
                '#3b82f6' if s == 'low' else
                '#9ca3af'
                for s in severity_counts.keys()
            ]
        }
    
    def _prepare_engine_chart(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare engine performance comparison"""
        engine_counts = Counter(f.get('engine_name', 'Unknown') for f in findings)
        
        return {
            'labels': list(engine_counts.keys()),
            'data': list(engine_counts.values())
        }
    
    def _prepare_cwe_chart(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare CWE category breakdown"""
        cwe_counts = Counter(
            f.get('cwe_id', 'No CWE') for f in findings if f.get('cwe_id')
        )
        
        # Get top 10 CWEs
        top_cwes = dict(cwe_counts.most_common(10))
        
        return {
            'labels': list(top_cwes.keys()),
            'data': list(top_cwes.values())
        }
    
    def _prepare_priority_chart(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare priority score distribution"""
        priority_ranges = {
            '90-100': 0,
            '80-89': 0,
            '70-79': 0,
            '60-69': 0,
            '50-59': 0,
            '0-49': 0
        }
        
        for finding in findings:
            score = finding.get('priority_score', 50)
            if score >= 90:
                priority_ranges['90-100'] += 1
            elif score >= 80:
                priority_ranges['80-89'] += 1
            elif score >= 70:
                priority_ranges['70-79'] += 1
            elif score >= 60:
                priority_ranges['60-69'] += 1
            elif score >= 50:
                priority_ranges['50-59'] += 1
            else:
                priority_ranges['0-49'] += 1
        
        return {
            'labels': list(priority_ranges.keys()),
            'data': list(priority_ranges.values())
        }
    
    def _prepare_trend_chart(self, historical_scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare trend analysis data"""
        # Sort by date
        sorted_scans = sorted(
            historical_scans,
            key=lambda x: x.get('started_at', '')
        )
        
        labels = []
        critical_data = []
        high_data = []
        medium_data = []
        low_data = []
        
        for scan in sorted_scans[-10:]:  # Last 10 scans
            labels.append(scan.get('started_at', '')[:10])  # Date only
            
            severity_dist = scan.get('findings_by_severity', {})
            critical_data.append(severity_dist.get('critical', 0))
            high_data.append(severity_dist.get('high', 0))
            medium_data.append(severity_dist.get('medium', 0))
            low_data.append(severity_dist.get('low', 0))
        
        return {
            'labels': labels,
            'datasets': [
                {'label': 'Critical', 'data': critical_data, 'color': '#dc2626'},
                {'label': 'High', 'data': high_data, 'color': '#f59e0b'},
                {'label': 'Medium', 'data': medium_data, 'color': '#facc15'},
                {'label': 'Low', 'data': low_data, 'color': '#3b82f6'},
            ]
        }
    
    def _generate_html(
        self,
        scan_summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
        severity_data: Dict[str, Any],
        engine_data: Dict[str, Any],
        cwe_data: Dict[str, Any],
        priority_data: Dict[str, Any],
        trend_data: Dict[str, Any] = None
    ) -> str:
        """Generate complete HTML with Chart.js"""
        
        total_findings = len(findings)
        scan_id = scan_summary.get('id', 'N/A')
        target = scan_summary.get('target_path', 'N/A')
        execution_time = scan_summary.get('execution_time', 0)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Megido Security Dashboard - Scan #{scan_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #1f2937;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        
        h1 {{
            font-size: 2.5rem;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            font-size: 1.1rem;
            color: #6b7280;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 0.9rem;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .chart-card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }}
        
        .chart-title {{
            font-size: 1.3rem;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 20px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .findings-table {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        tr:hover {{
            background: #f9fafb;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: #fee2e2; color: #dc2626; }}
        .severity-high {{ background: #fed7aa; color: #f59e0b; }}
        .severity-medium {{ background: #fef3c7; color: #ca8a04; }}
        .severity-low {{ background: #dbeafe; color: #3b82f6; }}
        .severity-info {{ background: #e5e7eb; color: #6b7280; }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: white;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Megido Security Dashboard</h1>
            <div class="subtitle">
                <strong>Scan ID:</strong> {scan_id} | 
                <strong>Target:</strong> {target} | 
                <strong>Execution Time:</strong> {execution_time:.2f}s
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{severity_data['data'][0] if severity_data['labels'] and 'critical' in [l.lower() for l in severity_data['labels']] else 0}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{scan_summary.get('successful_engines', 0)}/{scan_summary.get('total_engines_run', 0)}</div>
                <div class="stat-label">Engines</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len([f for f in findings if f.get('priority_score', 0) >= 80])}</div>
                <div class="stat-label">High Priority</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-card">
                <div class="chart-title">Severity Distribution</div>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Findings by Engine</div>
                <canvas id="engineChart"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Top CWE Categories</div>
                <canvas id="cweChart"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Priority Score Distribution</div>
                <canvas id="priorityChart"></canvas>
            </div>
        </div>
        
        {self._generate_trend_section(trend_data) if trend_data else ''}
        
        <div class="findings-table">
            <div class="chart-title">Top Findings</div>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Engine</th>
                        <th>File</th>
                        <th>Priority</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_findings_rows(findings[:20])}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            Generated by Megido Advanced Multi-Engine Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    
    <script>
        // Severity Chart (Pie)
        new Chart(document.getElementById('severityChart'), {{
            type: 'pie',
            data: {{
                labels: {json.dumps(severity_data['labels'])},
                datasets: [{{
                    data: {json.dumps(severity_data['data'])},
                    backgroundColor: {json.dumps(severity_data['colors'])}
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Engine Chart (Bar)
        new Chart(document.getElementById('engineChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(engine_data['labels'])},
                datasets: [{{
                    label: 'Findings',
                    data: {json.dumps(engine_data['data'])},
                    backgroundColor: '#667eea'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
        
        // CWE Chart (Horizontal Bar)
        new Chart(document.getElementById('cweChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(cwe_data['labels'])},
                datasets: [{{
                    label: 'Count',
                    data: {json.dumps(cwe_data['data'])},
                    backgroundColor: '#f59e0b'
                }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});
        
        // Priority Chart (Bar)
        new Chart(document.getElementById('priorityChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(priority_data['labels'])},
                datasets: [{{
                    label: 'Findings',
                    data: {json.dumps(priority_data['data'])},
                    backgroundColor: '#764ba2'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
        
        {self._generate_trend_script(trend_data) if trend_data else ''}
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_trend_section(self, trend_data: Dict[str, Any]) -> str:
        """Generate trend analysis section HTML"""
        return """
        <div class="chart-card" style="grid-column: 1 / -1;">
            <div class="chart-title">Trend Analysis (Last 10 Scans)</div>
            <canvas id="trendChart" style="max-height: 300px;"></canvas>
        </div>
        """
    
    def _generate_trend_script(self, trend_data: Dict[str, Any]) -> str:
        """Generate trend chart JavaScript"""
        datasets_js = []
        for dataset in trend_data['datasets']:
            datasets_js.append(f"""{{
                label: '{dataset['label']}',
                data: {json.dumps(dataset['data'])},
                borderColor: '{dataset['color']}',
                backgroundColor: '{dataset['color']}33',
                tension: 0.4
            }}""")
        
        return f"""
        new Chart(document.getElementById('trendChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(trend_data['labels'])},
                datasets: [{','.join(datasets_js)}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'top' }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
        """
    
    def _generate_findings_rows(self, findings: List[Dict[str, Any]]) -> str:
        """Generate table rows for findings"""
        rows = []
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            title = finding.get('title', 'Unknown')[:80]
            engine = finding.get('engine_name', 'Unknown')
            file_path = finding.get('file_path', 'N/A')
            if file_path and len(file_path) > 50:
                file_path = '...' + file_path[-47:]
            
            priority_score = finding.get('priority_score', 50)
            
            rows.append(f"""
            <tr>
                <td><span class="severity-badge severity-{severity}">{severity}</span></td>
                <td>{title}</td>
                <td>{engine}</td>
                <td><small>{file_path}</small></td>
                <td>{priority_score:.0f}</td>
            </tr>
            """)
        
        return ''.join(rows)
