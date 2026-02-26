from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid


class ScanTarget(models.Model):
    """
    Model for storing scan targets (hosts/networks to scan).
    """
    SCAN_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.CharField(max_length=255, help_text="IP address, hostname, or network range")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_targets')
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, default='pending')
    scan_type = models.CharField(max_length=50, default='comprehensive')
    stealth_mode = models.BooleanField(default=False, help_text="Enable stealth scanning techniques")
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['created_by', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.target} - {self.status}"


class ScanResult(models.Model):
    """
    Model for storing overall scan results.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_target = models.ForeignKey(ScanTarget, on_delete=models.CASCADE, related_name='results')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    host_discovered = models.BooleanField(default=False)
    open_ports_count = models.IntegerField(default=0)
    summary = models.TextField(blank=True)
    raw_output = models.TextField(blank=True, help_text="Raw scan output")
    
    class Meta:
        ordering = ['-started_at']
    
    def __str__(self):
        return f"Scan of {self.scan_target.target} at {self.started_at}"


class PortScan(models.Model):
    """
    Model for storing port scan results.
    """
    PORT_STATE_CHOICES = [
        ('open', 'Open'),
        ('closed', 'Closed'),
        ('filtered', 'Filtered'),
        ('unfiltered', 'Unfiltered'),
        ('open|filtered', 'Open|Filtered'),
        ('closed|filtered', 'Closed|Filtered'),
    ]
    
    SCAN_TYPE_CHOICES = [
        ('syn', 'TCP SYN (Stealth)'),
        ('connect', 'TCP Connect'),
        ('ack', 'TCP ACK'),
        ('window', 'TCP Window'),
        ('maimon', 'TCP Maimon'),
        ('null', 'TCP NULL'),
        ('fin', 'TCP FIN'),
        ('xmas', 'TCP XMAS'),
        ('udp', 'UDP'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='port_scans')
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20, choices=PORT_STATE_CHOICES)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES, default='syn')
    service_name = models.CharField(max_length=100, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['port']
        indexes = [
            models.Index(fields=['scan_result', 'port']),
            models.Index(fields=['state']),
        ]
    
    def __str__(self):
        return f"Port {self.port}/{self.protocol} - {self.state}"


class ServiceDetection(models.Model):
    """
    Model for storing service and version detection results.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    port_scan = models.OneToOneField(PortScan, on_delete=models.CASCADE, related_name='service_detection')
    service_name = models.CharField(max_length=100)
    service_version = models.CharField(max_length=200, blank=True)
    product = models.CharField(max_length=200, blank=True)
    extrainfo = models.TextField(blank=True)
    confidence = models.IntegerField(default=0, help_text="Confidence level 0-100")
    cpe = models.CharField(max_length=500, blank=True, help_text="Common Platform Enumeration")
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.service_name} {self.service_version} on port {self.port_scan.port}"


class OSFingerprint(models.Model):
    """
    Model for storing OS fingerprinting results.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='os_fingerprints')
    os_name = models.CharField(max_length=200)
    os_family = models.CharField(max_length=100, blank=True)
    os_generation = models.CharField(max_length=100, blank=True)
    os_vendor = models.CharField(max_length=100, blank=True)
    accuracy = models.IntegerField(default=0, help_text="Accuracy percentage 0-100")
    cpe = models.CharField(max_length=500, blank=True)
    fingerprint_method = models.CharField(max_length=50, default='tcp_ip_stack')
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-accuracy', '-detected_at']
    
    def __str__(self):
        return f"{self.os_name} ({self.accuracy}% accuracy)"


class PacketCapture(models.Model):
    """
    Model for storing captured network packets for analysis.
    """
    PACKET_TYPE_CHOICES = [
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('icmp', 'ICMP'),
        ('arp', 'ARP'),
        ('other', 'Other'),
    ]
    
    RELEVANCE_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='packet_captures')
    packet_type = models.CharField(max_length=10, choices=PACKET_TYPE_CHOICES)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    packet_size = models.IntegerField()
    payload = models.BinaryField(blank=True)
    flags = models.CharField(max_length=50, blank=True)
    relevance = models.CharField(max_length=10, choices=RELEVANCE_CHOICES, default='medium')
    analysis_notes = models.TextField(blank=True)
    captured_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-captured_at']
        indexes = [
            models.Index(fields=['scan_result', 'captured_at']),
            models.Index(fields=['relevance']),
            models.Index(fields=['packet_type']),
        ]
    
    def __str__(self):
        return f"{self.packet_type} packet: {self.source_ip}:{self.source_port or 'N/A'} -> {self.destination_ip}:{self.destination_port or 'N/A'}"


class StealthConfiguration(models.Model):
    """
    Model for storing stealth scanning configurations.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    timing_template = models.IntegerField(default=3, help_text="0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal, 4=Aggressive, 5=Insane")
    scan_delay = models.FloatField(default=0, help_text="Delay between probes in seconds")
    max_scan_delay = models.FloatField(default=0, help_text="Maximum delay between probes")
    min_rate = models.IntegerField(default=0, help_text="Minimum packets per second")
    max_rate = models.IntegerField(default=0, help_text="Maximum packets per second")
    max_retries = models.IntegerField(default=3, help_text="Maximum probe retransmissions")
    host_timeout = models.IntegerField(default=900, help_text="Timeout per host in seconds")
    fragment_packets = models.BooleanField(default=False, help_text="Fragment IP packets")
    randomize_hosts = models.BooleanField(default=True, help_text="Randomize target host order")
    spoof_mac = models.BooleanField(default=False, help_text="Spoof MAC address")
    decoy_scanning = models.BooleanField(default=False, help_text="Use decoy IP addresses")
    data_length = models.IntegerField(default=0, help_text="Append random data to packets")
    created_at = models.DateTimeField(auto_now_add=True)
    is_default = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class ScanLog(models.Model):
    """
    Model for logging scan activities and events.
    """
    LOG_LEVEL_CHOICES = [
        ('debug', 'Debug'),
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='logs')
    level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, default='info')
    message = models.TextField()
    details = models.JSONField(default=dict, blank=True)
    logged_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-logged_at']
        indexes = [
            models.Index(fields=['scan_result', 'logged_at']),
            models.Index(fields=['level']),
        ]
    
    def __str__(self):
        return f"[{self.level.upper()}] {self.message[:50]}"


class VulnerabilityFinding(models.Model):
    """
    Model for storing vulnerability scan results with CVE, CVSS, and remediation.
    """
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='vulnerability_findings')
    cve_id = models.CharField(max_length=30, blank=True, db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info', db_index=True)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    affected_component = models.CharField(max_length=500, blank=True)
    remediation = models.TextField(blank=True)
    exploit_available = models.BooleanField(default=False)
    vulnerability_type = models.CharField(max_length=100, blank=True)
    references = models.JSONField(default=list, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-cvss_score', '-discovered_at']
        indexes = [
            models.Index(fields=['scan_result', 'severity']),
            models.Index(fields=['cve_id']),
        ]

    def __str__(self):
        return f"{self.cve_id or self.title[:50]} - {self.severity.upper()} (CVSS: {self.cvss_score})"


class NetworkTopology(models.Model):
    """
    Model for storing network topology nodes and edges.
    """
    NODE_TYPE_CHOICES = [
        ('server', 'Server'),
        ('workstation', 'Workstation'),
        ('network_equipment', 'Network Equipment'),
        ('printer', 'Printer'),
        ('iot', 'IoT Device'),
        ('unknown', 'Unknown'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='topology_nodes')
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    node_type = models.CharField(max_length=20, choices=NODE_TYPE_CHOICES, default='unknown')
    vendor = models.CharField(max_length=200, blank=True)
    os_guess = models.CharField(max_length=200, blank=True)
    open_ports = models.JSONField(default=list, blank=True)
    services = models.JSONField(default=list, blank=True)
    graph_data = models.JSONField(default=dict, blank=True, help_text="D3.js-compatible node data")
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['ip_address']
        indexes = [
            models.Index(fields=['scan_result', 'ip_address']),
            models.Index(fields=['node_type']),
        ]

    def __str__(self):
        return f"{self.ip_address} ({self.node_type}) - {self.hostname or 'no hostname'}"


class TrafficFlow(models.Model):
    """
    Model for storing reconstructed network traffic flows and sessions.
    """
    PROTOCOL_CHOICES = [
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('icmp', 'ICMP'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='traffic_flows')
    flow_id = models.CharField(max_length=64, blank=True, db_index=True)
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, choices=PROTOCOL_CHOICES, default='tcp')
    application_protocol = models.CharField(max_length=50, blank=True)
    packet_count = models.IntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)
    flow_state = models.CharField(max_length=20, default='unknown')
    anomalies = models.JSONField(default=list, blank=True)
    extracted_data = models.JSONField(default=dict, blank=True)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-byte_count']
        indexes = [
            models.Index(fields=['scan_result', 'start_time']),
            models.Index(fields=['source_ip', 'destination_ip']),
            models.Index(fields=['application_protocol']),
        ]

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.application_protocol})"


class ThreatIntelligence(models.Model):
    """
    Model for storing threat intelligence IOC matches and reputation data.
    """
    IOC_TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('url', 'URL'),
        ('hash', 'File Hash'),
        ('email', 'Email'),
        ('yara', 'YARA Match'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='threat_intel_matches')
    ioc_type = models.CharField(max_length=10, choices=IOC_TYPE_CHOICES, db_index=True)
    ioc_value = models.CharField(max_length=500, db_index=True)
    threat_score = models.IntegerField(default=0)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')
    categories = models.JSONField(default=list, blank=True)
    threat_feeds = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    reputation_data = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-threat_score', '-discovered_at']
        indexes = [
            models.Index(fields=['scan_result', 'ioc_type']),
            models.Index(fields=['threat_score']),
        ]

    def __str__(self):
        return f"{self.ioc_type}: {self.ioc_value} (score: {self.threat_score})"


class CloudAsset(models.Model):
    """
    Model for storing discovered cloud assets and their security posture.
    """
    PROVIDER_CHOICES = [
        ('aws', 'Amazon Web Services'),
        ('azure', 'Microsoft Azure'),
        ('gcp', 'Google Cloud Platform'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='cloud_assets')
    provider = models.CharField(max_length=10, choices=PROVIDER_CHOICES, db_index=True)
    asset_type = models.CharField(max_length=100, db_index=True)
    asset_id = models.CharField(max_length=500)
    asset_name = models.CharField(max_length=500, blank=True)
    region = models.CharField(max_length=100, blank=True)
    is_public = models.BooleanField(default=False)
    security_findings = models.JSONField(default=list, blank=True)
    compliance_status = models.JSONField(default=dict, blank=True)
    risk_score = models.FloatField(default=0.0)
    tags = models.JSONField(default=dict, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-risk_score', '-discovered_at']
        indexes = [
            models.Index(fields=['scan_result', 'provider']),
            models.Index(fields=['asset_type']),
            models.Index(fields=['is_public']),
        ]

    def __str__(self):
        return f"{self.provider.upper()} {self.asset_type}: {self.asset_name or self.asset_id}"


class APIEndpoint(models.Model):
    """
    Model for storing discovered API endpoints and security test results.
    """
    METHOD_CHOICES = [
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE'),
        ('OPTIONS', 'OPTIONS'),
        ('HEAD', 'HEAD'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='api_endpoints')
    url = models.URLField(max_length=2000)
    path = models.CharField(max_length=1000)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES, default='GET')
    endpoint_type = models.CharField(max_length=50, blank=True)
    auth_required = models.BooleanField(null=True)
    status_code = models.IntegerField(null=True, blank=True)
    security_findings = models.JSONField(default=list, blank=True)
    parameters = models.JSONField(default=list, blank=True)
    response_schema = models.JSONField(default=dict, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['scan_result', 'endpoint_type']),
        ]

    def __str__(self):
        return f"{self.method} {self.url}"


class WirelessNetwork(models.Model):
    """
    Model for storing discovered wireless networks and their security state.
    """
    ENCRYPTION_CHOICES = [
        ('WPA3', 'WPA3'),
        ('WPA2', 'WPA2'),
        ('WPA2-EAP', 'WPA2-EAP (Enterprise)'),
        ('WPA', 'WPA'),
        ('WEP', 'WEP'),
        ('OPEN', 'Open (No Encryption)'),
        ('UNKNOWN', 'Unknown'),
    ]

    RISK_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('unknown', 'Unknown'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='wireless_networks')
    ssid = models.CharField(max_length=255, blank=True)
    bssid = models.CharField(max_length=17)
    channel = models.IntegerField(null=True, blank=True)
    frequency = models.IntegerField(null=True, blank=True, help_text="Frequency in MHz")
    signal_dbm = models.IntegerField(null=True, blank=True)
    encryption = models.CharField(max_length=10, choices=ENCRYPTION_CHOICES, default='UNKNOWN')
    wps_enabled = models.BooleanField(default=False)
    hidden = models.BooleanField(default=False)
    vendor = models.CharField(max_length=200, blank=True)
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES, default='unknown', db_index=True)
    security_findings = models.JSONField(default=list, blank=True)
    is_rogue = models.BooleanField(default=False)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['scan_result', 'risk_level']),
            models.Index(fields=['encryption']),
            models.Index(fields=['is_rogue']),
        ]

    def __str__(self):
        return f"{self.ssid or '(hidden)'} ({self.bssid}) - {self.encryption} - {self.risk_level}"


class CredentialFinding(models.Model):
    """
    Model for storing discovered credentials and secrets.
    """
    FINDING_TYPE_CHOICES = [
        ('default_credentials', 'Default Credentials'),
        ('exposed_secret', 'Exposed Secret'),
        ('weak_password', 'Weak Password'),
        ('password_in_url', 'Password in URL'),
        ('cleartext_auth', 'Cleartext Authentication'),
        ('certificate_issue', 'Certificate Issue'),
        ('hash_found', 'Password Hash Found'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='credential_findings')
    finding_type = models.CharField(max_length=30, choices=FINDING_TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='high', db_index=True)
    service = models.CharField(max_length=100, blank=True)
    username = models.CharField(max_length=255, blank=True)
    secret_type = models.CharField(max_length=100, blank=True)
    secret_value_redacted = models.CharField(max_length=500, blank=True)
    source_url = models.CharField(max_length=2000, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['scan_result', 'severity']),
            models.Index(fields=['finding_type']),
        ]

    def __str__(self):
        return f"{self.finding_type}: {self.service} - {self.severity.upper()}"


class ScanReport(models.Model):
    """
    Model for storing generated reports with metadata.
    """
    FORMAT_CHOICES = [
        ('json', 'JSON'),
        ('html', 'HTML'),
        ('pdf', 'PDF'),
        ('csv', 'CSV'),
        ('markdown', 'Markdown'),
        ('text', 'Plain Text'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_result = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='reports')
    title = models.CharField(max_length=300)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='html')
    content = models.TextField(blank=True)
    executive_summary = models.JSONField(default=dict, blank=True)
    risk_score = models.FloatField(default=0.0)
    finding_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    compliance_data = models.JSONField(default=dict, blank=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['scan_result', 'generated_at']),
            models.Index(fields=['format']),
        ]

    def __str__(self):
        return f"Report: {self.title} ({self.format}) - {self.generated_at}"


class ScanSchedule(models.Model):
    """
    Model for storing scheduled/recurring scan configurations.
    """
    FREQUENCY_CHOICES = [
        ('once', 'Run Once'),
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50, default='comprehensive')
    frequency = models.CharField(max_length=10, choices=FREQUENCY_CHOICES, default='once')
    next_run = models.DateTimeField(null=True, blank=True)
    last_run = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scan_schedules')
    scan_config = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['next_run']
        indexes = [
            models.Index(fields=['is_active', 'next_run']),
            models.Index(fields=['created_by']),
        ]

    def __str__(self):
        return f"Schedule: {self.name} ({self.frequency}) - {self.target}"


class ScanComparison(models.Model):
    """
    Model for storing scan-over-scan comparison and diff results.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    baseline_scan = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='baseline_comparisons')
    comparison_scan = models.ForeignKey(ScanResult, on_delete=models.CASCADE, related_name='comparison_results')
    new_findings = models.JSONField(default=list, blank=True)
    resolved_findings = models.JSONField(default=list, blank=True)
    unchanged_findings = models.JSONField(default=list, blank=True)
    new_ports = models.JSONField(default=list, blank=True)
    closed_ports = models.JSONField(default=list, blank=True)
    new_services = models.JSONField(default=list, blank=True)
    risk_delta = models.FloatField(default=0.0, help_text="Change in risk score (positive = worse)")
    summary = models.TextField(blank=True)
    compared_at = models.DateTimeField(auto_now_add=True)
    compared_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-compared_at']

    def __str__(self):
        return f"Comparison: {self.baseline_scan} vs {self.comparison_scan} (delta: {self.risk_delta:+.1f})"

