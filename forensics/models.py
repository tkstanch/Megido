"""
Models for the Forensics app.
"""
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import json


class ForensicCase(models.Model):
    CLASSIFICATION_CHOICES = [
        ('unclassified', 'Unclassified'),
        ('confidential', 'Confidential'),
        ('secret', 'Secret'),
        ('top_secret', 'Top Secret'),
    ]
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('active', 'Active'),
        ('closed', 'Closed'),
        ('archived', 'Archived'),
    ]
    case_number = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    investigator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='cases')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    classification = models.CharField(max_length=20, choices=CLASSIFICATION_CHOICES, default='unclassified')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    tags = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Forensic Case'
        verbose_name_plural = 'Forensic Cases'

    def __str__(self):
        return f"{self.case_number}: {self.title}"


class EvidenceItem(models.Model):
    ACQUISITION_CHOICES = [
        ('live', 'Live Acquisition'),
        ('dead', 'Dead-box Acquisition'),
        ('network', 'Network Acquisition'),
        ('cloud', 'Cloud Acquisition'),
        ('logical', 'Logical Acquisition'),
        ('physical', 'Physical Acquisition'),
    ]
    case = models.ForeignKey(ForensicCase, on_delete=models.CASCADE, related_name='evidence_items')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    acquisition_type = models.CharField(max_length=20, choices=ACQUISITION_CHOICES, default='logical')
    acquisition_timestamp = models.DateTimeField(default=timezone.now)
    acquired_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    storage_location = models.CharField(max_length=500, blank=True)
    sha256_hash = models.CharField(max_length=64, blank=True)
    md5_hash = models.CharField(max_length=32, blank=True)
    file_size = models.BigIntegerField(null=True, blank=True)
    integrity_verified = models.BooleanField(default=False)
    last_verified = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Evidence Item'
        verbose_name_plural = 'Evidence Items'

    def __str__(self):
        return f"{self.name} ({self.case.case_number})"


class ChainOfCustodyEntry(models.Model):
    evidence = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='custody_entries')
    action = models.CharField(max_length=255)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    location = models.CharField(max_length=255, blank=True)
    notes = models.TextField(blank=True)
    digital_signature = models.TextField(blank=True)

    class Meta:
        ordering = ['timestamp']
        verbose_name = 'Chain of Custody Entry'
        verbose_name_plural = 'Chain of Custody Entries'

    def __str__(self):
        return f"{self.evidence.name} - {self.action} at {self.timestamp}"


class ForensicFile(models.Model):
    """Uploaded forensic files with analysis results."""
    case = models.ForeignKey(ForensicCase, on_delete=models.SET_NULL, null=True, blank=True, related_name='files')
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.SET_NULL, null=True, blank=True, related_name='files')
    uploaded_file = models.FileField(upload_to='forensics/%Y/%m/%d/')
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField(help_text="File size in bytes")
    upload_date = models.DateTimeField(default=timezone.now)
    sha256_hash = models.CharField(max_length=64, blank=True)
    md5_hash = models.CharField(max_length=32, blank=True)
    sha1_hash = models.CharField(max_length=40, blank=True)
    sha512_hash = models.CharField(max_length=128, blank=True)
    device_model = models.CharField(max_length=255, blank=True, null=True)
    os_version = models.CharField(max_length=100, blank=True, null=True)
    serial_number = models.CharField(max_length=100, blank=True, null=True)
    file_type = models.CharField(max_length=100, blank=True)
    mime_type = models.CharField(max_length=100, blank=True)
    magic_bytes = models.CharField(max_length=100, blank=True)
    hex_sample = models.TextField(blank=True)
    entropy = models.FloatField(null=True, blank=True)
    is_encrypted = models.BooleanField(default=False)
    is_packed = models.BooleanField(default=False)
    yara_matches = models.TextField(blank=True)
    embedded_files_count = models.IntegerField(default=0)
    analysis_notes = models.TextField(blank=True)
    analysis_complete = models.BooleanField(default=False)

    class Meta:
        ordering = ['-upload_date']
        verbose_name = 'Forensic File'
        verbose_name_plural = 'Forensic Files'

    def __str__(self):
        return f"{self.original_filename} - {self.upload_date.strftime('%Y-%m-%d %H:%M')}"


class TimelineEvent(models.Model):
    EVENT_TYPES = [
        ('created', 'File Created'),
        ('modified', 'File Modified'),
        ('accessed', 'File Accessed'),
        ('deleted', 'File Deleted'),
        ('network', 'Network Connection'),
        ('process', 'Process Execution'),
        ('registry', 'Registry Change'),
        ('login', 'User Login'),
        ('other', 'Other'),
    ]
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='timeline_events', null=True, blank=True)
    forensic_file = models.ForeignKey(ForensicFile, on_delete=models.CASCADE, related_name='timeline_events', null=True, blank=True)
    event_time = models.DateTimeField()
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES, default='other')
    source = models.CharField(max_length=255)
    description = models.TextField()
    artifact_path = models.CharField(max_length=1000, blank=True)
    artifact_hash = models.CharField(max_length=64, blank=True)
    raw_data = models.TextField(blank=True)

    class Meta:
        ordering = ['event_time']
        verbose_name = 'Timeline Event'
        verbose_name_plural = 'Timeline Events'

    def __str__(self):
        return f"{self.event_time} - {self.event_type}: {self.description[:50]}"


class IOCIndicator(models.Model):
    IOC_TYPES = [
        ('md5', 'MD5 Hash'),
        ('sha1', 'SHA1 Hash'),
        ('sha256', 'SHA256 Hash'),
        ('ipv4', 'IPv4 Address'),
        ('ipv6', 'IPv6 Address'),
        ('domain', 'Domain Name'),
        ('url', 'URL'),
        ('email', 'Email Address'),
        ('filepath', 'File Path'),
        ('registry_key', 'Registry Key'),
        ('mutex', 'Mutex Name'),
        ('yara_match', 'YARA Match'),
        ('crypto_wallet', 'Crypto Wallet Address'),
        ('other', 'Other'),
    ]
    CONFIDENCE_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    ioc_type = models.CharField(max_length=20, choices=IOC_TYPES)
    ioc_value = models.TextField()
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES, default='medium')
    source = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    forensic_file = models.ForeignKey(ForensicFile, on_delete=models.CASCADE, related_name='iocs', null=True, blank=True)
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='iocs', null=True, blank=True)
    mitre_technique = models.CharField(max_length=50, blank=True)
    tags = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ['-first_seen']
        verbose_name = 'IOC Indicator'
        verbose_name_plural = 'IOC Indicators'
        unique_together = [('ioc_type', 'ioc_value')]

    def __str__(self):
        return f"{self.ioc_type}: {self.ioc_value[:50]}"


class ForensicReport(models.Model):
    REPORT_TYPES = [
        ('executive', 'Executive Summary'),
        ('technical', 'Full Technical Report'),
        ('ioc', 'IOC Report'),
        ('timeline', 'Timeline Report'),
        ('chain_of_custody', 'Chain of Custody Report'),
    ]
    FORMAT_CHOICES = [
        ('pdf', 'PDF'),
        ('html', 'HTML'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
    ]
    case = models.ForeignKey(ForensicCase, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES, default='technical')
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='pdf')
    title = models.CharField(max_length=255)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_at = models.DateTimeField(default=timezone.now)
    file_path = models.CharField(max_length=1000, blank=True)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ['-generated_at']
        verbose_name = 'Forensic Report'
        verbose_name_plural = 'Forensic Reports'

    def __str__(self):
        return f"{self.title} ({self.generated_at.strftime('%Y-%m-%d')})"


class AnalysisTask(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    TASK_TYPES = [
        ('disk', 'Disk Analysis'),
        ('memory', 'Memory Analysis'),
        ('network', 'Network Analysis'),
        ('timeline', 'Timeline Generation'),
        ('ioc', 'IOC Extraction'),
        ('yara', 'YARA Scan'),
        ('hash', 'Hash Verification'),
        ('report', 'Report Generation'),
    ]
    forensic_file = models.ForeignKey(ForensicFile, on_delete=models.CASCADE, related_name='tasks', null=True, blank=True)
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='tasks', null=True, blank=True)
    task_type = models.CharField(max_length=20, choices=TASK_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True)
    result_summary = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    progress_percent = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Analysis Task'
        verbose_name_plural = 'Analysis Tasks'

    def __str__(self):
        return f"{self.task_type} - {self.status}"


class YARARule(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    rule_content = models.TextField()
    tags = models.CharField(max_length=500, blank=True)
    author = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'YARA Rule'
        verbose_name_plural = 'YARA Rules'

    def __str__(self):
        return self.name


class HashSet(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    hash_type = models.CharField(max_length=20, default='sha256')
    source = models.CharField(max_length=255, blank=True)
    entry_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['name']
        verbose_name = 'Hash Set'
        verbose_name_plural = 'Hash Sets'

    def __str__(self):
        return f"{self.name} ({self.entry_count} hashes)"


class Artifact(models.Model):
    ARTIFACT_TYPES = [
        ('registry_key', 'Registry Key'),
        ('browser_history', 'Browser History'),
        ('email', 'Email'),
        ('document', 'Document'),
        ('image', 'Image'),
        ('executable', 'Executable'),
        ('prefetch', 'Prefetch File'),
        ('lnk', 'LNK File'),
        ('event_log', 'Event Log Entry'),
        ('usb_device', 'USB Device'),
        ('network_connection', 'Network Connection'),
        ('user_account', 'User Account'),
        ('installed_software', 'Installed Software'),
        ('other', 'Other'),
    ]
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='artifacts', null=True, blank=True)
    forensic_file = models.ForeignKey(ForensicFile, on_delete=models.CASCADE, related_name='artifacts', null=True, blank=True)
    artifact_type = models.CharField(max_length=30, choices=ARTIFACT_TYPES)
    name = models.CharField(max_length=500)
    value = models.TextField(blank=True)
    path = models.CharField(max_length=1000, blank=True)
    timestamp = models.DateTimeField(null=True, blank=True)
    extra_data = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Artifact'
        verbose_name_plural = 'Artifacts'

    def __str__(self):
        return f"{self.artifact_type}: {self.name[:50]}"


class NetworkConnection(models.Model):
    PROTOCOL_CHOICES = [
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('icmp', 'ICMP'),
        ('http', 'HTTP'),
        ('https', 'HTTPS'),
        ('dns', 'DNS'),
        ('ftp', 'FTP'),
        ('smtp', 'SMTP'),
        ('ssh', 'SSH'),
        ('smb', 'SMB'),
        ('other', 'Other'),
    ]
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='network_connections', null=True, blank=True)
    forensic_file = models.ForeignKey(ForensicFile, on_delete=models.CASCADE, related_name='network_connections', null=True, blank=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, choices=PROTOCOL_CHOICES, default='tcp')
    state = models.CharField(max_length=50, blank=True)
    process_name = models.CharField(max_length=255, blank=True)
    pid = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField(null=True, blank=True)
    bytes_sent = models.BigIntegerField(null=True, blank=True)
    bytes_received = models.BigIntegerField(null=True, blank=True)
    geo_country = models.CharField(max_length=100, blank=True)
    geo_city = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Network Connection'
        verbose_name_plural = 'Network Connections'

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol})"


class ProcessInfo(models.Model):
    evidence_item = models.ForeignKey(EvidenceItem, on_delete=models.CASCADE, related_name='processes', null=True, blank=True)
    forensic_file = models.ForeignKey(ForensicFile, on_delete=models.CASCADE, related_name='processes', null=True, blank=True)
    pid = models.IntegerField()
    ppid = models.IntegerField(null=True, blank=True)
    name = models.CharField(max_length=255)
    path = models.CharField(max_length=1000, blank=True)
    command_line = models.TextField(blank=True)
    username = models.CharField(max_length=255, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    exit_time = models.DateTimeField(null=True, blank=True)
    is_hidden = models.BooleanField(default=False)
    is_injected = models.BooleanField(default=False)
    dll_list = models.TextField(blank=True)
    md5_hash = models.CharField(max_length=32, blank=True)
    sha256_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ['pid']
        verbose_name = 'Process Info'
        verbose_name_plural = 'Process Info'

    def __str__(self):
        return f"PID {self.pid}: {self.name}"
