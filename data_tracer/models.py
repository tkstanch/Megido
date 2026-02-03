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
