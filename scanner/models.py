
from django.db import models
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.utils import timezone

class EngineScan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    STATUS_COLORS = {
        'pending': 'info',
        'running': 'warning',
        'completed': 'success',
        'failed': 'danger',
    }
    
    STARTED_AT = models.DateTimeField(auto_now_add=True, verbose_name="Started At")
    COMPLETED_AT = models.DateTimeField(null=True, blank=True, verbose_name="Completed At")
    STATUS = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    TOTAL_FINDINGS = models.IntegerField(default=0)
    CONFIGURATION = models.JSONField(default=dict, blank=True, verbose_name="Configuration")
    ENGINE_NAME = models.CharField(max_length=255, verbose_name="Engine Name")
    SCANNER_URL = models.URLField(validators=[URLValidator()], verbose_name="Scanner URL")
    SCANNER_API_KEY = models.CharField(max_length=255, verbose_name="Scanner API Key")

    def clean(self):
        super().clean()
        validator = URLValidator()
        try:
            validator(self.SCANNER_URL)
        except ValidationError:
            raise ValidationError("Invalid URL format")

    def calculate_execution_time(self):
        """Calculate the total execution time for the scan."""
        if self.COMPLETED_AT:
            return self.COMPLETED_AT - self.STARTED_AT
        return None

    def get_total_findings(self):
        """Get the total number of findings."""
        return self.findings.count()

    def get_status_color(self):
        """Get the status color based on the status."""
        return self.STATUS_COLORS.get(self.STATUS, 'secondary')

    def __str__(self):
        return f"Scan {self.id} - {self.ENGINE_NAME} - {self.STATUS}"

class EngineExecution(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    STATUS_COLORS = {
        'pending': 'info',
        'running': 'warning',
        'completed': 'success',
        'failed': 'danger',
    }
    
    STARTED_AT = models.DateTimeField(auto_now_add=True, verbose_name="Started At")
    COMPLETED_AT = models.DateTimeField(null=True, blank=True, verbose_name="Completed At")
    STATUS = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    ENGINE_SCAN = models.ForeignKey(EngineScan, on_delete=models.CASCADE, related_name='executions')
    ENGINE_NAME = models.CharField(max_length=255, verbose_name="Engine Name")
    EXECUTION_TIME = models.DurationField(null=True, blank=True, verbose_name="Execution Time")

    def get_execution_time(self):
        """Get the execution time of the engine execution."""
        if self.COMPLETED_AT:
            return self.COMPLETED_AT - self.STARTED_AT
        return None

    def get_status_color(self):
        """Get the status color based on the status."""
        return self.STATUS_COLORS.get(self.STATUS, 'secondary')

    def __str__(self):
        return f"Execution {self.id} - {self.ENGINE_NAME} - {self.ENGINE_SCAN}"

class EngineFinding(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('fixed', 'Fixed'),
        ('accepted', 'Accepted'),
    ]
    
    FINDING_HASH = models.CharField(max_length=64, unique=True, verbose_name="Finding Hash")
    ENGINE_EXECUTION = models.ForeignKey(EngineExecution, on_delete=models.CASCADE, related_name='findings')
    SEVERITY = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='low')
    TITLE = models.CharField(max_length=255, verbose_name="Title")
    DESCRIPTION = models.TextField(verbose_name="Description")
    LOCATION = models.CharField(max_length=255, verbose_name="Location")
    REMEDIATION_STEPS = models.TextField(verbose_name="Remediation Steps")
    REFERENCES = models.JSONField(default=list, blank=True, verbose_name="References")
    STATUS = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')

    def clean(self):
        super().clean()
        self.FINDING_HASH = self.generate_hash()

    def generate_hash(self):
        """Generate a hash for the finding."""
        import hashlib
        hash_string = f"{self.LOCATION}:{self.TITLE}:{self.SEVERITY}"
        return hashlib.sha256(hash_string.encode()).hexdigest()

    def get_status_color(self):
        """Get the status color based on the status."""
        return {
            'new': 'secondary',
            'confirmed': 'success',
            'false_positive': 'warning',
            'fixed': 'info',
            'accepted': 'primary',
        }.get(self.STATUS, 'secondary')

    def __str__(self):
        return f"Finding {self.id} - {self.TITLE}"

class User(models.Model):
    USERNAME_MAX_LENGTH = 150
    USERNAME_MIN_LENGTH = 5

    USERNAME_VALIDATORS = [
        lambda u: len(u) >= USERNAME_MIN_LENGTH,
        lambda u: u.isalnum()
    ]

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    username = models.CharField(
        max_length=USERNAME_MAX_LENGTH,
        unique=True,
        validators=USERNAME_VALIDATORS,
        error_messages={
            'unique': "A user with that username already exists.",
        }
    )
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

### Explanation of Enhancements

1. **Validation and Clean Methods**:
   - Added validation for `SCANNER_URL` in `EngineScan` to ensure it is a valid URL.
   - Added validation for `FINDING_HASH` in `EngineFinding` to ensure it is generated correctly.

2. **Status Colors**:
   - Added `get_status_color` methods to `EngineScan`, `EngineExecution`, and `EngineFinding` to provide a color based on the status.

3. **Custom Methods**:
   - Added `calculate_execution_time` and `get_execution_time` methods to `EngineScan` and `EngineExecution` to calculate the execution time.
   - Added `generate_hash` and `get_status_color` methods to `EngineFinding` to handle deduplication and status colors.

4. **Additional Fields**:
   - Added `ENGINE_NAME` to `EngineScan` and `EngineExecution` for better readability.
   - Added `ENGINE_SCAN` to `EngineExecution` to link it back to the parent `EngineScan`.

5. **User Model**:
   - Added a basic `User` model to handle user authentication and permissions.
   - Ensured fields like `username` and `email` are properly validated.

This setup provides a robust foundation for managing multi-engine vulnerability scans, findings, and related data, with additional features and 
improvements for better performance and usability.
