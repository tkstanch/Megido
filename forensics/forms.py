"""
Forms for the Forensics app.

Provides a file upload form for forensic analysis.
"""
from django import forms
from .models import ForensicFile


class ForensicFileUploadForm(forms.ModelForm):
    """
    Form for uploading forensic files for analysis.
    
    Accepts various file types including:
    - Forensic disk images (dd, E01, AFF, etc.)
    - Smartphone backups (Android, iOS)
    - System backups
    - Log files
    - Memory dumps
    - Archive files (zip, tar, etc.)
    """
    
    class Meta:
        model = ForensicFile
        fields = ['uploaded_file']
        widgets = {
            'uploaded_file': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '*/*',  # Accept all file types for forensic analysis
            })
        }
        labels = {
            'uploaded_file': 'Select Forensic File'
        }
        help_texts = {
            'uploaded_file': 'Upload a forensic image, backup file, or log file for analysis.'
        }
