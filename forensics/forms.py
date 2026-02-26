"""Forms for the Forensics app."""
from django import forms
from .models import ForensicFile, ForensicCase, EvidenceItem


class ForensicFileUploadForm(forms.ModelForm):
    class Meta:
        model = ForensicFile
        fields = ['uploaded_file']
        widgets = {
            'uploaded_file': forms.FileInput(attrs={'class': 'form-control', 'accept': '*/*'})
        }
        labels = {'uploaded_file': 'Select Forensic File'}
        help_texts = {'uploaded_file': 'Upload a forensic image, backup file, or log file for analysis.'}


class ForensicCaseForm(forms.ModelForm):
    class Meta:
        model = ForensicCase
        fields = ['case_number', 'title', 'description', 'status', 'classification', 'tags']
        widgets = {
            'case_number': forms.TextInput(attrs={'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'status': forms.Select(attrs={'class': 'form-select'}),
            'classification': forms.Select(attrs={'class': 'form-select'}),
            'tags': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'tag1, tag2, ...'}),
        }


class EvidenceItemForm(forms.ModelForm):
    class Meta:
        model = EvidenceItem
        fields = ['name', 'description', 'acquisition_type', 'storage_location', 'notes']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'acquisition_type': forms.Select(attrs={'class': 'form-select'}),
            'storage_location': forms.TextInput(attrs={'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }
