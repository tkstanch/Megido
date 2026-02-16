from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import Vulnerability


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = [
        'attack_type', 
        'severity', 
        'short_url', 
        'short_payload', 
        'response_status_code',
        'detected_at',
        'is_confirmed',
        'false_positive',
        'view_html_link'
    ]
    list_filter = [
        'attack_type', 
        'severity', 
        'is_confirmed', 
        'false_positive',
        'detected_at',
        'response_status_code'
    ]
    search_fields = [
        'target_url', 
        'payload', 
        'endpoint', 
        'notes',
        'response_body'
    ]
    readonly_fields = [
        'detected_at', 
        'render_html_preview'
    ]
    fieldsets = (
        ('Vulnerability Information', {
            'fields': (
                'attack_type',
                'severity',
                'target_url',
                'endpoint',
                'payload',
            )
        }),
        ('Request Details', {
            'fields': (
                'request_method',
                'request_headers',
                'request_body',
            )
        }),
        ('Response Details', {
            'fields': (
                'response_status_code',
                'response_headers',
                'response_body',
                'evidence_html',
                'render_html_preview',
            )
        }),
        ('Analysis & Proof of Concept', {
            'fields': (
                'is_confirmed',
                'false_positive',
                'proof_of_impact',
                'notes',
                'detected_at',
            )
        }),
    )
    list_per_page = 50
    date_hierarchy = 'detected_at'
    
    def short_url(self, obj):
        """Display truncated URL"""
        url = obj.target_url
        if len(url) > 60:
            return url[:57] + "..."
        return url
    short_url.short_description = 'Target URL'
    
    def short_payload(self, obj):
        """Display truncated payload"""
        return obj.get_short_payload()
    short_payload.short_description = 'Payload'
    
    def view_html_link(self, obj):
        """Link to view the HTML in an iframe"""
        if obj.evidence_html:
            url = reverse('admin:response_analyser_view_html', args=[obj.pk])
            return format_html(
                '<a href="{}" target="_blank">View HTML</a>',
                url
            )
        return '-'
    view_html_link.short_description = 'Evidence'
    
    def render_html_preview(self, obj):
        """Render HTML preview in a sandboxed iframe within admin"""
        if obj.evidence_html:
            # Create a safe iframe that sandboxes the content
            return format_html(
                '<div style="border: 1px solid #ddd; padding: 10px; margin: 10px 0;">'
                '<p><strong>HTML Preview (Sandboxed):</strong></p>'
                '<iframe sandbox="" style="width: 100%; height: 400px; border: 1px solid #ccc;" '
                'srcdoc="{}"></iframe>'
                '</div>',
                obj.evidence_html.replace('"', '&quot;')
            )
        return format_html('<p>No HTML evidence captured</p>')
    render_html_preview.short_description = 'HTML Preview'
    
    def get_urls(self):
        """Add custom URL for viewing HTML"""
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path(
                '<int:pk>/view-html/',
                self.admin_site.admin_view(self.view_html),
                name='response_analyser_view_html',
            ),
        ]
        return custom_urls + urls
    
    def view_html(self, request, pk):
        """Custom view to display HTML in a sandboxed iframe"""
        from django.shortcuts import get_object_or_404, render
        vulnerability = get_object_or_404(Vulnerability, pk=pk)
        return render(request, 'admin/response_analyser/view_html.html', {
            'vulnerability': vulnerability,
            'title': f'HTML Evidence - {vulnerability.attack_type}',
        })
