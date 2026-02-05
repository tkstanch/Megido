from django.core.management.base import BaseCommand
from app_manager.models import AppConfiguration


class Command(BaseCommand):
    help = 'Populate initial app configuration data'

    def handle(self, *args, **options):
        apps_data = [
            {
                'app_name': 'proxy',
                'display_name': 'HTTP Proxy',
                'description': 'HTTP interception and traffic analysis',
                'icon': '🔄',
                'category': 'interception',
                'capabilities': 'intercept, analyze, modify',
            },
            {
                'app_name': 'spider',
                'display_name': 'Web Spider',
                'description': 'Web crawling and content discovery',
                'icon': '🕷️',
                'category': 'discovery',
                'capabilities': 'crawl, discover, map',
            },
            {
                'app_name': 'scanner',
                'display_name': 'Vulnerability Scanner',
                'description': 'Automated vulnerability scanning',
                'icon': '🔍',
                'category': 'scanning',
                'capabilities': 'scan, detect, report',
            },
            {
                'app_name': 'repeater',
                'display_name': 'Request Repeater',
                'description': 'Manual request repeating and testing',
                'icon': '🔁',
                'category': 'testing',
                'capabilities': 'repeat, modify, test',
            },
            {
                'app_name': 'interceptor',
                'display_name': 'Request Interceptor',
                'description': 'Real-time request interception',
                'icon': '✋',
                'category': 'interception',
                'capabilities': 'intercept, modify, forward',
            },
            {
                'app_name': 'mapper',
                'display_name': 'Attack Surface Mapper',
                'description': 'Attack surface analysis and mapping',
                'icon': '🗺️',
                'category': 'analysis',
                'capabilities': 'map, analyze, identify',
            },
            {
                'app_name': 'bypasser',
                'display_name': 'WAF Bypasser',
                'description': 'WAF and filter bypassing techniques',
                'icon': '🚧',
                'category': 'evasion',
                'capabilities': 'bypass, evade, probe',
            },
            {
                'app_name': 'collaborator',
                'display_name': 'Collaborator',
                'description': 'Out-of-band interaction tracking',
                'icon': '🤝',
                'category': 'detection',
                'capabilities': 'track, monitor, detect',
            },
            {
                'app_name': 'decompiler',
                'display_name': 'Extension Decompiler',
                'description': 'Browser extension analysis',
                'icon': '📦',
                'category': 'analysis',
                'capabilities': 'decompile, analyze, extract',
            },
            {
                'app_name': 'malware_analyser',
                'display_name': 'Malware Analyser',
                'description': 'Malware analysis and detection',
                'icon': '🦠',
                'category': 'security',
                'capabilities': 'scan, analyze, detect',
            },
            {
                'app_name': 'response_analyser',
                'display_name': 'Response Analyser',
                'description': 'HTTP response vulnerability detection',
                'icon': '📊',
                'category': 'analysis',
                'capabilities': 'analyze, detect, report',
            },
            {
                'app_name': 'sql_attacker',
                'display_name': 'SQL Attacker',
                'description': 'SQL injection testing and exploitation',
                'icon': '💉',
                'category': 'exploitation',
                'capabilities': 'inject, exploit, extract',
            },
            {
                'app_name': 'data_tracer',
                'display_name': 'Data Tracer',
                'description': 'Network scanning and traffic analysis',
                'icon': '📡',
                'category': 'reconnaissance',
                'capabilities': 'scan, trace, fingerprint',
            },
            {
                'app_name': 'discover',
                'display_name': 'OSINT Discover',
                'description': 'OSINT gathering and reconnaissance',
                'icon': '🎯',
                'category': 'reconnaissance',
                'capabilities': 'gather, search, enumerate',
            },
            {
                'app_name': 'manipulator',
                'display_name': 'Payload Manipulator',
                'description': 'Payload crafting and manipulation',
                'icon': '🔧',
                'category': 'exploitation',
                'capabilities': 'craft, encode, manipulate',
            },
        ]

        created_count = 0
        updated_count = 0

        for app_data in apps_data:
            app_config, created = AppConfiguration.objects.get_or_create(
                app_name=app_data['app_name'],
                defaults=app_data
            )
            
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f'Created: {app_data["display_name"]}'))
            else:
                # Update existing app
                for key, value in app_data.items():
                    setattr(app_config, key, value)
                app_config.save()
                updated_count += 1
                self.stdout.write(self.style.WARNING(f'Updated: {app_data["display_name"]}'))

        self.stdout.write(self.style.SUCCESS(
            f'\nSummary: {created_count} created, {updated_count} updated'
        ))
