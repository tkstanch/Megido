"""
Management command to populate initial vulnerability types, payloads, and manipulation tricks.
"""
from django.core.management.base import BaseCommand
from manipulator.models import (
    VulnerabilityType, Payload, EncodingTechnique, PayloadManipulation
)
from manipulator.initial_data import (
    VULNERABILITY_TYPES, PAYLOADS, MANIPULATION_TRICKS, ENCODING_TECHNIQUES
)


class Command(BaseCommand):
    help = 'Populate initial data for manipulator app (vulnerabilities, payloads, encodings, tricks)'

    def sanitize_text(self, text):
        """
        Remove NUL (\\x00) characters from text fields to prevent database errors.
        
        Args:
            text: String that may contain NUL characters
            
        Returns:
            Sanitized string with NUL characters removed
        """
        if not isinstance(text, str):
            return text
        
        if '\x00' in text:
            sanitized = text.replace('\x00', '')
            self.stdout.write(self.style.WARNING(
                f'  ⚠ Removed NUL character from text: "{text[:50]}..."'
            ))
            return sanitized
        return text

    def handle(self, *args, **options):
        self.stdout.write('Populating initial data...')
        
        # Create vulnerability types
        self.stdout.write('Creating vulnerability types...')
        vuln_map = {}
        for vuln_data in VULNERABILITY_TYPES:
            vuln, created = VulnerabilityType.objects.get_or_create(
                name=self.sanitize_text(vuln_data['name']),
                defaults={
                    'description': self.sanitize_text(vuln_data['description']),
                    'category': self.sanitize_text(vuln_data['category']),
                    'severity': vuln_data['severity'],
                }
            )
            vuln_map[vuln.name] = vuln
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Created {vuln.name}'))
            else:
                self.stdout.write(f'  - {vuln.name} already exists')
        
        # Create payloads
        self.stdout.write('\nCreating payloads...')
        payload_count = 0
        for vuln_name, payloads_list in PAYLOADS.items():
            if vuln_name in vuln_map:
                vuln = vuln_map[vuln_name]
                for payload_data in payloads_list:
                    payload, created = Payload.objects.get_or_create(
                        vulnerability=vuln,
                        name=self.sanitize_text(payload_data['name']),
                        defaults={
                            'payload_text': self.sanitize_text(payload_data['payload_text']),
                            'description': self.sanitize_text(payload_data['description']),
                            'bypass_technique': self.sanitize_text(payload_data.get('bypass_technique', '')),
                            'platform': self.sanitize_text(payload_data.get('platform', '')),
                            'is_custom': False,
                        }
                    )
                    if created:
                        payload_count += 1
                        self.stdout.write(f'  ✓ Created {payload.name} for {vuln_name}')
        
        self.stdout.write(self.style.SUCCESS(f'Created {payload_count} payloads'))
        
        # Create manipulation tricks
        self.stdout.write('\nCreating manipulation tricks...')
        trick_count = 0
        for vuln_name, tricks_list in MANIPULATION_TRICKS.items():
            if vuln_name in vuln_map:
                vuln = vuln_map[vuln_name]
                for trick_data in tricks_list:
                    trick, created = PayloadManipulation.objects.get_or_create(
                        vulnerability=vuln,
                        name=self.sanitize_text(trick_data['name']),
                        defaults={
                            'technique': self.sanitize_text(trick_data['technique']),
                            'description': self.sanitize_text(trick_data['description']),
                            'effectiveness': trick_data.get('effectiveness', 'medium'),
                            'target_defense': self.sanitize_text(trick_data.get('target_defense', '')),
                            'example': self.sanitize_text(trick_data.get('example', '')),
                        }
                    )
                    if created:
                        trick_count += 1
                        self.stdout.write(f'  ✓ Created {trick.name} for {vuln_name}')
        
        self.stdout.write(self.style.SUCCESS(f'Created {trick_count} manipulation tricks'))
        
        # Create encoding techniques
        self.stdout.write('\nCreating encoding techniques...')
        encoding_count = 0
        for encoding_data in ENCODING_TECHNIQUES:
            encoding, created = EncodingTechnique.objects.get_or_create(
                name=self.sanitize_text(encoding_data['name']),
                defaults={
                    'description': self.sanitize_text(encoding_data['description']),
                    'encoding_type': self.sanitize_text(encoding_data['encoding_type']),
                    'is_reversible': encoding_data.get('is_reversible', True),
                }
            )
            if created:
                encoding_count += 1
                self.stdout.write(f'  ✓ Created {encoding.name}')
        
        self.stdout.write(self.style.SUCCESS(f'Created {encoding_count} encoding techniques'))
        
        self.stdout.write(self.style.SUCCESS('\n✓ Initial data population complete!'))
        self.stdout.write(f'Summary:')
        self.stdout.write(f'  - Vulnerability Types: {len(vuln_map)}')
        self.stdout.write(f'  - Payloads: {payload_count}')
        self.stdout.write(f'  - Manipulation Tricks: {trick_count}')
        self.stdout.write(f'  - Encoding Techniques: {encoding_count}')
