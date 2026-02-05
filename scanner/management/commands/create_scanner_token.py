"""
Management command to create or retrieve an API token for a user.
Usage: python manage.py create_scanner_token --username <username>
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    help = 'Creates or retrieves an API token for the specified user'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            required=True,
            help='Username for which to create or retrieve the API token'
        )

    def handle(self, *args, **options):
        username = options['username']
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f'User "{username}" does not exist')
        
        # Get or create the token for the user
        token, created = Token.objects.get_or_create(user=user)
        
        if created:
            self.stdout.write(self.style.SUCCESS(
                f'Successfully created new API token for user "{username}"'
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f'Retrieved existing API token for user "{username}"'
            ))
        
        self.stdout.write('\n' + '=' * 70)
        self.stdout.write('API TOKEN:')
        self.stdout.write(self.style.WARNING(token.key))
        self.stdout.write('=' * 70)
        self.stdout.write('\nUse this token in your API requests:')
        self.stdout.write('  Authorization: Token <your-token-here>\n')
        self.stdout.write('\nExample with curl:')
        self.stdout.write(f'  curl -H "Authorization: Token {token.key}" http://localhost:8000/scanner/api/targets/\n')
