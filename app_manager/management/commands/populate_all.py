"""
Management command to populate initial data for all apps in one step.
"""
from django.core.management.base import BaseCommand
from django.core.management import call_command


COMMANDS = [
    'populate_apps',
    'populate_manipulator_data',
    'populate_malware_data',
]


class Command(BaseCommand):
    help = 'Populate initial data for all apps (populate_apps, populate_manipulator_data, populate_malware_data)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--stop-on-error',
            action='store_true',
            dest='stop_on_error',
            help='Stop execution on the first command failure instead of continuing.',
        )

    def handle(self, *args, **options):
        stop_on_error = options['stop_on_error']
        succeeded = []
        failed = []

        self.stdout.write('=' * 60)
        self.stdout.write('Populating all initial data...')
        self.stdout.write('=' * 60)

        for command_name in COMMANDS:
            self.stdout.write('')
            self.stdout.write('-' * 60)
            self.stdout.write(f'Running: {command_name}')
            self.stdout.write('-' * 60)
            try:
                call_command(command_name, stdout=self.stdout, stderr=self.stderr)
                succeeded.append(command_name)
                self.stdout.write(self.style.SUCCESS(f'✓ {command_name} completed successfully'))
            except Exception as exc:
                failed.append(command_name)
                self.stderr.write(self.style.ERROR(f'✗ {command_name} failed: {exc}'))
                if stop_on_error:
                    self.stdout.write('')
                    self.stdout.write('=' * 60)
                    self.stdout.write('Stopped due to --stop-on-error flag.')
                    self._print_summary(succeeded, failed)
                    return

        self.stdout.write('')
        self.stdout.write('=' * 60)
        self._print_summary(succeeded, failed)

    def _print_summary(self, succeeded, failed):
        self.stdout.write('Summary:')
        for name in succeeded:
            self.stdout.write(self.style.SUCCESS(f'  ✓ {name}'))
        for name in failed:
            self.stdout.write(self.style.ERROR(f'  ✗ {name}'))
        self.stdout.write('=' * 60)
