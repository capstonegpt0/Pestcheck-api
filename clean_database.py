"""
Django management command to clean database while preserving admin accounts.
Place this file in: backend/api/management/commands/clean_database.py
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from api.models import Detection, PestReport, UserProfile  # Adjust imports based on your models
from detections.models import Detection as DetectionModel  # If you have this

User = get_user_model()

class Command(BaseCommand):
    help = 'Removes all data except admin accounts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm deletion without prompting',
        )

    def handle(self, *args, **options):
        if not options['confirm']:
            confirm = input('This will delete all non-admin users and their data. Type "yes" to continue: ')
            if confirm.lower() != 'yes':
                self.stdout.write(self.style.WARNING('Operation cancelled.'))
                return

        # Count before deletion
        total_users = User.objects.exclude(is_superuser=True).count()
        
        # Delete detections/reports (adjust model names as needed)
        try:
            detection_count = Detection.objects.all().count()
            Detection.objects.all().delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {detection_count} detections'))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'No Detection model or error: {e}'))

        try:
            detection_count = DetectionModel.objects.all().count()
            DetectionModel.objects.all().delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {detection_count} detection records'))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'No DetectionModel or error: {e}'))

        # Delete non-admin users
        User.objects.exclude(is_superuser=True).delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {total_users} non-admin users'))

        # Show remaining admin accounts
        admins = User.objects.filter(is_superuser=True)
        self.stdout.write(self.style.SUCCESS(f'\nRemaining admin accounts:'))
        for admin in admins:
            self.stdout.write(f'  - {admin.username} ({admin.email})')