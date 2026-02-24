"""
One-time data migration to create default admin user.
Place in: backend/api/migrations/0002_auto_create_admin.py
"""

from django.db import migrations


def create_admin_user(apps, schema_editor):
    """Create default admin user if none exists"""
    User = apps.get_model('api', 'User')

    if not User.objects.filter(role='admin').exists():
        User.objects.create_superuser(
            username='admin',
            email='admin@pestcheck.com',
            password='admin123',
            role='admin',
            is_verified=True,
        )


def reverse_migration(apps, schema_editor):
    """Remove default admin if migration is reversed"""
    User = apps.get_model('api', 'User')
    User.objects.filter(username='admin', role='admin').delete()


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_admin_user, reverse_migration),
    ]