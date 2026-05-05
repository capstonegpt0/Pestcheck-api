"""
Data migration to update default admin user password.
Place in: backend/api/migrations/0003_update_admin_password.py
"""

from django.db import migrations


def update_admin_password(apps, schema_editor):
    """Update default admin user password"""
    User = apps.get_model('api', 'User')

    try:
        user = User.objects.get(username='admin', role='admin')
        user.set_password('pestcheckadmin04072026')  # ← change this
        user.save()
    except User.DoesNotExist:
        pass


def reverse_migration(apps, schema_editor):
    """Revert admin password back to original"""
    User = apps.get_model('api', 'User')

    try:
        user = User.objects.get(username='admin', role='admin')
        user.set_password('admin123')
        user.save()
    except User.DoesNotExist:
        pass


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0017_backfill'),
    ]

    operations = [
        migrations.RunPython(update_admin_password, reverse_migration),
    ]