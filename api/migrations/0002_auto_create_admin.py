# Save this as: api/migrations/0002_auto_create_admin.py
# This will automatically create an admin user when you run migrations on Render

from django.db import migrations
from django.contrib.auth.hashers import make_password
import os


def create_admin_user(apps, schema_editor):
    User = apps.get_model('api', 'User')
    
    # Get credentials from environment variables or use defaults
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    email = os.environ.get('ADMIN_EMAIL', 'admin@pestcheck.com')
    password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    # Only create if no admin exists
    if not User.objects.filter(role='admin').exists():
        User.objects.create(
            username=username,
            email=email,
            password=make_password(password),
            first_name='Admin',
            last_name='User',
            role='admin',
            is_verified=True,
            is_staff=True,
            is_superuser=True,
            is_active=True
        )
        print(f'✅ Admin user created: {username}')
    else:
        print('ℹ️ Admin user already exists, skipping...')


def remove_admin_user(apps, schema_editor):
    User = apps.get_model('api', 'User')
    # Only remove if it's the default admin
    User.objects.filter(username='admin', role='admin').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),  # Replace with your actual last migration number
    ]

    operations = [
        migrations.RunPython(create_admin_user, remove_admin_user),
    ]
