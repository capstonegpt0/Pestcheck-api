from django.db import migrations

def create_admin_user(apps, schema_editor):
    User = apps.get_model('api', 'User')
    if not User.objects.filter(role='admin').exists():
        User.objects.create_superuser(
            username='admin',
            email='admin@pestcheck.com',
            password='admin123',
            role='admin',
            is_verified=True,
            is_staff=True,
            is_superuser=True,
        )

def reverse_admin(apps, schema_editor):
    User = apps.get_model('api', 'User')
    User.objects.filter(username='admin', role='admin').delete()

class Migration(migrations.Migration):
    dependencies = [
        ('api', '0006_notification'),
    ]
    operations = [
        migrations.RunPython(create_admin_user, reverse_admin),
    ]