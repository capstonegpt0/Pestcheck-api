from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_add_request_verification'),
    ]

    operations = [
        migrations.CreateModel(
            name='NotificationPreference',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('push_enabled', models.BooleanField(default=True)),
                ('detection_alerts', models.BooleanField(default=True)),
                ('critical_alerts', models.BooleanField(default=True)),
                ('push_subscription', models.JSONField(blank=True, help_text='Web Push subscription JSON', null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='notification_preferences', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'notification_preferences',
            },
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('notification_type', models.CharField(choices=[
                    ('detection_nearby', 'Pest Detection Nearby'),
                    ('verification_approved', 'Verification Approved'),
                    ('verification_rejected', 'Verification Rejected'),
                    ('farm_approved', 'Farm Request Approved'),
                    ('farm_rejected', 'Farm Request Rejected'),
                    ('admin_alert', 'Admin Alert'),
                    ('critical_pest', 'Critical Pest Alert'),
                    ('system', 'System Notification'),
                ], max_length=30)),
                ('title', models.CharField(max_length=200)),
                ('message', models.TextField()),
                ('is_read', models.BooleanField(default=False)),
                ('related_id', models.IntegerField(blank=True, help_text='ID of related object (detection, farm, etc.)', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'notifications',
                'ordering': ['-created_at'],
            },
        ),
    ]