from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Add 'detection_verified' and 'detection_rejected' to
    Notification.notification_type choices.

    Django stores CharField choices only in Python — no DB schema change
    is needed, but we still create a migration so the project history is
    consistent and the field's max_length stays in sync.
    """

    dependencies = [
        ('api', '0011_detectionfix'),   # last migration in the chain
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='notification_type',
            field=models.CharField(
                choices=[
                    ('detection_nearby',       'Pest Detection Nearby'),
                    ('verification_approved',  'Verification Approved'),
                    ('verification_rejected',  'Verification Rejected'),
                    ('farm_approved',          'Farm Request Approved'),
                    ('farm_rejected',          'Farm Request Rejected'),
                    ('admin_alert',            'Admin Alert'),
                    ('critical_pest',          'Critical Pest Alert'),
                    ('system',                 'System Notification'),
                    ('detection_verified',     'Detection Verified'),
                    ('detection_rejected',     'Detection Rejected'),
                ],
                max_length=30,
            ),
        ),
    ]