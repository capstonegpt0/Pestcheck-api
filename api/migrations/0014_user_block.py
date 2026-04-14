from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_add_barangay'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_blocked',
            field=models.BooleanField(
                default=False,
                help_text='Account blocked by admin due to repeated rejected detections',
            ),
        ),
        migrations.AddField(
            model_name='user',
            name='rejected_detection_count',
            field=models.PositiveIntegerField(
                default=0,
                help_text='Number of detection reports rejected by staff',
            ),
        ),
    ]