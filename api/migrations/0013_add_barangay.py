from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_add_notification_types'),
    ]

    operations = [
        migrations.AddField(
            model_name='farmrequest',
            name='barangay',
            field=models.CharField(
                blank=True,
                max_length=100,
                help_text='Barangay in Magalang, Pampanga where the farm is located',
            ),
        ),
        migrations.AddField(
            model_name='farm',
            name='barangay',
            field=models.CharField(
                blank=True,
                max_length=100,
                help_text='Barangay in Magalang, Pampanga where the farm is located',
            ),
        ),
    ]