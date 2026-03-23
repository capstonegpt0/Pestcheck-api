from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_notification'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[
                    ('admin', 'Administrator'),
                    ('mao_staff', 'MAO Staff'),
                    ('farmer', 'Farmer'),
                ],
                default='farmer',
                max_length=20
            ),
        ),
    ]