# Generated migration file
# Place this in your api/migrations/ directory with a sequential number
# e.g., api/migrations/0008_pestdetection_confirmed.py

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_populate_pest_data'),  # Update this to your last migration number
    ]

    operations = [
        migrations.AddField(
            model_name='pestdetection',
            name='confirmed',
            field=models.BooleanField(default=False, help_text='Whether user confirmed this detection is correct'),
        ),
    ]