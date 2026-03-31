from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_createdby'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pestdetection',
            name='pest_name',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]