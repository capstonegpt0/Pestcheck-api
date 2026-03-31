from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_maoandadmin'),
    ]

    operations = [
        # Add created_by to Farm - missing from 0001_initial
        migrations.AddField(
            model_name='farm',
            name='created_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='farms_created',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]