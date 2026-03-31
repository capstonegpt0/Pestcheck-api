from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_farmrequest'),
    ]

    operations = [
        # Only add address to Farm - FarmRequest already has it from 0008
        # User.role mao_staff choice already added in 0007
        migrations.AddField(
            model_name='farm',
            name='address',
            field=models.CharField(
                blank=True,
                default='',
                help_text='General address or location description',
                max_length=500,
            ),
            preserve_default=False,
        ),
    ]