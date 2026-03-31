from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_farmreqest'),  # Replace with your actual last migration name
    ]

    operations = [
        # Add address field to FarmRequest
        migrations.AddField(
            model_name='farmrequest',
            name='address',
            field=models.CharField(
                blank=True,
                default='',
                help_text='General address or location description of the farm',
                max_length=500,
            ),
            preserve_default=False,
        ),

        # Add address field to Farm
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

        # Update the role field on User to include mao_staff choice
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
                max_length=20,
            ),
        ),
    ]