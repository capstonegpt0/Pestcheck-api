from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_user_block'),
    ]

    operations = [
        # Make rsbsa_number unique across all VerificationRequests
        migrations.AlterField(
            model_name='verificationrequest',
            name='rsbsa_number',
            field=models.CharField(
                max_length=100,
                unique=True,
                help_text='RSBSA Registration Number',
            ),
        ),
        # Add FileExtensionValidator to valid_id_image
        migrations.AlterField(
            model_name='verificationrequest',
            name='valid_id_image',
            field=models.ImageField(
                upload_to='verification_ids/',
                help_text='Valid government-issued ID',
                validators=[
                    django.core.validators.FileExtensionValidator(
                        allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff']
                    )
                ],
            ),
        ),
    ]