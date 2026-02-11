from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        # Update this to match your latest migration number
        ('api', '0004_migrations'),
    ]

    operations = [
        migrations.CreateModel(
            name='VerificationRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rsbsa_number', models.CharField(help_text='RSBSA Registration Number', max_length=100)),
                ('valid_id_image', models.ImageField(help_text='Valid government-issued ID', upload_to='verification_ids/')),
                ('notes', models.TextField(blank=True, help_text='Additional notes from the user')),
                ('status', models.CharField(
                    choices=[('pending', 'Pending Review'), ('approved', 'Approved'), ('rejected', 'Rejected')],
                    default='pending',
                    max_length=20
                )),
                ('review_notes', models.TextField(blank=True, help_text='Admin feedback on the request')),
                ('reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='verification_requests',
                    to='api.user'
                )),
                ('reviewed_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='reviewed_verification_requests',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'verification_requests',
                'ordering': ['-created_at'],
            },
        ),
    ]