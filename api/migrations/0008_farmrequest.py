from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_add_mao_staff'),
    ]

    operations = [
        migrations.CreateModel(
            name='FarmRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('address', models.CharField(blank=True, help_text='General address or location description of the farm', max_length=500)),
                ('lat', models.FloatField(verbose_name='Latitude')),
                ('lng', models.FloatField(verbose_name='Longitude')),
                ('size', models.FloatField(blank=True, help_text='Size in hectares', null=True)),
                ('crop_type', models.CharField(blank=True, max_length=100, null=True)),
                ('description', models.TextField(blank=True, help_text='Additional information about the farm')),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending Review'),
                        ('approved', 'Approved'),
                        ('rejected', 'Rejected'),
                    ],
                    default='pending',
                    max_length=20
                )),
                ('review_notes', models.TextField(blank=True)),
                ('reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='farm_requests',
                    to='api.user'
                )),
                ('reviewed_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='reviewed_farm_requests',
                    to='api.user'
                )),
                ('approved_farm', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='original_request',
                    to='api.farm'
                )),
            ],
            options={
                'db_table': 'farm_requests',
                'ordering': ['-created_at'],
            },
        ),
    ]