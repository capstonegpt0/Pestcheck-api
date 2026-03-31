from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_farmrequest'),
    ]

    operations = [

        # ==================== VerificationRequest ====================
        migrations.CreateModel(
            name='VerificationRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rsbsa_number', models.CharField(help_text='RSBSA Registration Number', max_length=100)),
                ('valid_id_image', models.ImageField(help_text='Valid government-issued ID', upload_to='verification_ids/')),
                ('notes', models.TextField(blank=True, help_text='Additional notes from the user')),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending Review'),
                        ('approved', 'Approved'),
                        ('rejected', 'Rejected'),
                    ],
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

        # ==================== Farm ====================
        migrations.CreateModel(
            name='Farm',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('address', models.CharField(blank=True, help_text='General address or location description', max_length=500)),
                ('lat', models.FloatField(verbose_name='Latitude')),
                ('lng', models.FloatField(verbose_name='Longitude')),
                ('size', models.FloatField(blank=True, help_text='Size in hectares', null=True)),
                ('crop_type', models.CharField(blank=True, max_length=100, null=True)),
                ('is_verified', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='farms',
                    to='api.user'
                )),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='farms_created',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'farms',
                'ordering': ['-created_at'],
            },
        ),

        # ==================== Add approved_farm FK to FarmRequest ====================
        migrations.AddField(
            model_name='farmrequest',
            name='approved_farm',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='original_request',
                to='api.farm'
            ),
        ),

        # ==================== PestDetection ====================
        migrations.CreateModel(
            name='PestDetection',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(blank=True, null=True, upload_to='pest_images/')),
                ('crop_type', models.CharField(
                    choices=[('rice', 'Rice'), ('corn', 'Corn')],
                    max_length=10
                )),
                ('pest_name', models.CharField(blank=True, max_length=255)),
                ('pest_type', models.CharField(blank=True, max_length=200, null=True)),
                ('confidence', models.FloatField(default=0.0)),
                ('severity', models.CharField(
                    choices=[
                        ('low', 'Low'),
                        ('medium', 'Medium'),
                        ('high', 'High'),
                        ('critical', 'Critical'),
                    ],
                    max_length=20
                )),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending Review'),
                        ('verified', 'Verified'),
                        ('rejected', 'Rejected'),
                        ('resolved', 'Resolved'),
                    ],
                    default='pending',
                    max_length=20
                )),
                ('latitude', models.FloatField()),
                ('longitude', models.FloatField()),
                ('address', models.CharField(blank=True, max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('active', models.BooleanField(default=True)),
                ('confirmed', models.BooleanField(default=False, help_text='Whether user confirmed this detection is correct')),
                ('detected_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('reported_at', models.DateTimeField(blank=True, null=True)),
                ('resolved_at', models.DateTimeField(blank=True, null=True)),
                ('admin_notes', models.TextField(blank=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='detections',
                    to='api.user'
                )),
                ('farm', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='detections',
                    to='api.farm'
                )),
                ('verified_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='verified_detections',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'pest_detections',
                'ordering': ['-detected_at'],
            },
        ),

        # ==================== PestInfo ====================
        migrations.CreateModel(
            name='PestInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('scientific_name', models.CharField(max_length=100)),
                ('crop_affected', models.CharField(max_length=50)),
                ('description', models.TextField()),
                ('symptoms', models.TextField()),
                ('control_methods', models.TextField()),
                ('prevention', models.TextField()),
                ('image_url', models.URLField(blank=True)),
                ('is_published', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'pest_info',
            },
        ),

        # ==================== InfestationReport ====================
        migrations.CreateModel(
            name='InfestationReport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('area_affected', models.FloatField(help_text='Area in hectares')),
                ('notes', models.TextField(blank=True)),
                ('is_verified', models.BooleanField(default=False)),
                ('reported_at', models.DateTimeField(auto_now_add=True)),
                ('detection', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='api.pestdetection'
                )),
                ('verified_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='verified_reports',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'infestation_reports',
            },
        ),

        # ==================== Alert ====================
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('message', models.TextField()),
                ('alert_type', models.CharField(
                    choices=[
                        ('warning', 'Warning'),
                        ('info', 'Information'),
                        ('critical', 'Critical'),
                    ],
                    default='info',
                    max_length=20
                )),
                ('target_area', models.CharField(blank=True, max_length=100)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'alerts',
                'ordering': ['-created_at'],
            },
        ),

        # ==================== UserActivity ====================
        migrations.CreateModel(
            name='UserActivity',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=100)),
                ('details', models.TextField(blank=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='activities',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'user_activities',
                'ordering': ['-timestamp'],
            },
        ),

        # ==================== NotificationPreference ====================
        migrations.CreateModel(
            name='NotificationPreference',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('push_enabled', models.BooleanField(default=True)),
                ('detection_alerts', models.BooleanField(default=True)),
                ('critical_alerts', models.BooleanField(default=True)),
                ('push_subscription', models.JSONField(blank=True, help_text='Web Push subscription JSON', null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='notification_preferences',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'notification_preferences',
            },
        ),

        # ==================== Notification ====================
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('notification_type', models.CharField(
                    choices=[
                        ('detection_nearby', 'Pest Detection Nearby'),
                        ('verification_approved', 'Verification Approved'),
                        ('verification_rejected', 'Verification Rejected'),
                        ('farm_approved', 'Farm Request Approved'),
                        ('farm_rejected', 'Farm Request Rejected'),
                        ('admin_alert', 'Admin Alert'),
                        ('critical_pest', 'Critical Pest Alert'),
                        ('system', 'System Notification'),
                    ],
                    max_length=30
                )),
                ('title', models.CharField(max_length=200)),
                ('message', models.TextField()),
                ('is_read', models.BooleanField(default=False)),
                ('related_id', models.IntegerField(
                    blank=True,
                    help_text='ID of related object (detection, farm, etc.)',
                    null=True
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='notifications',
                    to='api.user'
                )),
            ],
            options={
                'db_table': 'notifications',
                'ordering': ['-created_at'],
            },
        ),
    ]