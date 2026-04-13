from django.db import migrations, models


MAGALANG_BARANGAYS = [
    'Ayala', 'Bucanan', 'Camias', 'Dolores', 'Escaler', 'La Paz',
    'Navaling', 'San Agustin', 'San Antonio', 'San Francisco',
    'San Ildefonso', 'San Isidro', 'San Jose', 'San Miguel',
    'San Nicolas 1st (Poblacion)', 'San Nicolas 2nd',
    'San Pablo (Poblacion)', 'San Pedro I', 'San Pedro II',
    'San Roque', 'San Vicente', 'Santa Cruz (Poblacion)',
    'Santa Lucia', 'Santa Maria', 'Santo Niño', 'Santo Rosario', 'Turu',
]


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_add_notification_types'),
    ]

    operations = [
        # Add barangay to FarmRequest (user-submitted requests)
        migrations.AddField(
            model_name='farmrequest',
            name='barangay',
            field=models.CharField(
                blank=True,
                max_length=100,
                help_text='Barangay in Magalang, Pampanga where the farm is located',
            ),
        ),
        # Add barangay to Farm (approved farms created by admin)
        migrations.AddField(
            model_name='farm',
            name='barangay',
            field=models.CharField(
                blank=True,
                max_length=100,
                help_text='Barangay in Magalang, Pampanga where the farm is located',
            ),
        ),
    ]