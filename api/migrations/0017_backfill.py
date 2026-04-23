from django.db import migrations


def backfill_farm_barangay(apps, schema_editor):
    """
    For every Farm that has no barangay set, look up the linked FarmRequest
    (via original_request reverse relation) and copy the barangay + address
    across.  This repairs farms that were approved before the fix was applied.
    """
    Farm = apps.get_model('api', 'Farm')
    FarmRequest = apps.get_model('api', 'FarmRequest')

    fixed = 0
    for farm in Farm.objects.filter(barangay=''):
        # The FarmRequest that produced this farm is linked via approved_farm FK
        try:
            req = FarmRequest.objects.get(approved_farm=farm)
        except FarmRequest.DoesNotExist:
            continue

        changed = False
        if req.barangay and req.barangay.strip():
            farm.barangay = req.barangay.strip()
            changed = True
        if req.address and req.address.strip() and not farm.address:
            farm.address = req.address.strip()
            changed = True

        if changed:
            farm.save(update_fields=['barangay', 'address'])
            fixed += 1

    print(f'[backfill_farm_barangay] Fixed {fixed} farm(s).')


class Migration(migrations.Migration):

    dependencies = [
        # Depends on the last migration in the chain
        ('api', '0016_alter_farm_is_verified_alter_farmrequest_id'),
    ]

    operations = [
        migrations.RunPython(backfill_farm_barangay, migrations.RunPython.noop),
    ]