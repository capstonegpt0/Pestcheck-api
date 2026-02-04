# create_users.py
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import User

# Create admin user
try:
    admin = User.objects.create_superuser(
        username='admin',
        email='admin@pestcheck.com',
        password='admin123',
        first_name='Admin',
        last_name='User',
        role='admin',
        is_verified=True
    )
    print(f"✅ Admin user created: {admin.username}")
except Exception as e:
    print(f"❌ Error creating admin: {e}")

# Create test farmer
try:
    farmer = User.objects.create_user(
        username='farmer1',
        email='farmer1@pestcheck.com',
        password='farmer123',
        first_name='Test',
        last_name='Farmer',
        role='farmer',
        is_verified=True
    )
    print(f"✅ Farmer user created: {farmer.username}")
except Exception as e:
    print(f"❌ Error creating farmer: {e}")

print("\n✅ All users created successfully!")