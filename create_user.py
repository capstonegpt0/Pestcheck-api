# create_users.py
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import User

# Create admin user
try:
    admin = User.objects.create_superuser(
        username='superadmin',
        email='superadmin@pestcheck.com',
        password='admin123',
        first_name='SuperAdmin',
        last_name='User',
        role='admin',
        is_verified=True
    )
    print(f"✅ Admin user created: {admin.username}")
except Exception as e:
    print(f"❌ Error creating admin: {e}")