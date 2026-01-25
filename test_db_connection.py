import os
import sys

print("=" * 50)
print("DATABASE CONNECTION TEST")
print("=" * 50)

# Check if DATABASE_URL exists
database_url = os.environ.get('DATABASE_URL')
if database_url:
    print(f"✓ DATABASE_URL is set")
    print(f"  First 60 chars: {database_url[:60]}...")
    
    # Check if it's localhost (bad)
    if 'localhost' in database_url:
        print("✗ ERROR: DATABASE_URL contains 'localhost'")
        sys.exit(1)
    
    # Check if it's the correct format
    if database_url.startswith('postgresql://'):
        print("✓ DATABASE_URL starts with 'postgresql://'")
    elif database_url.startswith('postgres://'):
        print("⚠ DATABASE_URL starts with 'postgres://' (will be converted)")
    else:
        print("✗ ERROR: DATABASE_URL has wrong format")
        sys.exit(1)
        
else:
    print("✗ ERROR: DATABASE_URL is NOT set!")
    sys.exit(1)

print("=" * 50)
print("Test passed! Database URL looks correct.")
print("=" * 50)