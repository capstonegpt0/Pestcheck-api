#!/usr/bin/env bash
set -o errexit

pip install --upgrade pip
pip install -r requirements.txt

# Test database connection BEFORE collectstatic
python test_db_connection.py

python manage.py collectstatic --no-input




