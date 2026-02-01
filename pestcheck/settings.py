import os
from pathlib import Path
from datetime import timedelta
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

# =========================
# SECURITY
# =========================
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")

DEBUG = os.environ.get("DEBUG", "False") == "True"

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    ".onrender.com",
    "10.0.2.2",  # ✅ Android emulator
]

# Add Render external hostname if available
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# =========================
# APPLICATIONS
# =========================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',

    'api',
]

# =========================
# MIDDLEWARE
# =========================
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # MUST BE FIRST
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',

    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',

    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# =========================
# URL / WSGI
# =========================
ROOT_URLCONF = 'pestcheck.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'pestcheck.wsgi.application'

# =========================
# DATABASE (RENDER SAFE)
# =========================
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # Convert postgres:// to postgresql:// if needed (Django 4.x requirement)
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    DATABASES = {
        "default": dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
else:
    # Fallback to SQLite for local development
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# =========================
# AUTH
# =========================
AUTH_USER_MODEL = 'api.User'

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# =========================
# INTERNATIONALIZATION
# =========================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Manila'
USE_I18N = True
USE_TZ = True

# =========================
# STATIC & MEDIA
# =========================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =========================
# CORS - ✅ UPDATED FOR CAPACITOR
# =========================
CORS_ALLOW_ALL_ORIGINS = False

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://pestcheck.onrender.com",
    
    # ✅ Capacitor support
    "capacitor://localhost",      # Capacitor iOS
    "http://localhost",            # Capacitor Android
    "ionic://localhost",           # Ionic Capacitor
    "http://10.0.2.2:8000",       # Android emulator
]

# Add Render backend URL to CORS if available
if RENDER_EXTERNAL_HOSTNAME:
    CORS_ALLOWED_ORIGINS.append(f"https://{RENDER_EXTERNAL_HOSTNAME}")

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# =========================
# CSRF - ✅ UPDATED FOR CAPACITOR
# =========================
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://pestcheck.onrender.com",  
    "https://*.onrender.com",
    "http://localhost",  # ✅ Capacitor
]

if RENDER_EXTERNAL_HOSTNAME:
    CSRF_TRUSTED_ORIGINS.append(f"https://{RENDER_EXTERNAL_HOSTNAME}")

# ✅ Capacitor-friendly CSRF settings
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to read CSRF token
CSRF_COOKIE_SAMESITE = 'Lax'  # Less strict for mobile apps

# =========================
# DRF & JWT
# =========================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
}

# =========================
# LOGGING
# =========================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}

# =========================
# SECURITY SETTINGS FOR PRODUCTION
# =========================
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True