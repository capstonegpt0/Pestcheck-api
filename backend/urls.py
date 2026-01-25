# D:\Pestcheck\backend\backend\urls.py

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

def health_check(request):
    """Simple health check endpoint"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'PestCheck API',
        'version': '1.0.0',
        'cors_enabled': True
    })

urlpatterns = [
    path('', health_check, name='health'),  # Root endpoint
    path('health/', health_check, name='health_check'),  # Health check
    path('admin/', admin.site.urls),
    
    # API routes - all under /api/
    path('api/', include('api.urls')),
    
    # JWT Authentication (also under /api/)
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)