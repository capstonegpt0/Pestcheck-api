from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.http import FileResponse, Http404
import os

# Media serving function (defined right here in urls.py)
def serve_media(request, path):
    """Serve media files in production"""
    file_path = os.path.join(settings.MEDIA_ROOT, path)
    
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'))
    else:
        raise Http404(f"Media file not found: {path}")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    
    # Serve media files
    re_path(r'^media/(?P<path>.*)$', serve_media, name='serve_media'),
]

# Static files
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)