from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from api.views import serve_media

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    
    # Explicitly serve media files
    re_path(r'^media/(?P<path>.*)$', serve_media, name='serve_media'),
]

# Also add static files serving (just in case)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)