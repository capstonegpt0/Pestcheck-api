# api/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    # Auth views
    register_view, 
    login_view, 
    logout_view, 
    user_profile,
    # User/Farmer ViewSets
    FarmViewSet, 
    PestDetectionViewSet, 
    PestInfoViewSet, 
    AlertViewSet,
    # Admin ViewSets
    AdminUserManagementViewSet, 
    AdminFarmManagementViewSet, 
    AdminDetectionManagementViewSet, 
    AdminPestInfoManagementViewSet,
    AdminAlertManagementViewSet, 
    AdminActivityLogViewSet,
    # Additional views
    DetectionStatisticsAPIView
)

# User/Farmer Router
user_router = DefaultRouter()
user_router.register(r'farms', FarmViewSet, basename='farm')
user_router.register(r'detections', PestDetectionViewSet, basename='detection')
user_router.register(r'pests', PestInfoViewSet, basename='pest')
user_router.register(r'alerts', AlertViewSet, basename='alert')

# Admin Router
admin_router = DefaultRouter()
admin_router.register(r'users', AdminUserManagementViewSet, basename='admin-user')
admin_router.register(r'farms', AdminFarmManagementViewSet, basename='admin-farm')
admin_router.register(r'detections', AdminDetectionManagementViewSet, basename='admin-detection')
admin_router.register(r'pests', AdminPestInfoManagementViewSet, basename='admin-pest')
admin_router.register(r'alerts', AdminAlertManagementViewSet, basename='admin-alert')
admin_router.register(r'activity-logs', AdminActivityLogViewSet, basename='admin-activity')

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', register_view, name='register'),
    path('auth/login/', login_view, name='login'),
    path('auth/logout/', logout_view, name='logout'),
    path('auth/profile/', user_profile, name='profile'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Statistics endpoint (keep this one)
    path('detections/statistics/', DetectionStatisticsAPIView.as_view(), name='detections-statistics'),
    
    # ✅ REMOVED DetectionListCreateAPIView - using PestDetectionViewSet instead
    # The router below already handles /detections/ via PestDetectionViewSet
    
    # User/Farmer endpoints - This includes /detections/ via PestDetectionViewSet
    path('', include(user_router.urls)),
    
    # Admin endpoints
    path('admin/', include(admin_router.urls)),
]