# api/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    register_view, login_view, logout_view, user_profile,
    update_profile, change_password, update_notification_settings,
    setup_super_admin,  # ⭐ ONE-TIME SETUP - DELETE AFTER USE
    # User/Farmer ViewSets
    FarmViewSet, 
    FarmRequestViewSet,
    PestDetectionViewSet, 
    PestInfoViewSet, 
    AlertViewSet,
    # Admin ViewSets
    AdminUserManagementViewSet, 
    AdminFarmManagementViewSet,
    AdminFarmRequestManagementViewSet,
    AdminDetectionManagementViewSet, 
    AdminPestInfoManagementViewSet,
    AdminAlertManagementViewSet, 
    AdminActivityLogViewSet,
    DatabaseManagementViewSet,  # ⭐ SUPER ADMIN DATABASE
    DetectionListCreateAPIView, 
    DetectionStatisticsAPIView
)

# User/Farmer Router
user_router = DefaultRouter()
user_router.register(r'farms', FarmViewSet, basename='farm')
user_router.register(r'farm-requests', FarmRequestViewSet, basename='farm-request')
user_router.register(r'detections', PestDetectionViewSet, basename='detection')
user_router.register(r'pests', PestInfoViewSet, basename='pest')
user_router.register(r'alerts', AlertViewSet, basename='alert')

# Admin Router
admin_router = DefaultRouter()
admin_router.register(r'users', AdminUserManagementViewSet, basename='admin-user')
admin_router.register(r'farms', AdminFarmManagementViewSet, basename='admin-farm')
admin_router.register(r'farm-requests', AdminFarmRequestManagementViewSet, basename='admin-farm-request')
admin_router.register(r'detections', AdminDetectionManagementViewSet, basename='admin-detection')
admin_router.register(r'pests', AdminPestInfoManagementViewSet, basename='admin-pest')
admin_router.register(r'alerts', AdminAlertManagementViewSet, basename='admin-alert')
admin_router.register(r'activity-logs', AdminActivityLogViewSet, basename='admin-activity')

# Super Admin Router (Database Management)
super_admin_router = DefaultRouter()
super_admin_router.register(r'database', DatabaseManagementViewSet, basename='database')

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', register_view, name='register'),
    path('auth/login/', login_view, name='login'),
    path('auth/logout/', logout_view, name='logout'),
    path('auth/profile/', user_profile, name='profile'),
    path('auth/profile/update/', update_profile, name='profile-update'),
    path('auth/change-password/', change_password, name='change-password'),
    path('auth/notification-settings/', update_notification_settings, name='notification-settings'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # ⚠️ ONE-TIME SETUP - DELETE THIS LINE AFTER CREATING SUPER ADMIN
    path('setup-super-admin/', setup_super_admin, name='setup-super-admin'),
    
    # Statistics endpoint
    path('detections/statistics/', DetectionStatisticsAPIView.as_view(), name='detections-statistics'),
    
    # User/Farmer endpoints
    path('', include(user_router.urls)),
    
    # Admin endpoints
    path('admin/', include(admin_router.urls)),
    
    # Super Admin endpoints
    path('super-admin/', include(super_admin_router.urls)),
]