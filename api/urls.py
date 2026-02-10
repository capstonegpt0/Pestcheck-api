from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    register_view,
    login_view,
    logout_view,
    user_profile,
    update_profile,
    change_password,
    update_notification_settings,
    check_verification_status,  # ✅ NEW
    FarmRequestViewSet,
    FarmViewSet,
    PestDetectionViewSet,
    DetectionListCreateAPIView,
    DetectionStatisticsAPIView,
    PestInfoViewSet,
    AlertViewSet,
    AdminUserManagementViewSet,
    AdminFarmManagementViewSet,
    AdminDetectionManagementViewSet,
    AdminPestInfoManagementViewSet,
    AdminAlertManagementViewSet,
    AdminFarmRequestManagementViewSet,
    AdminActivityLogViewSet,
)

router = DefaultRouter()
router.register(r'farm-requests', FarmRequestViewSet, basename='farm-request')
router.register(r'farms', FarmViewSet, basename='farm')
router.register(r'detections', PestDetectionViewSet, basename='detection')
router.register(r'pests', PestInfoViewSet, basename='pest')
router.register(r'alerts', AlertViewSet, basename='alert')

# Admin routes
router.register(r'admin/users', AdminUserManagementViewSet, basename='admin-user')
router.register(r'admin/farms', AdminFarmManagementViewSet, basename='admin-farm')
router.register(r'admin/detections', AdminDetectionManagementViewSet, basename='admin-detection')
router.register(r'admin/pests', AdminPestInfoManagementViewSet, basename='admin-pest')
router.register(r'admin/alerts', AdminAlertManagementViewSet, basename='admin-alert')
router.register(r'admin/farm-requests', AdminFarmRequestManagementViewSet, basename='admin-farm-request')
router.register(r'admin/activity-logs', AdminActivityLogViewSet, basename='admin-activity')

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Authentication endpoints
    path('auth/register/', register_view, name='register'),
    path('auth/login/', login_view, name='login'),
    path('auth/logout/', logout_view, name='logout'),
    path('auth/profile/', user_profile, name='profile'),
    path('auth/profile/update/', update_profile, name='update-profile'),
    path('auth/change-password/', change_password, name='change-password'),
    path('auth/notification-settings/', update_notification_settings, name='notification-settings'),
    
    # ✅ NEW: Verification status endpoint
    path('user/verification-status/', check_verification_status, name='verification-status'),
    
    # Detection endpoints (additional)
    path('detections/create/', DetectionListCreateAPIView.as_view(), name='detection-create'),
    path('detections/statistics/', DetectionStatisticsAPIView.as_view(), name='detection-statistics'),
]