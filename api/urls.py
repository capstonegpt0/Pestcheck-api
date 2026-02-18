from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

router = DefaultRouter()

# ==================== USER VIEWSETS ====================
router.register(r'detections', views.PestDetectionViewSet, basename='detection')
router.register(r'farms', views.FarmViewSet, basename='farm')
router.register(r'farm-requests', views.FarmRequestViewSet, basename='farm-request')
router.register(r'pests', views.PestInfoViewSet, basename='pest')
router.register(r'alerts', views.AlertViewSet, basename='alert')
router.register(r'notifications', views.NotificationViewSet, basename='notification')

# ==================== VERIFICATION REQUESTS ====================
# Users submit verification requests (RSBSA + valid ID) here
router.register(r'verification-requests', views.VerificationRequestViewSet, basename='verification-request')

# ==================== ADMIN VIEWSETS ====================
router.register(r'admin/users', views.AdminUserManagementViewSet, basename='admin-users')
router.register(r'admin/farms', views.AdminFarmManagementViewSet, basename='admin-farms')
router.register(r'admin/farm-requests', views.AdminFarmRequestManagementViewSet, basename='admin-farm-requests')
router.register(r'admin/detections', views.AdminDetectionManagementViewSet, basename='admin-detections')
router.register(r'admin/pests', views.AdminPestInfoManagementViewSet, basename='admin-pests')
router.register(r'admin/alerts', views.AdminAlertManagementViewSet, basename='admin-alerts')
router.register(r'admin/activity-logs', views.AdminActivityLogViewSet, basename='admin-activity-logs')

# Admin verification request management
router.register(r'admin/verification-requests', views.AdminVerificationRequestViewSet, basename='admin-verification-requests')

urlpatterns = [
    # ==================== AUTH ====================
    path('auth/register/', views.register_view, name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/profile/', views.user_profile, name='profile'),
    path('auth/profile/update/', views.update_profile, name='update-profile'),
    path('auth/change-password/', views.change_password, name='change-password'),
    path('auth/notification-settings/', views.update_notification_settings, name='notification-settings'),
    path('auth/push-subscription/', views.register_push_subscription, name='push-subscription'),

    # ==================== ROUTER URLS ====================
    path('', include(router.urls)),
]