from rest_framework import permissions

class IsSuperAdmin(permissions.BasePermission):
    """Only super admins can access - for database management"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'super_admin'

class IsAdmin(permissions.BasePermission):
    """Only admins can access"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['admin', 'super_admin']

class IsAdminOrReadOnly(permissions.BasePermission):
    """Admin can edit, others can only read"""
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        return request.user and request.user.is_authenticated and request.user.role in ['admin', 'super_admin']

class IsFarmerOrAdmin(permissions.BasePermission):
    """Farmers and admins can access"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['farmer', 'admin', 'super_admin']

class IsOwnerOrAdmin(permissions.BasePermission):
    """Owner or admin can edit"""
    def has_object_permission(self, request, view, obj):
        if request.user.role in ['admin', 'super_admin']:
            return True
        return obj.user == request.user