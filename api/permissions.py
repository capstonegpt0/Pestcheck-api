from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    """Only full admins can access"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'admin'

class IsAdminOrMAOStaff(permissions.BasePermission):
    """Admin or MAO staff can access"""
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.role in ('admin', 'mao_staff')
        )

class IsAdminOrMAOStaffNoDelete(permissions.BasePermission):
    """
    Admin or MAO staff can read/create/update.
    Only admin can delete.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.role == 'admin':
            return True
        if request.user.role == 'mao_staff':
            # MAO staff cannot delete
            return request.method != 'DELETE'
        return False

class IsAdminOrReadOnly(permissions.BasePermission):
    """Admin can edit, others can only read"""
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        return request.user and request.user.is_authenticated and request.user.role == 'admin'

class IsFarmerOrAdmin(permissions.BasePermission):
    """Farmers and admins can access"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['farmer', 'admin']

class IsOwnerOrAdmin(permissions.BasePermission):
    """Owner or admin can edit"""
    def has_object_permission(self, request, view, obj):
        if request.user.role == 'admin':
            return True
        return obj.user == request.user