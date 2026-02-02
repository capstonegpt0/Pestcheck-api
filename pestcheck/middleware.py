# pestcheck/middleware.py
import re
from django.utils.deprecation import MiddlewareMixin

class CsrfExemptMiddleware(MiddlewareMixin):
    """
    Exempt API endpoints from CSRF validation
    since we use JWT authentication
    """
    def process_request(self, request):
        # Exempt all /api/ endpoints from CSRF
        if request.path.startswith('/api/'):
            setattr(request, '_dont_enforce_csrf_checks', True)
        return None