import os
import tempfile
import requests
import time
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from .models import PestDetection, Farm
from .serializers import PestDetectionSerializer
from rest_framework import viewsets, status, generics, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models import User, Farm, FarmRequest, PestDetection, PestInfo, InfestationReport, Alert, UserActivity
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    FarmSerializer, FarmRequestSerializer, PestDetectionSerializer, PestInfoSerializer,
    InfestationReportSerializer, AlertSerializer, UserActivitySerializer
)
from .permissions import IsAdmin, IsAdminOrReadOnly, IsFarmerOrAdmin, IsOwnerOrAdmin
from .utils import get_crop_from_pest

# ✅ NEW: Import proximity alert utilities
from .proximity_utils import (
    check_and_create_proximity_alerts,
    check_proximity_alerts_for_farm,
    get_proximity_alert_stats,
    count_recent_detections_near_farm
)

# ==================== CONSTANTS ====================
MAGALANG_BOUNDS = {
    'north': 15.2547,
    'south': 15.1547,
    'east': 120.6447,
    'west': 120.5447
}

HUGGINGFACE_ML_URL = os.environ.get(
    'HUGGINGFACE_ML_URL', 
    'https://capstonegpt0-pestcheck-ml.hf.space'
)

# ==================== HELPER FUNCTIONS ====================
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {'refresh': str(refresh), 'access': str(refresh.access_token)}


def log_activity(user, action, details='', request=None):
    ip_address = None
    if request:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
    UserActivity.objects.create(user=user, action=action, details=details, ip_address=ip_address)


def call_ml_api(image_path, crop_type='rice', max_retries=3):
    """
    Sends image to HuggingFace ML service with retry logic
    """
    for attempt in range(max_retries):
        try:
            with open(image_path, "rb") as f:
                files = {"image": f}
                data = {"crop_type": crop_type}
                
                # Call HuggingFace ML service
                response = requests.post(
                    f"{HUGGINGFACE_ML_URL}/detect",
                    files=files,
                    data=data,
                    timeout=120
                )
            
            if response.status_code == 503:
                # Model not loaded yet - wait and retry
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 10  # 10s, 20s, 30s
                    print(f"ML service not ready, waiting {wait_time}s before retry {attempt + 1}/{max_retries}")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception("ML service is starting up. Please wait 30 seconds and try again.")
            
            if response.status_code != 200:
                raise Exception(f"ML API failed: {response.status_code} - {response.text}")
            
            return response.json()
        
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                print(f"Timeout on attempt {attempt + 1}/{max_retries}, retrying...")
                time.sleep(5)
                continue
            raise Exception("ML service timeout. The service might be cold-starting. Please try again in 30 seconds.")
        
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                print(f"Connection error on attempt {attempt + 1}/{max_retries}, retrying...")
                time.sleep(5)
                continue
            raise Exception("Cannot connect to ML service. Please check if the service is running.")
        
        except Exception as e:
            if "503" in str(e) and attempt < max_retries - 1:
                time.sleep(10)
                continue
            raise Exception(f"ML API error: {str(e)}")
    
    raise Exception("Max retries exceeded")


# ==================== AUTHENTICATION VIEWS ====================
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        log_activity(user, 'user_registered', request=request)
        return Response({'user': UserSerializer(user).data, 'tokens': tokens}, status=201)
    return Response(serializer.errors, status=400)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data
        tokens = get_tokens_for_user(user)
        log_activity(user, 'user_logged_in', request=request)
        return Response({'user': UserSerializer(user).data, 'tokens': tokens})
    return Response(serializer.errors, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.data.get('refresh_token')
        token = RefreshToken(refresh_token)
        token.blacklist()
        log_activity(request.user, 'user_logged_out', request=request)
        return Response({'message': 'Logout successful'})
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    return Response(UserSerializer(request.user).data)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    """Update user profile information"""
    user = request.user
    serializer = UserSerializer(user, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()
        log_activity(user, 'profile_updated', 'Updated profile information', request)
        return Response(serializer.data)
    
    return Response(serializer.errors, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """Change user password"""
    user = request.user
    current_password = request.data.get('current_password')
    new_password = request.data.get('new_password')
    
    # Verify current password
    if not user.check_password(current_password):
        return Response(
            {'error': 'Current password is incorrect'},
            status=400
        )
    
    # Validate new password
    if len(new_password) < 8:
        return Response(
            {'error': 'New password must be at least 8 characters long'},
            status=400
        )
    
    # Set new password
    user.set_password(new_password)
    user.save()
    
    log_activity(user, 'password_changed', 'Changed password', request)
    
    return Response({'message': 'Password changed successfully'})


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_notification_settings(request):
    """Update notification preferences (placeholder for future implementation)"""
    # For now, just acknowledge the request
    # In a real implementation, you would save these to a UserPreferences model
    log_activity(request.user, 'notification_settings_updated', 'Updated notification settings', request)
    return Response({'message': 'Notification settings updated successfully'})


# ==================== FARM REQUEST VIEWSET (NEW) ====================
class FarmRequestViewSet(viewsets.ModelViewSet):
    """
    Farmers can CREATE farm requests
    Farmers can VIEW their own farm requests
    """
    serializer_class = FarmRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.role == 'admin':
            return FarmRequest.objects.all()
        return FarmRequest.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        farm_request = serializer.save(user=self.request.user, status='pending')
        log_activity(
            self.request.user, 
            'farm_request_submitted', 
            f'Farm request: {farm_request.name}', 
            self.request
        )

    def create(self, request, *args, **kwargs):
        if request.user.role == 'admin':
            return Response(
                {'error': 'Admins create farms directly, not requests.'},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user.role != 'admin':
            if instance.user != request.user:
                return Response({'error': 'Cannot update others requests'}, status=status.HTTP_403_FORBIDDEN)
            if instance.status != 'pending':
                return Response({'error': 'Cannot update reviewed requests'}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user.role != 'admin':
            if instance.user != request.user:
                return Response({'error': 'Cannot delete others requests'}, status=status.HTTP_403_FORBIDDEN)
            if instance.status != 'pending':
                return Response({'error': 'Cannot delete reviewed requests'}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)


# ==================== FARM VIEWSET (UPDATED - READ ONLY FOR FARMERS) ====================
class FarmViewSet(viewsets.ReadOnlyModelViewSet):
    """
    All authenticated users can VIEW all farms (Read-Only).
    This enables collaborative pest monitoring across the Magalang region.
    """
    serializer_class = FarmSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Everyone sees every farm for collaborative monitoring
        return Farm.objects.all()


# ==================== PEST DETECTION VIEWSET ====================
class PestDetectionViewSet(viewsets.ModelViewSet):
    queryset = PestDetection.objects.all()
    serializer_class = PestDetectionSerializer
    permission_classes = [permissions.IsAuthenticated]

    # Automatically set the user on creation
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    

    def get_queryset(self):
        # All users see all detections for collaborative monitoring
        queryset = PestDetection.objects.all()

        # Geofence filter â€“ only Magalang area
        queryset = queryset.filter(
            latitude__gte=MAGALANG_BOUNDS['south'],
            latitude__lte=MAGALANG_BOUNDS['north'],
            longitude__gte=MAGALANG_BOUNDS['west'],
            longitude__lte=MAGALANG_BOUNDS['east']
        )

        # Optional filters
        if self.request.query_params.get('my_detections'):
            queryset = queryset.filter(user=self.request.user)

        page_size = self.request.query_params.get('page_size')
        if page_size and hasattr(self.pagination_class, 'page_size'):
            self.pagination_class.page_size = int(page_size)

        return queryset

    def create_manual_detection(self, request):
        """Handles manual detection (without image)"""
        try:
            lat = float(request.data.get('latitude', 0))
            lng = float(request.data.get('longitude', 0))
            farm = None
            farm_id = request.data.get('farm_id')
            if farm_id:
                farm = Farm.objects.filter(id=farm_id, user=request.user).first()

            detection = PestDetection.objects.create(
                user=request.user,
                farm=farm,
                crop_type=request.data.get('crop_type', 'rice'),
                pest_name=request.data.get('pest_type', ''),
                pest_type=request.data.get('pest_type', ''),
                confidence=0.0,
                severity=request.data.get('severity', 'low'),
                latitude=lat,
                longitude=lng,
                address=request.data.get('address', ''),
                description=request.data.get('description', ''),
                active=request.data.get('active', True),
                status='pending',
                detected_at=timezone.now(),
                reported_at=timezone.now()
            )
            log_activity(request.user, 'reported_infestation', f'Pest: {detection.pest_name}', request)
            serializer = self.get_serializer(detection)
            response_data = serializer.data
            response_data['farm_id'] = farm.id if farm else None
            return Response(response_data, status=201)
        except Exception as e:
            return Response({'error': str(e)}, status=400)

    def create(self, request):
        """Handles detection via ML API or manual fallback"""
        if 'image' not in request.FILES:
            return self.create_manual_detection(request)

        temp_path = None
        try:
            lat = float(request.data.get('latitude', 0))
            lng = float(request.data.get('longitude', 0))
            crop_type = request.data.get('crop_type', 'rice')
            image = request.FILES.get('image')

            if not image:
                return Response({'error': 'No image provided'}, status=400)

            # Save temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
                for chunk in image.chunks():
                    tmp_file.write(chunk)
                temp_path = tmp_file.name

            print(f"Calling ML API with image: {temp_path}, crop: {crop_type}")
            
            # Call ML API with retry logic
            analysis = call_ml_api(temp_path, crop_type=crop_type)
            
            print(f"ML API response: {analysis}")

            # âœ… ADD VALIDATION HERE - Check if pest was actually detected
            pest_name = analysis.get('pest_name', '')
            confidence = analysis.get('confidence', 0.0)
            
            print(f"ðŸ” Validation - pest_name: '{pest_name}', confidence: {confidence}")
            
            # Don't save if no pest was detected
            if not pest_name or pest_name == 'Unknown Pest' or pest_name == '' or confidence < 0.1:
                print(f"âŒ Validation FAILED - No valid pest detected")
                print(f"   pest_name: '{pest_name}' (empty: {not pest_name})")
                print(f"   confidence: {confidence} (too low: {confidence < 0.1})")
                return Response({
                    'error': 'No pest detected in the image. Please try another image with clearer pest visibility.',
                    'retry': True,
                    'debug': {
                        'pest_name': pest_name,
                        'confidence': confidence,
                        'ml_response': analysis
                    }
                }, status=400)
            
            print(f"âœ… Validation PASSED - Saving detection")
            print(f"   pest_name: '{pest_name}'")
            print(f"   confidence: {confidence}")

            # Determine crop type based on detected pest
            detected_crop_type = get_crop_from_pest(pest_name)
            print(f"   determined crop_type: '{detected_crop_type}' (from pest: '{pest_name}')")

            # Only save if we have a valid detection
            # Get confirmed and active from request, default to False (requires user confirmation)
            confirmed = request.data.get('confirmed', 'false').lower() == 'true'
            active_status = request.data.get('active', 'false').lower() == 'true'
            
            detection = PestDetection.objects.create(
                user=request.user,
                image=image,
                crop_type=detected_crop_type,  # Use crop type determined from pest
                pest_name=pest_name,  # Use validated pest_name
                pest_type=analysis.get('pest_key', ''),
                confidence=confidence,  # Use validated confidence
                severity=analysis.get('severity', 'low'),
                latitude=lat,
                longitude=lng,
                address=request.data.get('address', ''),
                description=analysis.get('symptoms', ''),
                status='pending',
                confirmed=confirmed,  # User confirmation status
                active=active_status,  # Whether detection is active/visible
                detected_at=timezone.now()
            )
            log_activity(request.user, 'detected_pest', f"Pest: {detection.pest_name}", request)

            # Return enriched response
            serializer = self.get_serializer(detection)
            response_data = serializer.data
            response_data.update({
                'scientific_name': analysis.get('scientific_name', ''),
                'symptoms': analysis.get('symptoms', ''),
                'control_methods': analysis.get('control_methods', []),
                'prevention': analysis.get('prevention', []),
                'num_detections': analysis.get('num_detections', 1)
            })
            
            print(f"âœ… Returning successful detection response")
            return Response(response_data, status=201)

        except Exception as e:
            error_message = str(e)
            print(f"âŒ Detection error: {error_message}")
            
            # Provide helpful error messages
            if "starting up" in error_message or "503" in error_message:
                return Response({
                    'error': 'ML service is warming up. Please wait 30 seconds and try again.',
                    'retry': True
                }, status=503)
            elif "timeout" in error_message.lower():
                return Response({
                    'error': 'ML service is taking longer than expected. Please try again.',
                    'retry': True
                }, status=504)
            else:
                return Response({
                    'error': f'Detection failed: {error_message}',
                    'retry': False
                }, status=500)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
                
    def partial_update(self, request, *args, **kwargs):
        detection_id = kwargs.get('pk')
        try:
            instance = PestDetection.objects.get(id=detection_id)
            if instance.user != request.user and request.user.role != 'admin':
                return Response({'error': 'Permission denied'}, status=403)

            # âœ… NEW: Handle farm_id updates
            if 'farm_id' in request.data:
                farm_id = request.data['farm_id']
                if farm_id:
                    try:
                        # Verify the farm exists and user has permission
                        farm = Farm.objects.get(id=farm_id)
                        if farm.user != request.user and request.user.role != 'admin':
                            return Response({
                                'error': 'You do not have permission to assign detections to this farm'
                            }, status=403)
                        instance.farm = farm
                    except Farm.DoesNotExist:
                        return Response({'error': 'Farm not found'}, status=404)
                else:
                    instance.farm = None

            # âœ… NEW: Handle severity updates (required for damage assessment)
            if 'severity' in request.data:
                valid_severities = ['low', 'medium', 'high', 'critical']
                severity = request.data['severity']
                if severity not in valid_severities:
                    return Response({
                        'error': f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
                    }, status=400)
                instance.severity = severity
            
            # âœ… NEW: Handle confirmed field updates
            if 'confirmed' in request.data:
                instance.confirmed = request.data['confirmed']
            
            if 'active' in request.data:
                instance.active = request.data['active']
            
            if 'status' in request.data:
                instance.status = request.data['status']
            
            # âœ… NEW: Allow updating description
            if 'description' in request.data:
                instance.description = request.data['description']
            
            if not instance.active or instance.status == 'resolved':
                instance.resolved_at = timezone.now()
                instance.status = 'resolved'
            
            instance.save()
            
            # ✅ NEW: Check for proximity alerts when detection is confirmed
            if 'confirmed' in request.data and instance.confirmed and instance.active and instance.farm:
                try:
                    created_alerts = check_and_create_proximity_alerts(instance)
                    if created_alerts:
                        print(f"✅ Created {len(created_alerts)} proximity alert(s) for detection {instance.id}")
                except Exception as e:
                    # Don't fail the update if alert creation fails
                    print(f"⚠️ Failed to create proximity alerts: {str(e)}")
            
            # âœ… UPDATED: Include farm and severity in log message
            log_message = f'Detection ID: {instance.id}, Severity: {instance.severity}'
            if instance.farm:
                log_message += f', Farm: {instance.farm.name}'
            
            log_activity(
                request.user, 
                'updated_detection', 
                log_message, 
                request
            )
            
            return Response(self.get_serializer(instance).data)
        except PestDetection.DoesNotExist:
            return Response({'error': 'Detection not found'}, status=404)

    def update(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    @action(detail=False, methods=['get'])
    def heatmap_data(self, request):
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        # All users see all active AND confirmed detections (collaborative monitoring)
        queryset = PestDetection.objects.all()
        queryset = queryset.filter(
            active=True, 
            confirmed=True  # Only show user-confirmed detections
        ).filter(Q(detected_at__gte=since) | Q(reported_at__gte=since))
        heatmap_points = [{
            'id': det.id,
            'pest': det.pest_name or det.pest_type,
            'severity': det.severity,
            'lat': det.latitude,
            'lng': det.longitude,
            'farm_id': det.farm_id,
            'user_id': det.user_id,
            'user_name': det.user.username if det.user else None,
            'reported_at': (det.reported_at or det.detected_at).isoformat(),
            'active': det.active,
            'status': det.status
        } for det in queryset.select_related('user')]
        return Response(heatmap_points)

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        queryset = self.get_queryset().filter(user=request.user)
        by_severity = {s: queryset.filter(severity=s).count() for s in ['low','medium','high','critical']}
        by_crop = {c: queryset.filter(crop_type=c).count() for c in ['rice','corn']}
        by_pest = list(queryset.values('pest_name').annotate(count=Count('id')).order_by('-count')[:5])
        return Response({'total_detections': queryset.count(), 'by_severity': by_severity, 'by_crop': by_crop, 'by_pest': by_pest})


class DetectionListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = PestDetectionSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        user = self.request.user
        my_detections = self.request.query_params.get('my_detections', None)
        queryset = PestDetection.objects.all().order_by('-detected_at')
        if my_detections == 'true':
            queryset = queryset.filter(user=user)
        return queryset

    def perform_create(self, serializer):
        farm_id = self.request.data.get('farm_id')
        farm = None
        if farm_id:
            try:
                farm = Farm.objects.get(id=farm_id)
            except Farm.DoesNotExist:
                pass
        serializer.save(user=self.request.user, farm=farm)

class DetectionStatisticsAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        total = PestDetection.objects.count()
        verified = PestDetection.objects.filter(status='verified').count()
        unverified = total - verified
        return Response({
            'total': total,
            'verified': verified,
            'unverified': unverified,
        })

# ==================== PEST INFO VIEWSET ====================
# In api/views.py
class PestInfoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = PestInfo.objects.filter(is_published=True)
    serializer_class = PestInfoSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'])
    def search(self, request):
        query = request.query_params.get('q', '')
        pests = self.queryset.filter(
            Q(name__icontains=query) | 
            Q(scientific_name__icontains=query) | 
            Q(crop_affected__icontains=query)
        )
        return Response(self.get_serializer(pests, many=True).data)


# ==================== ALERT VIEWSET ====================
class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        now = timezone.now()
        queryset = Alert.objects.filter(
            Q(is_active=True, expires_at__gte=now) | 
            Q(is_active=True, expires_at__isnull=True)
        )
        
        # ✅ NEW: Filter to show alerts for user's farms only
        user_farms = Farm.objects.filter(user=self.request.user).values_list('name', flat=True)
        if user_farms:
            queryset = queryset.filter(
                Q(target_area__in=user_farms) |  # Alerts for user's farms
                Q(target_area='') |               # General alerts
                Q(target_area__isnull=True)       # System-wide alerts
            )
        
        return queryset.order_by('-created_at')
    
    @action(detail=False, methods=['get'])
    def my_alerts(self, request):
        """Get alerts specific to user's farms"""
        user_farms = Farm.objects.filter(user=request.user).values_list('name', flat=True)
        
        if not user_farms:
            return Response([])
        
        now = timezone.now()
        alerts = Alert.objects.filter(
            is_active=True,
            target_area__in=user_farms
        ).filter(
            Q(expires_at__gte=now) | Q(expires_at__isnull=True)
        ).order_by('-created_at')
        
        serializer = self.get_serializer(alerts, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def proximity_stats(self, request):
        """Get proximity alert statistics"""
        stats = get_proximity_alert_stats()
        return Response(stats)



# ==================== ADMIN VIEWSETS ====================
# [Keep all your existing admin viewsets - they're already correct]

class AdminUserManagementViewSet(viewsets.ModelViewSet):
    """Admin can manage all users"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=True, methods=['post'])
    def verify_user(self, request, pk=None):
        user = self.get_object()
        user.is_verified = True
        user.save()
        log_activity(request.user, 'verified_user', f'User: {user.username}', request)
        return Response({'message': f'User {user.username} verified successfully'})
    
    @action(detail=True, methods=['post'])
    def change_role(self, request, pk=None):
        user = self.get_object()
        new_role = request.data.get('role')
        if new_role in ['admin', 'farmer']:
            user.role = new_role
            user.save()
            log_activity(request.user, 'changed_user_role', f'User: {user.username}, New role: {new_role}', request)
            return Response({'message': f'User role changed to {new_role}'})
        return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total_users = User.objects.count()
        farmers = User.objects.filter(role='farmer').count()
        admins = User.objects.filter(role='admin').count()
        verified = User.objects.filter(is_verified=True).count()
        
        return Response({
            'total_users': total_users,
            'farmers': farmers,
            'admins': admins,
            'verified_users': verified,
            'unverified_users': total_users - verified
        })

class AdminFarmManagementViewSet(viewsets.ModelViewSet):
    queryset = Farm.objects.all()
    serializer_class = FarmSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=True, methods=['post'])
    def verify_farm(self, request, pk=None):
        farm = self.get_object()
        farm.is_verified = True
        farm.save()
        log_activity(request.user, 'verified_farm', f'Farm: {farm.name}', request)
        return Response({'message': f'Farm {farm.name} verified successfully'})
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total_farms = Farm.objects.count()
        verified = Farm.objects.filter(is_verified=True).count()
        by_crop = {}
        for crop in Farm.objects.values_list('crop_type', flat=True).distinct():
            if crop:
                by_crop[crop] = Farm.objects.filter(crop_type=crop).count()
        
        return Response({
            'total_farms': total_farms,
            'verified_farms': verified,
            'unverified_farms': total_farms - verified,
            'by_crop_type': by_crop
        })

class AdminDetectionManagementViewSet(viewsets.ModelViewSet):
    queryset = PestDetection.objects.all()
    serializer_class = PestDetectionSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=True, methods=['post'])
    def verify_detection(self, request, pk=None):
        detection = self.get_object()
        detection.status = 'verified'
        detection.verified_by = request.user
        detection.admin_notes = request.data.get('notes', '')
        detection.save()
        log_activity(request.user, 'verified_detection', f'Detection ID: {detection.id}', request)
        return Response({'message': 'Detection verified successfully'})
    
    @action(detail=True, methods=['post'])
    def reject_detection(self, request, pk=None):
        detection = self.get_object()
        detection.status = 'rejected'
        detection.verified_by = request.user
        detection.admin_notes = request.data.get('notes', '')
        detection.save()
        log_activity(request.user, 'rejected_detection', f'Detection ID: {detection.id}', request)
        return Response({'message': 'Detection rejected'})
    
    @action(detail=False, methods=['get'])
    def pending_verifications(self, request):
        pending = PestDetection.objects.filter(status='pending')
        serializer = self.get_serializer(pending, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total = PestDetection.objects.count()
        pending = PestDetection.objects.filter(status='pending').count()
        verified = PestDetection.objects.filter(status='verified').count()
        rejected = PestDetection.objects.filter(status='rejected').count()
        resolved = PestDetection.objects.filter(status='resolved').count()
        
        by_severity = {
            'low': PestDetection.objects.filter(severity='low').count(),
            'medium': PestDetection.objects.filter(severity='medium').count(),
            'high': PestDetection.objects.filter(severity='high').count(),
            'critical': PestDetection.objects.filter(severity='critical').count(),
        }
        
        return Response({
            'total_detections': total,
            'pending': pending,
            'verified': verified,
            'rejected': rejected,
            'resolved': resolved,
            'by_severity': by_severity
        })
        
# ==================== ADMIN FARM REQUEST MANAGEMENT (NEW) ====================
class AdminFarmRequestManagementViewSet(viewsets.ModelViewSet):
    """Admin can manage all farm requests and approve/reject them"""
    queryset = FarmRequest.objects.all()
    serializer_class = FarmRequestSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve farm request and create farm"""
        farm_request = self.get_object()
        
        if farm_request.status != 'pending':
            return Response(
                {'error': f'Request already {farm_request.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Create the farm
            farm = Farm.objects.create(
                user=farm_request.user,
                name=farm_request.name,
                lat=farm_request.lat,
                lng=farm_request.lng,
                size=farm_request.size,
                crop_type=farm_request.crop_type,
                is_verified=True,
                created_by=request.user
            )
            
            # Update request
            farm_request.status = 'approved'
            farm_request.reviewed_by = request.user
            farm_request.reviewed_at = timezone.now()
            farm_request.review_notes = request.data.get('review_notes', '')
            farm_request.approved_farm = farm
            farm_request.save()
            
            log_activity(
                request.user, 
                'farm_request_approved', 
                f'Approved: {farm_request.name} for {farm_request.user.username}', 
                request
            )
            
            return Response({
                'message': 'Farm request approved',
                'farm_id': farm.id
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject farm request"""
        farm_request = self.get_object()
        
        if farm_request.status != 'pending':
            return Response(
                {'error': f'Request already {farm_request.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        farm_request.status = 'rejected'
        farm_request.reviewed_by = request.user
        farm_request.reviewed_at = timezone.now()
        farm_request.review_notes = request.data.get('review_notes', 'Rejected')
        farm_request.save()
        
        log_activity(
            request.user, 
            'farm_request_rejected', 
            f'Rejected: {farm_request.name}', 
            request
        )
        
        return Response({'message': 'Farm request rejected'})
    
    @action(detail=False, methods=['get'])
    def pending_requests(self, request):
        """Get pending requests"""
        pending = self.get_queryset().filter(status='pending')
        serializer = self.get_serializer(pending, many=True)
        return Response(serializer.data)

class AdminPestInfoManagementViewSet(viewsets.ModelViewSet):
    queryset = PestInfo.objects.all()
    serializer_class = PestInfoSerializer
    permission_classes = [IsAdmin]
    
    def perform_create(self, serializer):
        pest_info = serializer.save(created_by=self.request.user)
        log_activity(self.request.user, 'created_pest_info', f'Pest: {pest_info.name}', self.request)
    
    @action(detail=True, methods=['post'])
    def toggle_publish(self, request, pk=None):
        pest_info = self.get_object()
        pest_info.is_published = not pest_info.is_published
        pest_info.save()
        status_text = 'published' if pest_info.is_published else 'unpublished'
        log_activity(request.user, f'{status_text}_pest_info', f'Pest: {pest_info.name}', request)
        return Response({'message': f'Pest info {status_text} successfully'})

class AdminAlertManagementViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [IsAdmin]
    
    def perform_create(self, serializer):
        alert = serializer.save(created_by=self.request.user)
        log_activity(self.request.user, 'created_alert', f'Alert: {alert.title}', self.request)
    
    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        alert = self.get_object()
        alert.is_active = not alert.is_active
        alert.save()
        status_text = 'activated' if alert.is_active else 'deactivated'
        log_activity(request.user, f'{status_text}_alert', f'Alert: {alert.title}', request)
        return Response({'message': f'Alert {status_text} successfully'})

class AdminActivityLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = UserActivity.objects.all()
    serializer_class = UserActivitySerializer
    permission_classes = [IsAdmin]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action__icontains=action)
        
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        if date_from:
            queryset = queryset.filter(timestamp__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__lte=date_to)
        
        return queryset