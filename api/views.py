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

from .models import User, Farm, FarmRequest, VerificationRequest, PestDetection, PestInfo, InfestationReport, Alert, UserActivity, NotificationPreference, Notification
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    FarmSerializer, FarmRequestSerializer, VerificationRequestSerializer,
    PestDetectionSerializer, PestInfoSerializer,
    InfestationReportSerializer, AlertSerializer, UserActivitySerializer,
    NotificationPreferenceSerializer, NotificationSerializer
)
from .permissions import IsAdmin, IsAdminOrMAOStaff, IsAdminOrReadOnly, IsFarmerOrAdmin, IsOwnerOrAdmin
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
    'https://capstonegpt0-pestcheck-ml-test.hf.space'
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


@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_notification_settings(request):
    """Get or update notification preferences"""
    prefs, created = NotificationPreference.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        serializer = NotificationPreferenceSerializer(prefs)
        return Response(serializer.data)

    # PATCH
    serializer = NotificationPreferenceSerializer(prefs, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        log_activity(request.user, 'notification_settings_updated', 'Updated notification settings', request)
        return Response(serializer.data)
    return Response(serializer.errors, status=400)


# ==================== NOTIFICATION HELPER ====================
def create_notification(user, notification_type, title, message, related_id=None):
    """Create an in-app notification for a user, respecting their preferences."""
    try:
        prefs, _ = NotificationPreference.objects.get_or_create(user=user)

        # Check preferences
        if notification_type in ('detection_nearby',) and not prefs.detection_alerts:
            return None
        if notification_type in ('critical_pest',) and not prefs.critical_alerts:
            return None

        return Notification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            related_id=related_id
        )
    except Exception as e:
        print(f"Failed to create notification: {e}")
        return None


# ==================== NOTIFICATION ENDPOINTS ====================
class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """User notifications - list, read, mark all read"""
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        unread_count = queryset.filter(is_read=False).count()
        # Return latest 50
        notifications = queryset[:50]
        serializer = self.get_serializer(notifications, many=True)
        return Response({
            'unread_count': unread_count,
            'results': serializer.data
        })

    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        notification.is_read = True
        notification.save()
        return Response({'status': 'read'})

    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        self.get_queryset().filter(is_read=False).update(is_read=True)
        return Response({'status': 'all read'})

    @action(detail=False, methods=['get'])
    def unread_count(self, request):
        count = self.get_queryset().filter(is_read=False).count()
        return Response({'unread_count': count})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_push_subscription(request):
    """Save push subscription for the user"""
    subscription = request.data.get('subscription')
    if not subscription:
        return Response({'error': 'No subscription provided'}, status=400)
    prefs, _ = NotificationPreference.objects.get_or_create(user=request.user)
    prefs.push_subscription = subscription
    prefs.push_enabled = True
    prefs.save()
    return Response({'status': 'subscribed'})


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
        if not request.user.is_verified:
            return Response(
                {'error': 'Only verified farmers can request farms. Please contact an administrator to get verified.'},
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

        # Geofence filter ✅ only Magalang area
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

            # ✅ ADD VALIDATION HERE - Check if pest was actually detected
            pest_name = analysis.get('pest_name', '')
            confidence = analysis.get('confidence', 0.0)
            
            print(f"🔍 Validation - pest_name: '{pest_name}', confidence: {confidence}")
            
            # Don't save if no pest was detected
            if not pest_name or pest_name == 'Unknown Pest' or pest_name == '' or confidence < 0.1:
                print(f"❌ Validation FAILED - No valid pest detected")
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
            
            print(f"✅ Validation PASSED - Saving detection")
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
            
            print(f"✅ Returning successful detection response")
            return Response(response_data, status=201)

        except Exception as e:
            error_message = str(e)
            print(f"❌ Detection error: {error_message}")
            
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
        print(f"📋 partial_update called for detection {detection_id}")
        print(f"📋 Request data: {dict(request.data)}")
        print(f"📋 Content-Type: {request.content_type}")
        try:
            instance = PestDetection.objects.get(id=detection_id)
            if instance.user != request.user and request.user.role != 'admin':
                return Response({'error': 'Permission denied'}, status=403)

            # ✅ NEW: Handle farm_id updates
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

            # ✅ NEW: Handle severity updates (required for damage assessment)
            if 'severity' in request.data:
                valid_severities = ['low', 'medium', 'high', 'critical']
                severity = request.data['severity']
                if severity not in valid_severities:
                    return Response({
                        'error': f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
                    }, status=400)
                instance.severity = severity
            
            # ✅ NEW: Handle confirmed field updates
            if 'confirmed' in request.data:
                instance.confirmed = request.data['confirmed']
            
            if 'active' in request.data:
                instance.active = request.data['active']
            
            if 'status' in request.data:
                instance.status = request.data['status']
            
            # ✅ NEW: Allow updating description
            if 'description' in request.data:
                instance.description = request.data['description']
            
            # Allow updating coordinates (for farm location pinning)
            if 'latitude' in request.data:
                try:
                    new_lat = float(request.data['latitude'])
                    print(f"📋 Updating latitude: {instance.latitude} -> {new_lat}")
                    instance.latitude = new_lat
                except (ValueError, TypeError) as e:
                    print(f"⚠️ Invalid latitude value: {request.data['latitude']} - {e}")
            if 'longitude' in request.data:
                try:
                    new_lng = float(request.data['longitude'])
                    print(f"📋 Updating longitude: {instance.longitude} -> {new_lng}")
                    instance.longitude = new_lng
                except (ValueError, TypeError) as e:
                    print(f"⚠️ Invalid longitude value: {request.data['longitude']} - {e}")
            
            print(f"📋 Final coords before save: lat={instance.latitude}, lng={instance.longitude}")
            
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
            
            # ✅ UPDATED: Include farm and severity in log message
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
            'user_is_verified': det.user.is_verified if det.user else False,
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
        # Base: only active, non-expired alerts
        base_qs = Alert.objects.filter(
            Q(is_active=True, expires_at__gte=now) |
            Q(is_active=True, expires_at__isnull=True)
        )

        # General/system-wide alerts: empty, null, OR broad geographic names (not a specific farm)
        general_q = Q(target_area='') | Q(target_area__isnull=True) | Q(target_area__icontains='Magalang')

        # Farm-specific alerts - match user's farm names (case-insensitive contains)
        user_farms = Farm.objects.filter(user=self.request.user).values_list('name', flat=True)
        if user_farms:
            farm_q = Q()
            for farm_name in user_farms:
                farm_q |= Q(target_area__iexact=farm_name)
                farm_q |= Q(target_area__icontains=farm_name)
            queryset = base_qs.filter(general_q | farm_q)
        else:
            # Users with no farms still see general/system-wide alerts
            queryset = base_qs.filter(general_q)

        return queryset.order_by('-created_at')

    @action(detail=False, methods=['get'])
    def my_alerts(self, request):
        """Get alerts specific to user's farms + general alerts"""
        now = timezone.now()
        base_qs = Alert.objects.filter(
            is_active=True
        ).filter(
            Q(expires_at__gte=now) | Q(expires_at__isnull=True)
        )

        # Always include general alerts (empty, null, or broad geographic names)
        general_q = Q(target_area='') | Q(target_area__isnull=True) | Q(target_area__icontains='Magalang')

        user_farms = Farm.objects.filter(user=request.user).values_list('name', flat=True)
        if user_farms:
            farm_q = Q()
            for farm_name in user_farms:
                farm_q |= Q(target_area__iexact=farm_name)
                farm_q |= Q(target_area__icontains=farm_name)
            alerts = base_qs.filter(general_q | farm_q)
        else:
            alerts = base_qs.filter(general_q)

        serializer = self.get_serializer(alerts, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def proximity_stats(self, request):
        """Get proximity alert statistics"""
        stats = get_proximity_alert_stats()
        return Response(stats)



# ==================== VERIFICATION REQUEST VIEWSET ====================
class VerificationRequestViewSet(viewsets.ModelViewSet):
    """
    Farmers can submit verification requests with RSBSA number and valid ID.
    Only one pending/approved request allowed per user at a time.
    """
    serializer_class = VerificationRequestSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def get_queryset(self):
        if self.request.user.role == 'admin':
            return VerificationRequest.objects.all()
        return VerificationRequest.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        # Prevent admins from submitting requests
        if request.user.role == 'admin':
            return Response(
                {'error': 'Admins do not need to submit verification requests.'},
                status=status.HTTP_403_FORBIDDEN
            )
        # Already verified
        if request.user.is_verified:
            return Response(
                {'error': 'Your account is already verified.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Block if there is an existing pending request
        existing_pending = VerificationRequest.objects.filter(
            user=request.user, status='pending'
        ).exists()
        if existing_pending:
            return Response(
                {'error': 'You already have a pending verification request. Please wait for admin review.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        vr = serializer.save(user=self.request.user, status='pending')
        log_activity(
            self.request.user,
            'verification_request_submitted',
            f'RSBSA: {vr.rsbsa_number}',
            self.request
        )

    def update(self, request, *args, **kwargs):
        return Response({'error': 'Verification requests cannot be edited.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, *args, **kwargs):
        return Response({'error': 'Verification requests cannot be edited.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user.role != 'admin' and instance.status != 'pending':
            return Response(
                {'error': 'Only pending requests can be cancelled.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if request.user.role != 'admin' and instance.user != request.user:
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

    @action(detail=False, methods=['get'])
    def my_request(self, request):
        """Get the current user's latest verification request"""
        latest = VerificationRequest.objects.filter(user=request.user).first()
        if not latest:
            return Response(None)
        serializer = self.get_serializer(latest, context={'request': request})
        return Response(serializer.data)


# ==================== ADMIN VERIFICATION REQUEST MANAGEMENT ====================
class AdminVerificationRequestViewSet(viewsets.ModelViewSet):
    """Admin and MAO staff can view and review verification requests"""
    queryset = VerificationRequest.objects.all()
    serializer_class = VerificationRequestSerializer
    permission_classes = [IsAdminOrMAOStaff]
    parser_classes = [MultiPartParser, FormParser]

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve verification request and mark user as verified"""
        vr = self.get_object()

        if vr.status != 'pending':
            return Response(
                {'error': f'Request is already {vr.status}.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark user as verified
        vr.user.is_verified = True
        vr.user.save()

        # Update the request
        vr.status = 'approved'
        vr.reviewed_by = request.user
        vr.reviewed_at = timezone.now()
        vr.review_notes = request.data.get('review_notes', '')
        vr.save()

        log_activity(
            request.user,
            'verification_approved',
            f'Verified user: {vr.user.username}',
            request
        )

        create_notification(
            vr.user, 'verification_approved', 'Account Verified',
            'Your account has been verified! You now have full access to farm registration and pest monitoring features.',
            related_id=vr.id
        )

        return Response({
            'message': f'User {vr.user.username} has been verified successfully.',
            'user_id': vr.user.id
        })

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject verification request"""
        vr = self.get_object()

        if vr.status != 'pending':
            return Response(
                {'error': f'Request is already {vr.status}.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        vr.status = 'rejected'
        vr.reviewed_by = request.user
        vr.reviewed_at = timezone.now()
        vr.review_notes = request.data.get('review_notes', 'Rejected')
        vr.save()

        log_activity(
            request.user,
            'verification_rejected',
            f'Rejected request for user: {vr.user.username}',
            request
        )

        create_notification(
            vr.user, 'verification_rejected', 'Verification Request Rejected',
            f'Your verification request was rejected. Reason: {review_notes}. You may resubmit with corrected information.',
            related_id=vr.id
        )

        return Response({'message': f'Verification request for {vr.user.username} has been rejected.'})

    @action(detail=False, methods=['get'])
    def pending_requests(self, request):
        """Get all pending verification requests"""
        pending = self.get_queryset().filter(status='pending')
        serializer = self.get_serializer(pending, many=True, context={'request': request})
        return Response(serializer.data)


# ==================== ADMIN VIEWSETS ====================
# [Keep all your existing admin viewsets - they're already correct]

class AdminUserManagementViewSet(viewsets.ModelViewSet):
    """Admin can manage all users"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=False, methods=['post'])
    def create_staff(self, request):
        """Admin creates a MAO staff account directly"""
        data = request.data
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        phone = data.get('phone', '').strip()
        role = data.get('role', 'mao_staff')

        # Validate role — only mao_staff can be created this way
        if role not in ('mao_staff',):
            return Response(
                {'error': 'Only mao_staff accounts can be created via this endpoint.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Basic validation
        errors = {}
        if not username:
            errors['username'] = 'Username is required.'
        elif User.objects.filter(username=username).exists():
            errors['username'] = 'A user with that username already exists.'
        if not email:
            errors['email'] = 'Email is required.'
        elif User.objects.filter(email=email).exists():
            errors['email'] = 'A user with that email already exists.'
        if not password or len(password) < 8:
            errors['password'] = 'Password must be at least 8 characters.'
        if not first_name:
            errors['first_name'] = 'First name is required.'
        if not last_name:
            errors['last_name'] = 'Last name is required.'

        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            role='mao_staff',
            is_verified=True,  # Staff accounts are pre-verified
        )

        log_activity(
            request.user,
            'created_mao_staff',
            f'Created MAO staff account: {username}',
            request
        )

        return Response(
            {
                'message': f'MAO Staff account for {first_name} {last_name} created successfully.',
                'user': UserSerializer(user).data
            },
            status=status.HTTP_201_CREATED
        )

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
        if new_role in ['admin', 'mao_staff', 'farmer']:
            user.role = new_role
            user.save()
            log_activity(request.user, 'changed_user_role', f'User: {user.username}, New role: {new_role}', request)
            return Response({'message': f'User role changed to {new_role}'})
        return Response({'error': 'Invalid role. Must be admin, mao_staff, or farmer'}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total_users = User.objects.count()
        farmers = User.objects.filter(role='farmer').count()
        admins = User.objects.filter(role='admin').count()
        mao_staff = User.objects.filter(role='mao_staff').count()
        verified = User.objects.filter(is_verified=True).count()
        
        return Response({
            'total_users': total_users,
            'farmers': farmers,
            'admins': admins,
            'mao_staff': mao_staff,
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
    """Admin and MAO staff can manage farm requests"""
    queryset = FarmRequest.objects.all()
    serializer_class = FarmRequestSerializer
    permission_classes = [IsAdminOrMAOStaff]
    
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

            create_notification(
                farm_request.user, 'farm_approved', 'Farm Request Approved',
                f'Your farm "{farm_request.name}" has been approved and is now registered.',
                related_id=farm.id
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

        create_notification(
            farm_request.user, 'farm_rejected', 'Farm Request Rejected',
            f'Your farm request "{farm_request.name}" was rejected. Reason: {farm_request.review_notes}',
            related_id=farm_request.id
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
    permission_classes = [IsAdminOrMAOStaff]
    
    def perform_create(self, serializer):
        alert = serializer.save(created_by=self.request.user)
        log_activity(self.request.user, 'created_alert', f'Alert: {alert.title}', self.request)
        
        # Notify target users
        if alert.target_area:
            target_users = User.objects.filter(farms__name=alert.target_area).distinct()
        else:
            target_users = User.objects.filter(role='farmer')
        for u in target_users:
            create_notification(
                u, 'admin_alert', alert.title, alert.message, related_id=alert.id
            )
    
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