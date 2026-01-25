import os
import tempfile
import requests
import time
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q

from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, Farm, PestDetection, PestInfo, InfestationReport, Alert, UserActivity
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    FarmSerializer, PestDetectionSerializer, PestInfoSerializer,
    InfestationReportSerializer, AlertSerializer, UserActivitySerializer
)
from .permissions import IsAdmin, IsAdminOrReadOnly, IsFarmerOrAdmin, IsOwnerOrAdmin, IsExpertOrAdmin

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


# ==================== FARM VIEWSET ====================
class FarmViewSet(viewsets.ModelViewSet):
    serializer_class = FarmSerializer
    permission_classes = [IsAuthenticated, IsFarmerOrAdmin]

    def get_queryset(self):
        if self.request.user.role == 'admin':
            return Farm.objects.all()
        return Farm.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        farm = serializer.save(user=self.request.user)
        log_activity(self.request.user, 'created_farm', f'Farm: {farm.name}', self.request)


# ==================== PEST DETECTION VIEWSET ====================
class PestDetectionViewSet(viewsets.ModelViewSet):
    serializer_class = PestDetectionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = PestDetection.objects.all()
        if self.request.user.role != 'admin':
            queryset = queryset.filter(Q(user=self.request.user) | Q(status='verified'))

        # Geofence filter
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

            # Save detection
            detection = PestDetection.objects.create(
                user=request.user,
                image=image,
                crop_type=crop_type,
                pest_name=analysis.get('pest_name', 'Unknown Pest'),
                pest_type=analysis.get('pest_key', ''),
                confidence=analysis.get('confidence', 0.0),
                severity=analysis.get('severity', 'low'),
                latitude=lat,
                longitude=lng,
                address=request.data.get('address', ''),
                description=analysis.get('symptoms', ''),
                status='pending',
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
            return Response(response_data, status=201)

        except Exception as e:
            error_message = str(e)
            print(f"Detection error: {error_message}")
            
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

            if 'active' in request.data:
                instance.active = request.data['active']
            if 'status' in request.data:
                instance.status = request.data['status']
            if not instance.active or instance.status == 'resolved':
                instance.resolved_at = timezone.now()
                instance.status = 'resolved'
            instance.save()
            log_activity(request.user, 'updated_detection', f'Detection ID: {instance.id}', request)
            return Response(self.get_serializer(instance).data)
        except PestDetection.DoesNotExist:
            return Response({'error': 'Detection not found'}, status=404)

    def update(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    @action(detail=False, methods=['get'])
    def heatmap_data(self, request):
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        queryset = PestDetection.objects.all() if request.user.role == 'admin' else PestDetection.objects.filter(Q(user=request.user) | Q(status='verified'))
        queryset = queryset.filter(active=True).filter(Q(detected_at__gte=since) | Q(reported_at__gte=since))
        heatmap_points = [{
            'id': det.id,
            'pest': det.pest_name or det.pest_type,
            'severity': det.severity,
            'lat': det.latitude,
            'lng': det.longitude,
            'farm_id': det.farm_id,
            'reported_at': (det.reported_at or det.detected_at).isoformat(),
            'active': det.active,
            'status': det.status
        } for det in queryset]
        return Response(heatmap_points)

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        queryset = self.get_queryset().filter(user=request.user)
        by_severity = {s: queryset.filter(severity=s).count() for s in ['low','medium','high','critical']}
        by_crop = {c: queryset.filter(crop_type=c).count() for c in ['rice','corn']}
        by_pest = list(queryset.values('pest_name').annotate(count=Count('id')).order_by('-count')[:5])
        return Response({'total_detections': queryset.count(), 'by_severity': by_severity, 'by_crop': by_crop, 'by_pest': by_pest})


# ==================== PEST INFO VIEWSET ====================
class PestInfoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = PestInfo.objects.filter(is_published=True)
    serializer_class = PestInfoSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'])
    def search(self, request):
        query = request.query_params.get('q', '')
        pests = self.queryset.filter(Q(name__icontains=query) | Q(scientific_name__icontains=query) | Q(crop_affected__icontains=query))
        return Response(self.get_serializer(pests, many=True).data)


# ==================== ALERT VIEWSET ====================
class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        now = timezone.now()
        return Alert.objects.filter(Q(is_active=True, expires_at__gte=now) | Q(is_active=True, expires_at__isnull=True))


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
        if new_role in ['admin', 'farmer', 'expert']:
            user.role = new_role
            user.save()
            log_activity(request.user, 'changed_user_role', f'User: {user.username}, New role: {new_role}', request)
            return Response({'message': f'User role changed to {new_role}'})
        return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total_users = User.objects.count()
        farmers = User.objects.filter(role='farmer').count()
        experts = User.objects.filter(role='expert').count()
        admins = User.objects.filter(role='admin').count()
        verified = User.objects.filter(is_verified=True).count()
        
        return Response({
            'total_users': total_users,
            'farmers': farmers,
            'experts': experts,
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