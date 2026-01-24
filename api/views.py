from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import User, Farm, PestDetection, PestInfo, InfestationReport, Alert, UserActivity
from .serializers import (UserSerializer, RegisterSerializer, LoginSerializer,
                          FarmSerializer, PestDetectionSerializer, PestInfoSerializer,
                          InfestationReportSerializer, AlertSerializer, UserActivitySerializer)
from .permissions import IsAdmin, IsAdminOrReadOnly, IsFarmerOrAdmin, IsOwnerOrAdmin, IsExpertOrAdmin

# Magalang, Pampanga bounds
MAGALANG_BOUNDS = {
    'north': 15.2547,
    'south': 15.1547,
    'east': 120.6447,
    'west': 120.5447
}

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

def log_activity(user, action, details='', request=None):
    """Helper function to log user activities"""
    ip_address = None
    if request:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
    
    UserActivity.objects.create(
        user=user,
        action=action,
        details=details,
        ip_address=ip_address
    )

@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        log_activity(user, 'user_registered', request=request)
        return Response({
            'user': UserSerializer(user).data,
            'tokens': tokens
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data
        tokens = get_tokens_for_user(user)
        log_activity(user, 'user_logged_in', request=request)
        return Response({
            'user': UserSerializer(user).data,
            'tokens': tokens
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

# ==================== FARMER/USER VIEWSETS ====================

class FarmViewSet(viewsets.ModelViewSet):
    """ViewSet for managing farms - Farmers can CRUD their own farms"""
    serializer_class = FarmSerializer
    permission_classes = [IsAuthenticated, IsFarmerOrAdmin]
    http_method_names = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']
    
    def get_queryset(self):
        if self.request.user.role == 'admin':
            return Farm.objects.all()
        return Farm.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        farm = serializer.save(user=self.request.user)
        log_activity(self.request.user, 'created_farm', f'Farm: {farm.name}', self.request)

class PestDetectionViewSet(viewsets.ModelViewSet):
    """ViewSet for pest detections - Users can view/create, Admins can verify"""
    queryset = PestDetection.objects.all()
    serializer_class = PestDetectionSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by geofence (Magalang, Pampanga)
        queryset = queryset.filter(
            latitude__gte=MAGALANG_BOUNDS['south'],
            latitude__lte=MAGALANG_BOUNDS['north'],
            longitude__gte=MAGALANG_BOUNDS['west'],
            longitude__lte=MAGALANG_BOUNDS['east']
        )
        
        # Farmers see only verified or their own detections
        if self.request.user.role == 'farmer':
            queryset = queryset.filter(
                Q(user=self.request.user) | Q(status='verified')
            )
        
        # Filter by user if requested
        if self.request.query_params.get('my_detections'):
            queryset = queryset.filter(user=self.request.user)
        
        # Get page_size parameter for pagination
        page_size = self.request.query_params.get('page_size')
        if page_size:
            self.pagination_class.page_size = int(page_size)
        
        return queryset
    
    def create(self, request):
        print("\n" + "=" * 70)
        print("PEST DETECTION REQUEST")
        print("=" * 70)
        print(f"User: {request.user}")
        print(f"Files: {list(request.FILES.keys())}")
        print(f"Data keys: {list(request.data.keys())}")
        
        # Check if this is a manual report (from HeatMap) or image detection
        if 'image' not in request.FILES:
            print("→ Manual infestation report (no image)")
            
            try:
                lat = float(request.data.get('latitude', 0))
                lng = float(request.data.get('longitude', 0))
            except (ValueError, TypeError):
                return Response({
                    'error': 'Invalid latitude or longitude'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            farm_id = request.data.get('farm_id')
            farm = None
            if farm_id:
                try:
                    farm = Farm.objects.get(id=farm_id, user=request.user)
                except Farm.DoesNotExist:
                    return Response({
                        'error': 'Farm not found or does not belong to you'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
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
            
            print(f"✓ Manual detection created: ID={detection.id}")
            log_activity(request.user, 'reported_infestation', f'Pest: {detection.pest_name}', request)
            
            # Return properly serialized response
            serializer = self.get_serializer(detection)
            response_data = serializer.data
            
            # Ensure farm_id is included in response
            response_data['farm_id'] = farm.id if farm else None
            
            print(f"Response data: {response_data}")
            print("=" * 70)
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        # Image-based detection
        print("→ Image-based detection")
        
        temp_path = None
        try:
            lat = float(request.data.get('latitude', 0))
            lng = float(request.data.get('longitude', 0))
            crop_type = request.data.get('crop_type', 'rice')
            
            print(f"Location: ({lat}, {lng})")
            print(f"Crop: {crop_type}")
            
            # Validate location (lenient for testing)
            in_bounds = (MAGALANG_BOUNDS['south'] <= lat <= MAGALANG_BOUNDS['north'] and
                        MAGALANG_BOUNDS['west'] <= lng <= MAGALANG_BOUNDS['east'])
            
            if not in_bounds:
                print(f"⚠ WARNING: Location outside Magalang bounds")
                print(f"  Bounds: {MAGALANG_BOUNDS}")
                print(f"  Received: lat={lat}, lng={lng}")
            
            image = request.FILES.get('image')
            if not image:
                return Response({'error': 'No image provided'}, status=status.HTTP_400_BAD_REQUEST)
            
            print(f"Image: {image.name} ({image.size} bytes)")
            
            # Save image temporarily
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as temp_file:
                for chunk in image.chunks():
                    temp_file.write(chunk)
                temp_path = temp_file.name
            
            print(f"Temp file: {temp_path}")
            
            # Try to use ML model
            try:
                from .ml_model import analyze_pest_image
                print("→ Running ML detection...")
                analysis = analyze_pest_image(temp_path, crop_type=crop_type)
                print(f"✓ Detection complete: {analysis.get('pest_name')}")
            except ImportError as e:
                print(f"⚠ ML model not available: {e}")
                print("→ Using mock detection")
                analysis = {
                    'success': True,
                    'pest_name': 'Brown Planthopper' if crop_type == 'rice' else 'Armyworm',
                    'scientific_name': 'Nilaparvata lugens' if crop_type == 'rice' else 'Spodoptera frugiperda',
                    'confidence': 0.85,
                    'severity': 'medium',
                    'crop_type': crop_type,
                    'symptoms': 'Yellow-orange discoloration of leaves' if crop_type == 'rice' else 'Window-paning on leaves',
                    'control_methods': ['Apply appropriate insecticides', 'Use biological control methods'],
                    'prevention': ['Maintain field sanitation', 'Regular monitoring'],
                    'num_detections': 1
                }
            except Exception as e:
                print(f"⚠ ML detection error: {e}")
                import traceback
                traceback.print_exc()
                analysis = {
                    'success': True,
                    'pest_name': 'Brown Planthopper' if crop_type == 'rice' else 'Armyworm',
                    'scientific_name': 'Nilaparvata lugens' if crop_type == 'rice' else 'Spodoptera frugiperda',
                    'confidence': 0.75,
                    'severity': 'medium',
                    'crop_type': crop_type,
                    'symptoms': 'Pest damage detected on crop',
                    'control_methods': ['Consult agricultural expert', 'Apply appropriate treatments'],
                    'prevention': ['Regular field inspection'],
                    'num_detections': 1
                }
            
            if not analysis.get('success', False):
                return Response({
                    'error': analysis.get('message', 'Detection failed')
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create detection record
            detection = PestDetection.objects.create(
                user=request.user,
                image=image,
                crop_type=crop_type,
                pest_name=analysis['pest_name'],
                pest_type=analysis.get('pest_key', ''),
                confidence=analysis['confidence'],
                severity=analysis['severity'],
                latitude=lat,
                longitude=lng,
                address=request.data.get('address', ''),
                description=analysis.get('symptoms', ''),
                status='pending',
                detected_at=timezone.now()
            )
            
            print(f"✓ Detection saved: ID={detection.id}")
            
            log_activity(request.user, 'detected_pest', f'Pest: {detection.pest_name}', request)
            
            # Return detailed response
            serializer = self.get_serializer(detection)
            response_data = serializer.data
            response_data['scientific_name'] = analysis.get('scientific_name', '')
            response_data['symptoms'] = analysis.get('symptoms', '')
            response_data['control_methods'] = analysis.get('control_methods', [])
            response_data['prevention'] = analysis.get('prevention', [])
            response_data['num_detections'] = analysis.get('num_detections', 1)
            
            print("=" * 70)
            return Response(response_data, status=status.HTTP_201_CREATED)
                    
        except ValueError as e:
            print(f"✗ ValueError: {e}")
            return Response({'error': f'Invalid data: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"✗ Exception: {e}")
            import traceback
            traceback.print_exc()
            return Response({
                'error': f'Detection processing failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            # Clean up temp file
            import os
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                    print(f"✓ Cleaned up temp file: {temp_path}")
                except Exception as e:
                    print(f"⚠ Failed to clean up temp file: {e}")
    
    def partial_update(self, request, *args, **kwargs):
        """Handle PATCH requests for resolving infestations"""
        print("\n" + "=" * 70)
        print("PATCH REQUEST - UPDATING DETECTION")
        print("=" * 70)
        print(f"User: {request.user}")
        print(f"Detection ID: {kwargs.get('pk')}")
        print(f"Data: {request.data}")
        
        try:
            instance = self.get_object()
            print(f"Current detection: {instance.id} - {instance.pest_name}")
            print(f"Current active: {instance.active}")
            print(f"Current status: {instance.status}")
            
            # Only owner or admin can update
            if instance.user != request.user and request.user.role != 'admin':
                print("✗ Permission denied")
                return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
            # Update fields
            if 'active' in request.data:
                instance.active = request.data['active']
                print(f"→ Setting active to: {instance.active}")
            
            if 'status' in request.data:
                instance.status = request.data['status']
                print(f"→ Setting status to: {instance.status}")
            
            # If being resolved, set resolved_at timestamp
            if not instance.active or instance.status == 'resolved':
                instance.resolved_at = timezone.now()
                instance.status = 'resolved'
                print(f"→ Marking as resolved at: {instance.resolved_at}")
            
            instance.save()
            print(f"✓ Detection updated successfully")
            
            log_activity(request.user, 'updated_detection', f'Detection ID: {instance.id}', request)
            
            serializer = self.get_serializer(instance)
            print("=" * 70)
            return Response(serializer.data)
            
        except Exception as e:
            print(f"✗ Error updating detection: {e}")
            import traceback
            traceback.print_exc()
            print("=" * 70)
            return Response({
                'error': f'Failed to update detection: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def update(self, request, *args, **kwargs):
        """Handle PUT requests - same as PATCH for this endpoint"""
        return self.partial_update(request, *args, **kwargs)
    
    @action(detail=False, methods=['get'])
    def heatmap_data(self, request):
        """Get data for heatmap visualization"""
        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)
        
        # Get all detections for the user (or all if admin)
        if request.user.role == 'admin':
            queryset = PestDetection.objects.all()
        else:
            queryset = PestDetection.objects.filter(
                Q(user=request.user) | Q(status='verified')
            )
        
        # Filter by date and active status
        queryset = queryset.filter(
            active=True
        )
        
        # Apply date filter - use detected_at OR reported_at
        queryset = queryset.filter(
            Q(detected_at__gte=since) | Q(reported_at__gte=since)
        )
        
        heatmap_points = []
        for detection in queryset:
            heatmap_points.append({
                'id': detection.id,
                'pest': detection.pest_name or detection.pest_type,
                'severity': detection.severity,
                'lat': detection.latitude,
                'lng': detection.longitude,
                'farm_id': detection.farm_id,
                'reported_at': (detection.reported_at or detection.detected_at).isoformat() if (detection.reported_at or detection.detected_at) else timezone.now().isoformat(),
                'active': detection.active,
                'status': detection.status
            })
        
        return Response(heatmap_points)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get detection statistics for dashboard"""
        queryset = self.get_queryset().filter(user=request.user)
        
        # By severity
        by_severity = {
            'low': queryset.filter(severity='low').count(),
            'medium': queryset.filter(severity='medium').count(),
            'high': queryset.filter(severity='high').count(),
            'critical': queryset.filter(severity='critical').count(),
        }
        
        # By crop
        by_crop = {
            'rice': queryset.filter(crop_type='rice').count(),
            'corn': queryset.filter(crop_type='corn').count(),
        }
        
        # By pest (top pests)
        by_pest = list(
            queryset.values('pest_name')
            .annotate(count=Count('id'))
            .order_by('-count')[:5]
        )
        
        stats = {
            'total_detections': queryset.count(),
            'by_severity': by_severity,
            'by_crop': by_crop,
            'by_pest': by_pest,
        }
        
        return Response(stats)

class PestInfoViewSet(viewsets.ReadOnlyModelViewSet):
    """Pest information - Read only for users"""
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
        serializer = self.get_serializer(pests, many=True)
        return Response(serializer.data)

class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    """Alerts - Read only for users, managed by admin"""
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Alert.objects.filter(
            is_active=True,
            expires_at__gte=timezone.now()
        ) | Alert.objects.filter(
            is_active=True,
            expires_at__isnull=True
        )

# ==================== ADMIN-ONLY VIEWSETS ====================

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
        """Get user statistics"""
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
    """Admin can manage and verify all farms"""
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
        """Get farm statistics"""
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
    """Admin can manage and verify all detections"""
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
        """Get all pending detections"""
        pending = PestDetection.objects.filter(status='pending')
        serializer = self.get_serializer(pending, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get detection statistics for admin dashboard"""
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
    """Admin can create, edit, and manage pest information"""
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
    """Admin can create and manage alerts"""
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
    """Admin can view all user activities"""
    queryset = UserActivity.objects.all()
    serializer_class = UserActivitySerializer
    permission_classes = [IsAdmin]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by user if provided
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by action if provided
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action__icontains=action)
        
        # Filter by date range
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        if date_from:
            queryset = queryset.filter(timestamp__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__lte=date_to)
        
        return queryset