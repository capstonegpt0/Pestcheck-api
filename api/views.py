import os
import tempfile
import requests
import time
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from .models import PestDetection, Farm
from .serializers import PestDetectionSerializer
from rest_framework import viewsets, status, generics, permissions
from rest_framework.decorators import api_view, permission_classes, action, parser_classes as parser_classes_decorator
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models import User, Farm, FarmRequest, PestDetection, PestInfo, InfestationReport, Alert, UserActivity
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    FarmSerializer, FarmRequestSerializer, PestDetectionSerializer, PestInfoSerializer,
    InfestationReportSerializer, AlertSerializer, UserActivitySerializer
)
from .permissions import IsAdmin, IsAdminOrReadOnly, IsFarmerOrAdmin, IsOwnerOrAdmin

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
    """Users can submit farm requests, admin can approve/reject"""
    serializer_class = FarmRequestSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_admin():
            return FarmRequest.objects.all()
        return FarmRequest.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        farm_request = serializer.save(user=self.request.user)
        log_activity(
            self.request.user, 
            'farm_request_created', 
            f'Farm: {farm_request.name}', 
            self.request
        )
    
    @action(detail=True, methods=['post'])
    def withdraw(self, request, pk=None):
        """User can withdraw their pending request"""
        farm_request = self.get_object()
        
        if farm_request.user != request.user:
            return Response(
                {'error': 'Not authorized'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if farm_request.status != 'pending':
            return Response(
                {'error': 'Can only withdraw pending requests'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        farm_request.delete()
        log_activity(request.user, 'farm_request_withdrawn', f'Farm: {farm_request.name}', request)
        
        return Response({'message': 'Farm request withdrawn'})

# ==================== FARM VIEWSET ====================
class FarmViewSet(viewsets.ModelViewSet):
    """Users can view their farms, admins can view all"""
    serializer_class = FarmSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_admin():
            return Farm.objects.all()
        return Farm.objects.filter(user=self.request.user)


# ==================== PEST DETECTION VIEWSET ====================
class PestDetectionViewSet(viewsets.ModelViewSet):
    serializer_class = PestDetectionSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get_parser_classes(self):
        """
        Override parser classes based on the action.
        manual-report needs JSON, others need multipart/form-data for images.
        """
        if self.action == 'manual_report':
            return [JSONParser]
        return self.parser_classes

    def get_queryset(self):
        if self.request.user.is_admin():
            return PestDetection.objects.all()
        return PestDetection.objects.filter(user=self.request.user)

    @action(detail=False, methods=['post'], url_path='preview')
    def preview_detection(self, request):
        """
        Preview detection without saving to database.
        This allows users to confirm before saving.
        """
        temp_path = None
        try:
            crop_type = request.data.get('crop_type', 'rice')
            image = request.FILES.get('image')

            if not image:
                return Response({'error': 'No image provided'}, status=400)

            # Save temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
                for chunk in image.chunks():
                    tmp_file.write(chunk)
                temp_path = tmp_file.name

            print(f"🔍 Previewing detection - image: {temp_path}, crop: {crop_type}")
            
            # Call ML API
            analysis = call_ml_api(temp_path, crop_type=crop_type)
            
            print(f"ML API response: {analysis}")

            # Validate detection
            pest_name = analysis.get('pest_name', '')
            confidence = analysis.get('confidence', 0.0)
            
            print(f"📋 Validation - pest_name: '{pest_name}', confidence: {confidence}")
            
            # Don't allow preview of invalid detections
            if not pest_name or pest_name == 'Unknown Pest' or pest_name == '' or confidence < 0.1:
                print(f"❌ Validation FAILED - No valid pest detected")
                return Response({
                    'error': 'No pest detected in the image. Please try another image with clearer pest visibility.',
                    'retry': True
                }, status=400)
            
            print(f"✅ Valid detection - returning preview")

            # Return preview data (don't save to database)
            preview_data = {
                'pest_name': pest_name,
                'pest_key': analysis.get('pest_key', ''),
                'confidence': confidence,
                'severity': analysis.get('severity', 'low'),
                'scientific_name': analysis.get('scientific_name', ''),
                'symptoms': analysis.get('symptoms', ''),
                'control_methods': analysis.get('control_methods', []),
                'prevention': analysis.get('prevention', []),
                'num_detections': analysis.get('num_detections', 1),
                'crop_type': crop_type
            }
            
            return Response(preview_data, status=200)

        except Exception as e:
            error_message = str(e)
            print(f"❌ Preview error: {error_message}")
            
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

    def create(self, request, *args, **kwargs):
        """
        Save confirmed detection to database.
        This is called after user confirms the preview.
        """
        try:
            lat = float(request.data.get('latitude', 0))
            lng = float(request.data.get('longitude', 0))
            crop_type = request.data.get('crop_type', 'rice')
            image = request.FILES.get('image')
            
            # Get confirmed data from request
            pest_name = request.data.get('pest_name', '')
            pest_type = request.data.get('pest_type', '')
            confidence = float(request.data.get('confidence', 0.0))
            severity = request.data.get('severity', 'low')

            if not image:
                return Response({'error': 'No image provided'}, status=400)

            # Validate that we have the required data
            if not pest_name or confidence < 0.1:
                return Response({
                    'error': 'Invalid detection data. Please try detection again.',
                }, status=400)
            
            print(f"✅ Saving confirmed detection")
            print(f"   pest_name: '{pest_name}'")
            print(f"   confidence: {confidence}")

            # Save the confirmed detection
            detection = PestDetection.objects.create(
                user=request.user,
                image=image,
                crop_type=crop_type,
                pest_name=pest_name,
                pest_type=pest_type,
                confidence=confidence,
                severity=severity,
                latitude=lat,
                longitude=lng,
                address=request.data.get('address', ''),
                status='pending',
                detected_at=timezone.now()
            )
            log_activity(request.user, 'confirmed_pest_detection', f"Pest: {detection.pest_name}", request)

            serializer = self.get_serializer(detection)
            
            print(f"✅ Detection saved successfully - ID: {detection.id}")
            return Response(serializer.data, status=201)

        except Exception as e:
            error_message = str(e)
            print(f"❌ Save error: {error_message}")
            return Response({
                'error': f'Failed to save detection: {error_message}',
            }, status=500)

    @action(detail=False, methods=['post'], url_path='manual-report')
    def manual_report(self, request):
        """
        Create a manual infestation report without requiring an image.
        This is used when farmers want to report infestations from the map.
        """
        try:
            # Extract and validate data with defaults
            pest_name = str(request.data.get('pest', '')).strip()
            severity = str(request.data.get('severity', 'low')).strip().lower()
            address = str(request.data.get('address', 'Magalang, Pampanga')).strip()
            description = str(request.data.get('description', '')).strip()
            crop_type = str(request.data.get('crop_type', 'rice')).strip().lower()
            
            # Handle farm_id safely
            farm_id = request.data.get('farm_id')
            
            # Handle latitude/longitude safely
            try:
                lat = float(request.data.get('latitude', 0))
                lng = float(request.data.get('longitude', 0))
            except (ValueError, TypeError) as e:
                print(f"❌ Invalid coordinates: lat={request.data.get('latitude')}, lng={request.data.get('longitude')}")
                return Response({
                    'error': 'Invalid latitude or longitude values'
                }, status=400)

            print(f"📝 Manual report request received")
            print(f"   Data received: {request.data}")
            print(f"   pest_name: '{pest_name}'")
            print(f"   severity: '{severity}'")
            print(f"   crop_type: '{crop_type}'")
            print(f"   lat: {lat}, lng: {lng}")
            print(f"   farm_id: {farm_id}")

            # Validate required fields
            if not pest_name or pest_name == '':
                print(f"❌ Pest name is empty")
                return Response({
                    'error': 'Pest type is required and cannot be empty'
                }, status=400)

            if lat == 0 or lng == 0:
                print(f"❌ Coordinates are zero")
                return Response({
                    'error': 'Valid location coordinates are required'
                }, status=400)

            # Get farm if provided
            farm = None
            if farm_id:
                try:
                    farm_id_int = int(farm_id)
                    farm = Farm.objects.get(id=farm_id_int)
                    print(f"✓ Found farm: {farm.name}")
                    
                    # Try to get farm's crop type
                    if hasattr(farm, 'crop_type') and farm.crop_type:
                        farm_crop = str(farm.crop_type).strip().lower()
                        print(f"   Farm crop type: '{farm_crop}'")
                        # Only use if it's valid
                        if farm_crop in ['rice', 'corn']:
                            crop_type = farm_crop
                            print(f"   Using farm crop type: {crop_type}")
                except (ValueError, TypeError) as e:
                    print(f"⚠️ Invalid farm_id format: {farm_id} - {e}")
                except Farm.DoesNotExist:
                    print(f"⚠️ Farm {farm_id} not found")
                except Exception as e:
                    print(f"⚠️ Error getting farm: {e}")

            # Normalize and validate crop_type
            if crop_type not in ['rice', 'corn']:
                print(f"⚠️ Invalid crop_type '{crop_type}', defaulting to 'rice'")
                crop_type = 'rice'

            # Normalize and validate severity
            if severity not in ['low', 'medium', 'high', 'critical']:
                print(f"⚠️ Invalid severity '{severity}', defaulting to 'low'")
                severity = 'low'

            print(f"✓ Validated data:")
            print(f"   pest_name: {pest_name}")
            print(f"   severity: {severity}")
            print(f"   crop_type: {crop_type}")
            print(f"   location: {lat}, {lng}")
            print(f"   farm: {farm.id if farm else None}")

            # Create detection
            try:
                detection = PestDetection.objects.create(
                    user=request.user,
                    farm=farm,
                    image=None,
                    crop_type=crop_type,
                    pest_name=pest_name,
                    pest_type=pest_name,
                    confidence=0.0,
                    severity=severity,
                    latitude=lat,
                    longitude=lng,
                    address=address if address else 'Magalang, Pampanga',
                    description=description,
                    status='pending',
                    detected_at=timezone.now()
                )
                print(f"✅ Detection created successfully - ID: {detection.id}")
            except Exception as e:
                import traceback
                print(f"❌ Database error creating detection:")
                print(f"   Error: {str(e)}")
                print(f"   Type: {type(e).__name__}")
                print(f"   Traceback:\n{traceback.format_exc()}")
                return Response({
                    'error': f'Database error: {str(e)}'
                }, status=500)
            
            # Log activity
            try:
                log_activity(
                    request.user, 
                    'manual_infestation_report', 
                    f"Pest: {detection.pest_name}", 
                    request
                )
            except Exception as e:
                print(f"⚠️ Could not log activity: {e}")
                # Don't fail the request if logging fails

            # Serialize response
            try:
                serializer = self.get_serializer(detection)
                response_data = serializer.data
                print(f"✅ Manual report saved and serialized successfully")
                return Response(response_data, status=201)
            except Exception as e:
                print(f"⚠️ Serialization error: {e}")
                # Return basic response if serialization fails
                return Response({
                    'id': detection.id,
                    'pest_name': detection.pest_name,
                    'severity': detection.severity,
                    'message': 'Report saved successfully'
                }, status=201)

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"❌ CRITICAL ERROR in manual_report:")
            print(f"   Error message: {str(e)}")
            print(f"   Error type: {type(e).__name__}")
            print(f"   Full traceback:\n{error_trace}")
            
            return Response({
                'error': f'Server error: {str(e)}',
                'type': type(e).__name__
            }, status=500)
                
    def partial_update(self, request, *args, **kwargs):
        detection_id = kwargs.get('pk')
        try:
            # Get the instance with a SELECT FOR UPDATE lock to prevent race conditions
            instance = PestDetection.objects.select_for_update().get(id=detection_id)
            
            # Permission check
            if instance.user != request.user and request.user.role != 'admin':
                return Response({'error': 'Permission denied'}, status=403)

            # Log the incoming request
            print(f"🔄 PATCH request for detection {detection_id}:")
            print(f"   Request data: {request.data}")
            print(f"   Current active status: {instance.active}")
            print(f"   Current status: {instance.status}")
            
            # Update active field if provided
            if 'active' in request.data:
                new_active = request.data['active']
                print(f"   Setting active to: {new_active}")
                instance.active = new_active
                
            # Update status field if provided
            if 'status' in request.data:
                instance.status = request.data['status']
                
            # If being marked as inactive or resolved, ensure both fields are set correctly
            if not instance.active or instance.status == 'resolved':
                instance.active = False  # Explicitly set to False
                instance.status = 'resolved'
                instance.resolved_at = timezone.now()
                print(f"   ✅ Marking as resolved: active=False, status=resolved")
                
            # Save the instance
            instance.save()
            
            # Log the result
            print(f"   ✅ Saved to database:")
            print(f"      active: {instance.active}")
            print(f"      status: {instance.status}")
            print(f"      resolved_at: {instance.resolved_at}")
            
            # Log the activity
            log_activity(request.user, 'updated_detection', f'Detection ID: {instance.id} - active: {instance.active}', request)
            
            # Serialize and return
            serialized_data = self.get_serializer(instance).data
            print(f"   📤 Returning serialized data: active={serialized_data.get('active')}")
            
            return Response(serialized_data)
            
        except PestDetection.DoesNotExist:
            return Response({'error': 'Detection not found'}, status=404)

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get user's detection statistics"""
        user_detections = self.get_queryset()
        
        total = user_detections.count()
        by_crop = {
            'rice': user_detections.filter(crop_type='rice').count(),
            'corn': user_detections.filter(crop_type='corn').count(),
        }
        by_severity = {
            'low': user_detections.filter(severity='low').count(),
            'medium': user_detections.filter(severity='medium').count(),
            'high': user_detections.filter(severity='high').count(),
            'critical': user_detections.filter(severity='critical').count(),
        }
        recent = user_detections.filter(
            detected_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        return Response({
            'total_detections': total,
            'recent_week': recent,
            'by_severity': by_severity,
            'by_crop_type': by_crop
        })

# ==================== PEST INFO VIEWSET ====================
class PestInfoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = PestInfo.objects.filter(is_published=True)
    serializer_class = PestInfoSerializer
    permission_classes = [AllowAny]

# ==================== INFESTATION REPORT VIEWSET ====================
class InfestationReportViewSet(viewsets.ModelViewSet):
    serializer_class = InfestationReportSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.is_admin():
            return InfestationReport.objects.all()
        return InfestationReport.objects.filter(detection__user=self.request.user)
    
    def perform_create(self, serializer):
        report = serializer.save()
        log_activity(
            self.request.user, 
            'created_infestation_report', 
            f"Detection ID: {report.detection.id}", 
            self.request
        )

# ==================== ALERT VIEWSET ====================
class AlertViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Show active alerts that haven't expired
        return Alert.objects.filter(
            is_active=True
        ).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gte=timezone.now())
        )

# ==================== ADMIN VIEWSETS ====================
class AdminDashboardViewSet(viewsets.ViewSet):
    permission_classes = [IsAdmin]
    
    @action(detail=False, methods=['get'])
    def overview(self, request):
        total_users = User.objects.filter(role='farmer').count()
        total_farms = Farm.objects.count()
        total_detections = PestDetection.objects.count()
        pending_requests = FarmRequest.objects.filter(status='pending').count()
        
        recent_detections = PestDetection.objects.filter(
            detected_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        active_alerts = Alert.objects.filter(is_active=True).count()
        
        return Response({
            'total_users': total_users,
            'total_farms': total_farms,
            'total_detections': total_detections,
            'pending_farm_requests': pending_requests,
            'recent_detections_week': recent_detections,
            'active_alerts': active_alerts
        })
    
    @action(detail=False, methods=['get'])
    def analytics(self, request):
        # Detection trends
        detections_by_month = PestDetection.objects.extra(
            select={'month': "strftime('%%Y-%%m', detected_at)"}
        ).values('month').annotate(count=Count('id'))
        
        # Severity distribution
        severity_dist = {
            'low': PestDetection.objects.filter(severity='low').count(),
            'medium': PestDetection.objects.filter(severity='medium').count(),
            'high': PestDetection.objects.filter(severity='high').count(),
            'critical': PestDetection.objects.filter(severity='critical').count(),
        }
        
        # Crop type distribution
        crop_dist = {
            'rice': PestDetection.objects.filter(crop_type='rice').count(),
            'corn': PestDetection.objects.filter(crop_type='corn').count(),
        }
        
        return Response({
            'detections_by_month': list(detections_by_month),
            'severity_distribution': severity_dist,
            'crop_distribution': crop_dist
        })

class AdminUserManagementViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(role='farmer')
    serializer_class = UserSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=True, methods=['post'])
    def toggle_verification(self, request, pk=None):
        user = self.get_object()
        user.is_verified = not user.is_verified
        user.save()
        status_text = 'verified' if user.is_verified else 'unverified'
        log_activity(request.user, f'{status_text}_user', f'User: {user.username}', request)
        return Response({'message': f'User {status_text} successfully'})
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total = User.objects.filter(role='farmer').count()
        verified = User.objects.filter(role='farmer', is_verified=True).count()
        active = User.objects.filter(
            role='farmer',
            last_login__gte=timezone.now() - timedelta(days=30)
        ).count()
        
        return Response({
            'total_farmers': total,
            'verified_farmers': verified,
            'active_farmers': active
        })

class AdminFarmManagementViewSet(viewsets.ModelViewSet):
    queryset = Farm.objects.all()
    serializer_class = FarmSerializer
    permission_classes = [IsAdmin]
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        total = Farm.objects.count()
        verified = Farm.objects.filter(is_verified=True).count()
        by_crop = {
            'rice': Farm.objects.filter(crop_type='rice').count(),
            'corn': Farm.objects.filter(crop_type='corn').count(),
        }
        
        return Response({
            'total_farms': total,
            'verified_farms': verified,
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

# ==================== LEGACY API VIEWS (FOR BACKWARDS COMPATIBILITY) ====================
class DetectionListCreateAPIView(generics.ListCreateAPIView):
    """Legacy view - kept for backwards compatibility. Use PestDetectionViewSet instead."""
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
    """Legacy view - kept for backwards compatibility. Use PestDetectionViewSet.statistics instead."""
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