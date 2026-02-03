from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import (
    User,
    Farm,
    FarmRequest,
    PestDetection,
    PestInfo,
    InfestationReport,
    UserActivity,
    Alert
)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone', 'first_name', 'last_name', 'role', 'is_verified', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=['farmer'], default='farmer')

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'first_name', 'last_name', 'phone', 'role']

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid credentials")

# Farm Request Serializer
class FarmRequestSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    reviewed_by_name = serializers.CharField(source='reviewed_by.username', read_only=True, allow_null=True)
    approved_farm_id = serializers.IntegerField(source='approved_farm.id', read_only=True, allow_null=True)
    
    class Meta:
        model = FarmRequest
        fields = [
            'id', 'user', 'user_name', 'name', 'lat', 'lng', 'size', 'crop_type', 
            'description', 'status', 'reviewed_by', 'reviewed_by_name', 'review_notes', 
            'reviewed_at', 'approved_farm_id', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'user_name', 'status', 'reviewed_by', 'reviewed_by_name', 
            'review_notes', 'reviewed_at', 'approved_farm_id', 'created_at', 'updated_at'
        ]

class FarmSerializer(serializers.ModelSerializer):
    """
    Farm serializer with calculated status fields.
    
    IMPORTANT: Status is NOT stored in the database. It is calculated dynamically
    based on the number of active, verified detections associated with the farm.
    
    Calculated fields:
    - total_infestation_count: All verified detections (including resolved)
    - active_infestation_count: Currently active verified detections
    - calculated_status: Status level (low/moderate/high/critical) or None
    - status_display: Human-readable status text
    - status_color: CSS color class for status display
    - should_show_status: Boolean indicating if status should be shown
    """
    user_name = serializers.CharField(source='user.username', read_only=True)
    created_by_name = serializers.CharField(source='created_by.username', read_only=True, allow_null=True)
    
    # Legacy field (for backward compatibility) - shows total verified detections
    infestation_count = serializers.SerializerMethodField()
    
    # New calculated fields for dynamic status
    active_infestation_count = serializers.IntegerField(source='active_infestation_count', read_only=True)
    total_infestation_count = serializers.IntegerField(source='total_infestation_count', read_only=True)
    calculated_status = serializers.CharField(source='calculated_status', read_only=True, allow_null=True)
    status_display = serializers.CharField(source='status_display', read_only=True)
    status_color = serializers.CharField(source='status_color', read_only=True)
    should_show_status = serializers.BooleanField(source='should_show_status', read_only=True)

    class Meta:
        model = Farm
        fields = [
            'id', 'name', 'lat', 'lng', 'size', 'crop_type', 'is_verified', 
            'user_name', 'created_by_name', 'created_at', 'updated_at',
            # Infestation counts
            'infestation_count',  # Legacy field
            'active_infestation_count',
            'total_infestation_count',
            # Calculated status fields
            'calculated_status',
            'status_display',
            'status_color',
            'should_show_status'
        ]
        read_only_fields = [
            'id', 'is_verified', 'user_name', 'created_by_name', 'created_at', 'updated_at',
            'infestation_count', 'active_infestation_count', 'total_infestation_count',
            'calculated_status', 'status_display', 'status_color', 'should_show_status'
        ]

    def get_infestation_count(self, obj):
        """
        Legacy method for backward compatibility.
        Returns total verified detections (same as total_infestation_count).
        """
        return obj.total_infestation_count

class PestDetectionSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    farm_name = serializers.CharField(source='farm.name', read_only=True, allow_null=True)
    farm_id = serializers.IntegerField(source='farm.id', read_only=True, allow_null=True)
    pest = serializers.CharField(source='pest_name', read_only=True)

    class Meta:
        model = PestDetection
        fields = '__all__'
        read_only_fields = ['user', 'detected_at', 'verified_by', 'status', 'pest_name']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['pest'] = instance.pest_name or ""
        representation['farm_id'] = instance.farm.id if instance.farm else None
        return representation

class PestInfoSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.username', read_only=True, allow_null=True)
    
    class Meta:
        model = PestInfo
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at']

class InfestationReportSerializer(serializers.ModelSerializer):
    detection_details = PestDetectionSerializer(source='detection', read_only=True)
    verified_by_name = serializers.CharField(source='verified_by.username', read_only=True, allow_null=True)
    
    class Meta:
        model = InfestationReport
        fields = '__all__'
        read_only_fields = ['reported_at', 'verified_by']

class AlertSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at']

class UserActivitySerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_role = serializers.CharField(source='user.role', read_only=True)
    
    class Meta:
        model = UserActivity
        fields = ['id', 'user', 'user_name', 'user_role', 'action', 'details', 'ip_address', 'timestamp']
        read_only_fields = ['id', 'timestamp']