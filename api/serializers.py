from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import (
    User,
    Farm,
    PestDetection,
    PestInfo,
    InfestationReport,
    UserActivity,
)

class PestInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PestInfo
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone', 'first_name', 'last_name', 'role', 'is_verified', 'date_joined']
        read_only_fields = ['id', 'date_joined']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=['farmer', 'expert'], default='farmer')

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

class FarmSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    infestation_count = serializers.SerializerMethodField()

    class Meta:
        model = Farm
        fields = ['id', 'name', 'lat', 'lng', 'size', 'crop_type', 'is_verified', 'created_at', 'updated_at', 'user_name', 'infestation_count']
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_verified', 'user_name']

    def get_infestation_count(self, obj):
        return obj.detections.filter(status='verified').count()

class PestDetectionSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    farm_name = serializers.CharField(source='farm.name', read_only=True, allow_null=True)
    farm_id = serializers.IntegerField(source='farm.id', read_only=True, allow_null=True)
    pest = serializers.CharField(source='pest_name', read_only=True)

    class Meta:
        model = PestDetection
        fields = '__all__'
        read_only_fields = ['user', 'detected_at', 'verified_by', 'status']

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['pest'] = instance.pest_name or ""
        representation['farm_id'] = instance.farm.id if instance.farm else None
        return representation

class PestInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PestInfo
        fields = '__all__'

class InfestationReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = InfestationReport
        fields = '__all__'