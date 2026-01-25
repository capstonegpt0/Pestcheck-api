from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom User model
class User(AbstractUser):
    ROLE_CHOICES = [
        ('farmer', 'Farmer'),
        ('expert', 'Expert'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='farmer')
    phone = models.CharField(max_length=20, blank=True)
    is_verified = models.BooleanField(default=False)

# Farm model
class Farm(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='farms')
    name = models.CharField(max_length=255)
    lat = models.FloatField()
    lng = models.FloatField()
    size = models.FloatField()
    crop_type = models.CharField(max_length=100)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# PestDetection model
class PestDetection(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='detections')
    farm = models.ForeignKey(Farm, on_delete=models.SET_NULL, null=True, blank=True, related_name='detections')
    pest_name = models.CharField(max_length=100, blank=True)
    image = models.ImageField(upload_to='detections/')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    detected_at = models.DateTimeField(auto_now_add=True)
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_detections')

# Optional models
class PestInfo(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
