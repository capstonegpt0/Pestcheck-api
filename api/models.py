from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Custom User model
class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('farmer', 'Farmer'),
    ]
    
    phone = models.CharField(max_length=15, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='farmer')
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'users'
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_farmer(self):
        return self.role == 'farmer'

# Farm Request model - Users request farms here
class FarmRequest(models.Model):
    """Farm registration requests from users - requires admin approval"""
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='farm_requests')
    name = models.CharField(max_length=200)
    lat = models.FloatField(verbose_name='Latitude')
    lng = models.FloatField(verbose_name='Longitude')
    size = models.FloatField(null=True, blank=True, help_text='Size in hectares')
    crop_type = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField(blank=True, help_text='Additional information about the farm')
    
    # Request status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Admin review
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_farm_requests')
    review_notes = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    
    # Associated farm (created when approved)
    approved_farm = models.ForeignKey('Farm', on_delete=models.SET_NULL, null=True, blank=True, related_name='original_request')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'farm_requests'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.user.username} ({self.status})"

# Farm model - Created only by admin when approving requests
class Farm(models.Model):
    """
    Farm locations for users - Created only by admin approval.
    
    IMPORTANT: Farms do NOT have a status field stored in the database.
    Status is calculated dynamically based on the number of active detections.
    See the calculated_status property for status logic.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='farms')
    name = models.CharField(max_length=200)
    lat = models.FloatField(verbose_name='Latitude')
    lng = models.FloatField(verbose_name='Longitude')
    size = models.FloatField(null=True, blank=True, help_text='Size in hectares')
    crop_type = models.CharField(max_length=100, null=True, blank=True)
    is_verified = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='farms_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'farms'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} - {self.user.username}"
    
    # ==================== CALCULATED STATUS PROPERTIES ====================
    # These properties calculate farm status dynamically based on detections.
    # NO status is stored in the database.
    
    @property
    def active_infestation_count(self):
        """
        Count of currently active, verified pest detections on this farm.
        This is the primary metric used to calculate farm status.
        """
        return self.detections.filter(active=True, status='verified').count()
    
    @property
    def total_infestation_count(self):
        """
        Total count of all verified detections (including resolved ones).
        Useful for historical tracking.
        """
        return self.detections.filter(status='verified').count()
    
    @property
    def calculated_status(self):
        """
        Calculate farm status based on active detection count.
        Returns None until the minimum threshold is reached.
        
        Thresholds:
        - None: 0-2 detections (below threshold, no status shown)
        - 'low': 3-4 detections
        - 'moderate': 5-6 detections
        - 'high': 7-9 detections
        - 'critical': 10+ detections
        
        Returns:
            str or None: Status level or None if below threshold
        """
        MINIMUM_THRESHOLD = 3
        count = self.active_infestation_count
        
        # NO STATUS until minimum threshold is reached
        if count < MINIMUM_THRESHOLD:
            return None
        
        # Calculate status based on count
        if count >= 10:
            return 'critical'
        elif count >= 7:
            return 'high'
        elif count >= 5:
            return 'moderate'
        elif count >= MINIMUM_THRESHOLD:
            return 'low'
        
        return None
    
    @property
    def status_display(self):
        """
        Get human-readable status display text.
        Returns empty string if no status (below threshold).
        
        Returns:
            str: Human-readable status or empty string
        """
        status = self.calculated_status
        if not status:
            return ''
        
        status_map = {
            'low': 'Low Risk - Early Detection',
            'moderate': 'Moderate Risk - Action Needed',
            'high': 'High Risk - Monitor Closely',
            'critical': 'Critical - High Infestation'
        }
        return status_map.get(status, '')
    
    @property
    def status_color(self):
        """
        Get color code for status display.
        Returns empty string if no status.
        
        Returns:
            str: CSS color class or empty string
        """
        status = self.calculated_status
        if not status:
            return ''
        
        color_map = {
            'low': 'text-green-600',
            'moderate': 'text-yellow-600',
            'high': 'text-orange-600',
            'critical': 'text-red-700'
        }
        return color_map.get(status, '')
    
    @property
    def should_show_status(self):
        """
        Determine if status should be displayed to users.
        Returns False if detection count is below threshold.
        
        Returns:
            bool: True if status should be shown, False otherwise
        """
        return self.calculated_status is not None

# PestDetection model
class PestDetection(models.Model):
    CROP_CHOICES = [
        ('rice', 'Rice'),
        ('corn', 'Corn'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
        ('resolved', 'Resolved'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='detections')
    farm = models.ForeignKey(Farm, on_delete=models.SET_NULL, null=True, blank=True, related_name='detections')
    image = models.ImageField(upload_to='pest_images/', null=True, blank=True)
    crop_type = models.CharField(max_length=10, choices=CROP_CHOICES)
    pest_name = models.CharField(max_length=255, blank=True)
    pest_type = models.CharField(max_length=200, null=True, blank=True)
    confidence = models.FloatField(default=0.0)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    latitude = models.FloatField()
    longitude = models.FloatField()
    address = models.CharField(max_length=255, blank=True)
    description = models.TextField(null=True, blank=True)
    active = models.BooleanField(default=True)
    detected_at = models.DateTimeField(default=timezone.now)
    reported_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_detections')
    admin_notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'pest_detections'
        ordering = ['-detected_at']

    def __str__(self):
        return f"{self.pest_name} - {self.crop_type} ({self.detected_at})"

# PestInfo model
class PestInfo(models.Model):
    name = models.CharField(max_length=100, unique=True)
    scientific_name = models.CharField(max_length=100)
    crop_affected = models.CharField(max_length=50)
    description = models.TextField()
    symptoms = models.TextField()
    control_methods = models.TextField()
    prevention = models.TextField()
    image_url = models.URLField(blank=True)
    is_published = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pest_info'
    
    def __str__(self):
        return self.name

# InfestationReport model
class InfestationReport(models.Model):
    detection = models.OneToOneField(PestDetection, on_delete=models.CASCADE)
    area_affected = models.FloatField(help_text="Area in hectares")
    notes = models.TextField(blank=True)
    is_verified = models.BooleanField(default=False)
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_reports')
    reported_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'infestation_reports'
    
    def __str__(self):
        return f"Report for {self.detection.id} at {self.reported_at}"

# Alert model
class Alert(models.Model):
    """Admin can create alerts for farmers"""
    ALERT_TYPES = [
        ('warning', 'Warning'),
        ('info', 'Information'),
        ('critical', 'Critical'),
    ]
    
    title = models.CharField(max_length=200)
    message = models.TextField()
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES, default='info')
    target_area = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'alerts'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.title

# UserActivity model
class UserActivity(models.Model):
    """Track user activities for admin monitoring"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    action = models.CharField(max_length=100)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'user_activities'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.username} - {self.action}"