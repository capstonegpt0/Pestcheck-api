# api/proximity_utils.py
"""
Proximity Alert System - Utilities
Calculates distances between farms and generates proximity alerts
"""
import math
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q
from .models import Farm, PestDetection, Alert, User


# ==================== CONFIGURATION ====================
PROXIMITY_ALERT_CONFIG = {
    'PROXIMITY_RADIUS_KM': 2.0,  # Alert farms within 2km
    'DETECTION_THRESHOLD': 3,     # Trigger alert after 3+ detections
    'TIME_WINDOW_DAYS': 7,        # Count detections from last 7 days
    'ALERT_COOLDOWN_HOURS': 24,   # Don't spam - only one alert per 24 hours per area
}


# ==================== DISTANCE CALCULATION ====================
def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two coordinates using Haversine formula
    Returns distance in kilometers
    """
    # Radius of Earth in kilometers
    R = 6371.0
    
    # Convert degrees to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    
    # Differences
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    
    # Haversine formula
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.arctan2(math.sqrt(a), math.sqrt(1 - a))
    
    distance = R * c
    return distance


def get_nearby_farms(source_farm, radius_km=None):
    """
    Get all farms within specified radius of source farm
    
    Args:
        source_farm: Farm object to search around
        radius_km: Search radius in kilometers (default from config)
    
    Returns:
        List of (farm, distance) tuples sorted by distance
    """
    if radius_km is None:
        radius_km = PROXIMITY_ALERT_CONFIG['PROXIMITY_RADIUS_KM']
    
    all_farms = Farm.objects.exclude(id=source_farm.id)
    nearby_farms = []
    
    for farm in all_farms:
        distance = calculate_distance(
            source_farm.lat, source_farm.lng,
            farm.lat, farm.lng
        )
        
        if distance <= radius_km:
            nearby_farms.append((farm, distance))
    
    # Sort by distance
    nearby_farms.sort(key=lambda x: x[1])
    return nearby_farms


# ==================== DETECTION COUNTING ====================
def count_recent_detections_near_farm(farm, days=None):
    """
    Count active detections near a farm within time window
    
    Args:
        farm: Farm object to check around
        days: Number of days to look back (default from config)
    
    Returns:
        Dictionary with detection counts by pest type
    """
    if days is None:
        days = PROXIMITY_ALERT_CONFIG['TIME_WINDOW_DAYS']
    
    since = timezone.now() - timedelta(days=days)
    radius_km = PROXIMITY_ALERT_CONFIG['PROXIMITY_RADIUS_KM']
    
    # Get all recent active detections
    recent_detections = PestDetection.objects.filter(
        active=True,
        confirmed=True,
        detected_at__gte=since
    )
    
    # Filter by proximity
    nearby_detections = []
    for detection in recent_detections:
        distance = calculate_distance(
            farm.lat, farm.lng,
            detection.latitude, detection.longitude
        )
        
        if distance <= radius_km:
            nearby_detections.append(detection)
    
    # Count by pest type
    pest_counts = {}
    for detection in nearby_detections:
        pest = detection.pest_name or 'Unknown'
        pest_counts[pest] = pest_counts.get(pest, 0) + 1
    
    return {
        'total': len(nearby_detections),
        'by_pest': pest_counts,
        'detections': nearby_detections
    }


# ==================== ALERT CHECKING ====================
def should_create_proximity_alert(farm, detection_data):
    """
    Determine if a proximity alert should be created
    
    Args:
        farm: Farm to check
        detection_data: Result from count_recent_detections_near_farm()
    
    Returns:
        Boolean indicating if alert should be created
    """
    # Check if threshold is met
    if detection_data['total'] < PROXIMITY_ALERT_CONFIG['DETECTION_THRESHOLD']:
        return False
    
    # Check for recent alerts (cooldown period)
    cooldown_hours = PROXIMITY_ALERT_CONFIG['ALERT_COOLDOWN_HOURS']
    recent_alert_cutoff = timezone.now() - timedelta(hours=cooldown_hours)
    
    # Check if similar alert was created recently for this farm
    recent_alerts = Alert.objects.filter(
        created_at__gte=recent_alert_cutoff,
        target_area__icontains=farm.name,
        alert_type='warning'
    )
    
    if recent_alerts.exists():
        return False
    
    return True


# ==================== ALERT CREATION ====================
def create_proximity_alert(affected_farm, detection_data, source_farm_name=None):
    """
    Create a proximity alert for a farm
    
    Args:
        affected_farm: Farm that should receive the alert
        detection_data: Detection count data
        source_farm_name: Name of farm where detections occurred (optional)
    
    Returns:
        Created Alert object or None
    """
    if not should_create_proximity_alert(affected_farm, detection_data):
        return None
    
    # Build alert message
    pest_list = []
    for pest, count in detection_data['by_pest'].items():
        pest_list.append(f"{count} {pest}")
    
    pest_summary = ", ".join(pest_list)
    
    if source_farm_name:
        title = f"⚠️ Pest Activity Detected Near {affected_farm.name}"
        message = (
            f"Warning: {detection_data['total']} pest detection(s) reported within "
            f"{PROXIMITY_ALERT_CONFIG['PROXIMITY_RADIUS_KM']}km of your farm in the past "
            f"{PROXIMITY_ALERT_CONFIG['TIME_WINDOW_DAYS']} days.\n\n"
            f"Detected pests: {pest_summary}\n\n"
            f"Nearby affected area: {source_farm_name}\n\n"
            f"Recommendation: Inspect your crops for similar pest activity and "
            f"implement preventive measures."
        )
    else:
        title = f"⚠️ Pest Activity Detected in Your Area"
        message = (
            f"Warning: {detection_data['total']} pest detection(s) reported within "
            f"{PROXIMITY_ALERT_CONFIG['PROXIMITY_RADIUS_KM']}km of {affected_farm.name} "
            f"in the past {PROXIMITY_ALERT_CONFIG['TIME_WINDOW_DAYS']} days.\n\n"
            f"Detected pests: {pest_summary}\n\n"
            f"Recommendation: Inspect your crops for similar pest activity and "
            f"implement preventive measures."
        )
    
    # Create alert
    # Use system admin or first admin as creator
    admin_user = User.objects.filter(role='admin').first()
    if not admin_user:
        return None
    
    alert = Alert.objects.create(
        title=title,
        message=message,
        alert_type='warning',
        target_area=affected_farm.name,
        is_active=True,
        created_by=admin_user,
        expires_at=timezone.now() + timedelta(days=7)
    )
    
    return alert


# ==================== BULK ALERT GENERATION ====================
def check_and_create_proximity_alerts(detection):
    """
    Check all farms near a new detection and create alerts if needed
    Called automatically when a new detection is confirmed
    
    Args:
        detection: PestDetection object that was just created/confirmed
    
    Returns:
        List of created Alert objects
    """
    created_alerts = []
    
    # Skip if detection is not confirmed or not active
    if not detection.confirmed or not detection.active:
        return created_alerts
    
    # Get the farm where detection occurred
    if not detection.farm:
        return created_alerts
    
    source_farm = detection.farm
    
    # Get nearby farms
    nearby_farms = get_nearby_farms(
        source_farm,
        radius_km=PROXIMITY_ALERT_CONFIG['PROXIMITY_RADIUS_KM']
    )
    
    # For each nearby farm, check if alert should be created
    for farm, distance in nearby_farms:
        detection_data = count_recent_detections_near_farm(farm)
        
        alert = create_proximity_alert(
            affected_farm=farm,
            detection_data=detection_data,
            source_farm_name=source_farm.name
        )
        
        if alert:
            created_alerts.append(alert)
    
    return created_alerts


# ==================== MANUAL ALERT CHECK ====================
def check_proximity_alerts_for_farm(farm):
    """
    Manually check and create proximity alert for a specific farm
    Can be called from admin interface or scheduled tasks
    
    Args:
        farm: Farm object to check
    
    Returns:
        Created Alert object or None
    """
    detection_data = count_recent_detections_near_farm(farm)
    return create_proximity_alert(farm, detection_data)


# ==================== ALERT STATISTICS ====================
def get_proximity_alert_stats():
    """
    Get statistics about proximity alerts in the system
    
    Returns:
        Dictionary with alert statistics
    """
    now = timezone.now()
    last_7_days = now - timedelta(days=7)
    last_24_hours = now - timedelta(hours=24)
    
    return {
        'total_active_alerts': Alert.objects.filter(
            is_active=True,
            alert_type='warning'
        ).count(),
        'alerts_last_7_days': Alert.objects.filter(
            created_at__gte=last_7_days,
            alert_type='warning'
        ).count(),
        'alerts_last_24_hours': Alert.objects.filter(
            created_at__gte=last_24_hours,
            alert_type='warning'
        ).count(),
        'farms_with_alerts': Alert.objects.filter(
            is_active=True,
            alert_type='warning'
        ).values('target_area').distinct().count(),
    }