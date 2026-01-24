from django.db import models

class Detection(models.Model):
    pest_name = models.CharField(max_length=100)
    confidence = models.FloatField()
    crop_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    latitude = models.FloatField()
    longitude = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
