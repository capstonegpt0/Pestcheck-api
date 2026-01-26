from django.urls import path
from .views import DetectionView

urlpatterns = [
    path('', DetectionView.as_view()),
]
