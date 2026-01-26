from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.files.storage import default_storage
from .yolo import detect_pest
from .models import Detection

@method_decorator(csrf_exempt, name='dispatch')
class DetectionView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        image = request.FILES.get("image")

        if not image:
            return Response(
                {"error": "Image is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        crop_type = request.data.get("crop_type")
        latitude = request.data.get("latitude")
        longitude = request.data.get("longitude")

        path = default_storage.save(f"uploads/{image.name}", image)
        full_path = default_storage.path(path)

        result = detect_pest(full_path)

        if not result:
            return Response({
                "pest_name": "No pest detected",
                "confidence": 0,
                "severity": "low",
                "crop_type": crop_type
            })

        conf = result["confidence"]

        severity = (
            "critical" if conf > 0.85 else
            "high" if conf > 0.7 else
            "medium"
        )

        Detection.objects.create(
            pest_name=result["pest_name"],
            confidence=conf,
            crop_type=crop_type,
            severity=severity,
            latitude=latitude,
            longitude=longitude
        )

        return Response({
            "pest_name": result["pest_name"],
            "confidence": conf,
            "severity": severity,
            "crop_type": crop_type
        })
