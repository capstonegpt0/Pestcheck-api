def create(self, request):
        """Handles detection via ML API or manual fallback"""
        if 'image' not in request.FILES:
            return self.create_manual_detection(request)

        temp_path = None
        try:
            lat = float(request.data.get('latitude', 0))
            lng = float(request.data.get('longitude', 0))
            crop_type = request.data.get('crop_type', 'rice')
            image = request.FILES.get('image')

            if not image:
                return Response({'error': 'No image provided'}, status=400)

            # Save temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg') as tmp_file:
                for chunk in image.chunks():
                    tmp_file.write(chunk)
                temp_path = tmp_file.name

            print(f"Calling ML API with image: {temp_path}, crop: {crop_type}")
            
            # Call ML API with retry logic
            analysis = call_ml_api(temp_path, crop_type=crop_type)
            
            print(f"ML API response: {analysis}")

            # ✅ CHECK IF PEST WAS ACTUALLY DETECTED
            pest_name = analysis.get('pest_name', '')
            confidence = analysis.get('confidence', 0.0)
            
            # If no pest detected or very low confidence, return error instead of saving
            if not pest_name or pest_name == 'Unknown Pest' or pest_name == '' or confidence < 0.1:
                return Response({
                    'error': 'No pest detected in the image. Please try another image with clearer pest visibility.',
                    'retry': True,
                    'confidence': confidence,
                    'detected': pest_name
                }, status=400)

            # Save detection ONLY if pest was found
            detection = PestDetection.objects.create(
                user=request.user,
                image=image,
                crop_type=crop_type,
                pest_name=pest_name,
                pest_type=analysis.get('pest_key', ''),
                confidence=confidence,
                severity=analysis.get('severity', 'low'),
                latitude=lat,
                longitude=lng,
                address=request.data.get('address', ''),
                description=analysis.get('symptoms', ''),
                status='pending',
                detected_at=timezone.now()
            )
            log_activity(request.user, 'detected_pest', f"Pest: {detection.pest_name}", request)

            # Return enriched response
            serializer = self.get_serializer(detection)
            response_data = serializer.data
            response_data.update({
                'scientific_name': analysis.get('scientific_name', ''),
                'symptoms': analysis.get('symptoms', ''),
                'control_methods': analysis.get('control_methods', []),
                'prevention': analysis.get('prevention', []),
                'num_detections': analysis.get('num_detections', 1)
            })
            return Response(response_data, status=201)

        except Exception as e:
            error_message = str(e)
            print(f"Detection error: {error_message}")
            
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