# backend/api/ml_models/pest_detector.py
"""
Pest detection ML model wrapper
This is a stub implementation that can be replaced with actual YOLOv5 or other ML model
"""

import random
from PIL import Image
import os

# Pest database for mock detection
RICE_PESTS = [
    {
        'name': 'Brown Planthopper',
        'scientific_name': 'Nilaparvata lugens',
        'common_severity': 'high'
    },
    {
        'name': 'Rice Stem Borer',
        'scientific_name': 'Scirpophaga incertulas',
        'common_severity': 'medium'
    },
    {
        'name': 'Rice Leaf Folder',
        'scientific_name': 'Cnaphalocrocis medinalis',
        'common_severity': 'low'
    },
    {
        'name': 'Green Leafhopper',
        'scientific_name': 'Nephotettix virescens',
        'common_severity': 'medium'
    }
]

CORN_PESTS = [
    {
        'name': 'Fall Armyworm',
        'scientific_name': 'Spodoptera frugiperda',
        'common_severity': 'high'
    },
    {
        'name': 'Corn Borer',
        'scientific_name': 'Ostrinia furnacalis',
        'common_severity': 'medium'
    },
    {
        'name': 'Corn Earworm',
        'scientific_name': 'Helicoverpa zea',
        'common_severity': 'medium'
    },
    {
        'name': 'Cutworm',
        'scientific_name': 'Agrotis ipsilon',
        'common_severity': 'low'
    }
]

def detect_pest(image_path, crop_type='rice'):
    """
    Detect pest from image
    
    Args:
        image_path (str): Path to the image file
        crop_type (str): Type of crop ('rice' or 'corn')
    
    Returns:
        dict: Detection results
    """
    try:
        # Verify image exists and is valid
        if not os.path.exists(image_path):
            return {
                'success': False,
                'message': 'Image file not found'
            }
        
        # Try to open image to verify it's valid
        try:
            img = Image.open(image_path)
            img.verify()
            # Reopen after verify
            img = Image.open(image_path)
            width, height = img.size
            
            # Check image size
            if width < 100 or height < 100:
                return {
                    'success': False,
                    'message': 'Image is too small. Please provide a clearer image.'
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'Invalid image file: {str(e)}'
            }
        
        # Select appropriate pest database
        pest_db = RICE_PESTS if crop_type.lower() == 'rice' else CORN_PESTS
        
        # Mock detection - in production, replace with actual ML model
        # For now, randomly select a pest with weighted probabilities
        pest = random.choice(pest_db)
        
        # Generate realistic confidence score
        confidence = random.uniform(0.75, 0.95)
        
        # Determine severity based on pest type and add some randomness
        severity_map = {
            'low': ['low', 'medium'],
            'medium': ['low', 'medium', 'high'],
            'high': ['medium', 'high', 'critical']
        }
        
        base_severity = pest['common_severity']
        possible_severities = severity_map[base_severity]
        severity = random.choice(possible_severities)
        
        return {
            'success': True,
            'pest_name': pest['name'],
            'scientific_name': pest['scientific_name'],
            'confidence': confidence,
            'severity': severity,
            'crop_type': crop_type,
            'detection_method': 'mock',  # Change to 'yolov5' when using real model
            'message': 'Detection successful'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Detection failed: {str(e)}'
        }


def analyze_pest_severity(pest_name, crop_type, image_features=None):
    """
    Analyze pest severity based on pest type and image features
    
    Args:
        pest_name (str): Name of detected pest
        crop_type (str): Type of crop
        image_features (dict): Optional image features for severity assessment
    
    Returns:
        str: Severity level ('low', 'medium', 'high', 'critical')
    """
    # This would use actual image analysis in production
    # For now, return based on pest type
    severity_weights = {
        'Brown Planthopper': 0.8,
        'Rice Stem Borer': 0.6,
        'Fall Armyworm': 0.9,
        'Corn Borer': 0.7,
    }
    
    weight = severity_weights.get(pest_name, 0.5)
    rand = random.random()
    
    if rand < weight * 0.3:
        return 'critical'
    elif rand < weight * 0.6:
        return 'high'
    elif rand < weight * 0.9:
        return 'medium'
    else:
        return 'low'


# ============= REAL ML MODEL INTEGRATION (COMMENTED OUT) =============
# Uncomment and modify this section when you have a trained model

"""
import torch
from pathlib import Path

# Path to your trained model weights
MODEL_PATH = Path(__file__).parent / 'weights' / 'best.pt'

class PestDetectorModel:
    def __init__(self):
        self.model = None
        self.device = None
        
    def load_model(self):
        if self.model is None:
            try:
                # Load YOLOv5 model
                self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
                self.model = torch.hub.load('ultralytics/yolov5', 'custom', 
                                           path=str(MODEL_PATH), 
                                           device=self.device)
                self.model.conf = 0.5  # Confidence threshold
                self.model.iou = 0.45  # NMS IOU threshold
            except Exception as e:
                raise Exception(f"Failed to load model: {str(e)}")
    
    def predict(self, image_path):
        self.load_model()
        
        # Run inference
        results = self.model(image_path)
        
        # Parse results
        detections = results.pandas().xyxy[0]
        
        if len(detections) == 0:
            return {
                'success': False,
                'message': 'No pest detected in image'
            }
        
        # Get highest confidence detection
        best_detection = detections.iloc[0]
        
        return {
            'success': True,
            'pest_name': best_detection['name'],
            'confidence': float(best_detection['confidence']),
            'bbox': [
                float(best_detection['xmin']),
                float(best_detection['ymin']),
                float(best_detection['xmax']),
                float(best_detection['ymax'])
            ]
        }

# Global model instance
_model = PestDetectorModel()

def detect_pest_ml(image_path, crop_type='rice'):
    try:
        result = _model.predict(image_path)
        if result['success']:
            # Determine severity based on pest type
            severity = analyze_pest_severity(result['pest_name'], crop_type)
            result['severity'] = severity
            result['crop_type'] = crop_type
        return result
    except Exception as e:
        return {
            'success': False,
            'message': f'ML detection failed: {str(e)}'
        }
"""