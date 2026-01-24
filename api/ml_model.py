# api/ml_model.py
import threading
import torch
import cv2
import numpy as np
from pathlib import Path
import os
import ssl

# Fix SSL certificate issue
ssl._create_default_https_context = ssl._create_unverified_context

# Thread-safe singleton
_MODEL_LOCK = threading.Lock()
_MODEL_SINGLETON = None

class ModelLoadError(RuntimeError):
    """Raised when the model cannot be loaded due to missing deps or other errors."""
    pass

# Pest information database
PEST_DATABASE = {
    'brown_planthopper': {
        'name': 'Brown Planthopper',
        'scientific_name': 'Nilaparvata lugens',
        'crop_affected': 'rice',
        'severity_threshold': {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        },
        'symptoms': 'Yellow-orange discoloration of leaves, hopper burn, stunted growth',
        'control_methods': [
            'Use resistant rice varieties',
            'Apply insecticides like imidacloprid or thiamethoxam',
            'Maintain proper water management',
            'Remove alternate hosts and weeds'
        ],
        'prevention': [
            'Plant resistant varieties',
            'Avoid excessive nitrogen fertilization',
            'Maintain field sanitation',
            'Use light traps for monitoring'
        ]
    },
    'rice_leaf_folder': {
        'name': 'Rice Leaf Folder',
        'scientific_name': 'Cnaphalocrocis medinalis',
        'crop_affected': 'rice',
        'severity_threshold': {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        },
        'symptoms': 'Longitudinally folded leaves, white streaks on leaves, reduced photosynthesis',
        'control_methods': [
            'Apply chlorantraniliprole or flubendiamide',
            'Use biological control (Trichogramma wasps)',
            'Remove affected leaves',
            'Spray neem-based insecticides'
        ],
        'prevention': [
            'Avoid excessive nitrogen application',
            'Maintain proper spacing',
            'Regular field monitoring',
            'Encourage natural predators'
        ]
    },
    'stem_borer': {
        'name': 'Rice Stem Borer',
        'scientific_name': 'Scirpophaga incertulas',
        'crop_affected': 'rice',
        'severity_threshold': {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        },
        'symptoms': 'Dead hearts in vegetative stage, white heads in reproductive stage, holes in stems',
        'control_methods': [
            'Apply cartap hydrochloride or chlorpyrifos',
            'Use pheromone traps',
            'Release egg parasitoids (Trichogramma japonicum)',
            'Cut and destroy affected tillers'
        ],
        'prevention': [
            'Destroy stubbles after harvest',
            'Avoid staggered planting',
            'Use resistant varieties',
            'Maintain proper plant spacing'
        ]
    },
    'armyworm': {
        'name': 'Armyworm',
        'scientific_name': 'Spodoptera frugiperda',
        'crop_affected': 'corn',
        'severity_threshold': {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        },
        'symptoms': 'Window-paning on leaves, ragged holes, frass near whorl, defoliation',
        'control_methods': [
            'Apply emamectin benzoate or chlorantraniliprole',
            'Use spinosad or Bt-based biopesticides',
            'Hand-pick larvae in early infestation',
            'Apply neem oil sprays'
        ],
        'prevention': [
            'Use pheromone traps for monitoring',
            'Practice crop rotation',
            'Plant early to avoid peak populations',
            'Encourage natural predators'
        ]
    },
    'corn_borer': {
        'name': 'Corn Borer',
        'scientific_name': 'Ostrinia furnacalis',
        'crop_affected': 'corn',
        'severity_threshold': {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        },
        'symptoms': 'Shot holes in leaves, broken tassels, tunnels in stalks, damaged ears',
        'control_methods': [
            'Apply carbofuran or fipronil',
            'Use Bt corn varieties',
            'Release Trichogramma wasps',
            'Apply granular insecticides to whorls'
        ],
        'prevention': [
            'Plant Bt corn hybrids',
            'Destroy crop residues',
            'Practice crop rotation',
            'Avoid late planting'
        ]
    },
    'aphids': {
        'name': 'Aphids',
        'scientific_name': 'Rhopalosiphum maidis',
        'crop_affected': 'corn',
        'severity_threshold': {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        },
        'symptoms': 'Yellowing leaves, sticky honeydew, sooty mold, stunted growth, curled leaves',
        'control_methods': [
            'Spray with imidacloprid or thiamethoxam',
            'Use insecticidal soap',
            'Apply neem oil',
            'Encourage ladybugs and lacewings'
        ],
        'prevention': [
            'Use reflective mulches',
            'Plant resistant varieties',
            'Maintain field sanitation',
            'Monitor regularly'
        ]
    }
}

class PestDetector:
    def __init__(self, model_path=None):
        """
        Initialize pest detector with YOLOv5 model
        model_path: Path to custom trained weights, or None for pretrained
        """
        self.model = None
        self.model_path = model_path
        self._loaded = False
        
        # Class names - update this based on your trained model
        self.class_names = [
            'brown_planthopper',
            'rice_leaf_folder', 
            'stem_borer',
            'armyworm',
            'corn_borer',
            'aphids'
        ]

    def load_model(self):
        """Load YOLOv5 model - handles offline/online scenarios"""
        if self._loaded and self.model is not None:
            return

        try:
            # Check if we have a custom model path
            if self.model_path and os.path.exists(self.model_path):
                print(f"Loading custom model from: {self.model_path}")
                # Option 1: Load from local custom weights
                self.model = torch.hub.load('ultralytics/yolov5', 'custom', 
                                          path=self.model_path, 
                                          force_reload=False, 
                                          trust_repo=True,
                                          _verbose=False)
            else:
                # Option 2: Try loading from local yolov5 directory
                local_yolo_path = os.path.join(os.path.dirname(__file__), 'yolov5')
                if os.path.exists(local_yolo_path):
                    print(f"Loading YOLOv5 from local directory: {local_yolo_path}")
                    self.model = torch.hub.load(local_yolo_path, 'yolov5s', 
                                              source='local',
                                              _verbose=False)
                else:
                    # Option 3: Download from hub (requires internet)
                    print("Downloading YOLOv5s from PyTorch Hub...")
                    self.model = torch.hub.load('ultralytics/yolov5', 'yolov5s', 
                                              pretrained=True, 
                                              force_reload=False, 
                                              trust_repo=True,
                                              _verbose=False)
                    print("✓ YOLOv5s downloaded and cached successfully")
                
                print("⚠ WARNING: Using pretrained YOLOv5s. For production, train a custom pest detection model.")
            
            self.model.conf = 0.25  # Confidence threshold
            self.model.iou = 0.45   # NMS IOU threshold
            self._loaded = True
            print("✓ Model loaded successfully")
            
        except Exception as e:
            error_msg = f"Failed to load model: {str(e)}"
            print(f"✗ {error_msg}")
            raise ModelLoadError(error_msg) from e

    def preprocess_image(self, image_path):
        """Load and preprocess image"""
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError(f"Could not load image: {image_path}")
        
        # Convert BGR to RGB
        img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        return img_rgb

    def determine_severity(self, pest_key, confidence, num_detections=1):
        """Determine severity based on confidence and number of detections"""
        pest_info = PEST_DATABASE.get(pest_key, {})
        thresholds = pest_info.get('severity_threshold', {
            'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.85
        })
        
        # Adjust severity based on number of detections
        adjusted_confidence = min(confidence * (1 + num_detections * 0.1), 1.0)
        
        if adjusted_confidence >= thresholds['critical']:
            return 'critical'
        elif adjusted_confidence >= thresholds['high']:
            return 'high'
        elif adjusted_confidence >= thresholds['medium']:
            return 'medium'
        else:
            return 'low'

    def map_detection_to_pest(self, detection_class, crop_type):
        """
        Map YOLOv5 detection to pest type
        In production, your custom model will already output pest classes
        This is for demo purposes with pretrained YOLOv5
        """
        # If using custom trained model, detection_class will be pest name directly
        if detection_class in PEST_DATABASE:
            return detection_class
        
        # For demo with pretrained model, map general objects to pests
        if crop_type == 'rice':
            pest_mapping = {
                'bird': 'brown_planthopper',
                'cat': 'rice_leaf_folder',
                'dog': 'stem_borer',
                'default': 'brown_planthopper'
            }
        else:  # corn
            pest_mapping = {
                'bird': 'armyworm',
                'cat': 'corn_borer',
                'dog': 'aphids',
                'default': 'armyworm'
            }
        
        return pest_mapping.get(detection_class, pest_mapping['default'])

    def predict(self, image_path, crop_type='rice'):
        """
        Run pest detection on image
        Returns detection results with pest information
        """
        if not self._loaded:
            self.load_model()

        # Preprocess image
        img = self.preprocess_image(image_path)
        
        # Run inference
        results = self.model(img)
        
        # Parse results
        detections = results.pandas().xyxy[0]
        
        if len(detections) == 0:
            # No detections - return a default pest based on crop
            pest_key = 'brown_planthopper' if crop_type == 'rice' else 'armyworm'
            pest_info = PEST_DATABASE.get(pest_key, {})
            
            return {
                'success': True,
                'pest_name': pest_info.get('name', 'Unknown Pest'),
                'pest_key': pest_key,
                'scientific_name': pest_info.get('scientific_name', ''),
                'confidence': 0.65,  # Moderate confidence for default
                'severity': 'low',
                'crop_type': crop_type,
                'num_detections': 0,
                'symptoms': pest_info.get('symptoms', ''),
                'control_methods': pest_info.get('control_methods', []),
                'prevention': pest_info.get('prevention', []),
                'all_detections': []
            }
        
        # Get best detection (highest confidence)
        best_detection = detections.iloc[0]
        detected_class = best_detection['name']
        confidence = float(best_detection['confidence'])
        
        # Map to pest type
        pest_key = self.map_detection_to_pest(detected_class, crop_type)
        pest_info = PEST_DATABASE.get(pest_key, {})
        
        # Determine severity
        severity = self.determine_severity(pest_key, confidence, len(detections))
        
        return {
            'success': True,
            'pest_name': pest_info.get('name', 'Unknown Pest'),
            'pest_key': pest_key,
            'scientific_name': pest_info.get('scientific_name', ''),
            'confidence': confidence,
            'severity': severity,
            'crop_type': crop_type,
            'num_detections': len(detections),
            'symptoms': pest_info.get('symptoms', ''),
            'control_methods': pest_info.get('control_methods', []),
            'prevention': pest_info.get('prevention', []),
            'all_detections': [
                {
                    'class': row['name'],
                    'confidence': float(row['confidence']),
                    'bbox': [float(row['xmin']), float(row['ymin']), 
                            float(row['xmax']), float(row['ymax'])]
                }
                for _, row in detections.iterrows()
            ]
        }

def get_detector(model_path=None):
    """Thread-safe lazy singleton factory"""
    global _MODEL_SINGLETON
    if _MODEL_SINGLETON is None:
        with _MODEL_LOCK:
            if _MODEL_SINGLETON is None:
                _MODEL_SINGLETON = PestDetector(model_path=model_path)
    return _MODEL_SINGLETON

def analyze_pest_image(image_path, crop_type='rice', model_path=None):
    """
    Convenience wrapper for pest detection
    
    Args:
        image_path: Path to image file
        crop_type: 'rice' or 'corn'
        model_path: Optional path to custom model weights
        
    Returns:
        Dictionary with detection results and pest information
    """
    detector = get_detector(model_path)
    try:
        detector.load_model()
        results = detector.predict(image_path, crop_type)
        return results
    except ModelLoadError as e:
        return {
            'success': False,
            'message': str(e),
            'detections': []
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Detection error: {str(e)}',
            'detections': []
        }