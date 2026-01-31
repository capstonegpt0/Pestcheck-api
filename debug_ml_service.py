"""
Direct HuggingFace ML Service Debugger
This will show us EXACTLY why no detections are happening
"""

import requests
import os

ML_URL = "https://capstonegpt0-pestcheck-ml.hf.space"

print("\n" + "="*80)
print("HUGGINGFACE ML SERVICE DEBUG")
print("="*80)

# Step 1: Check if service is online
print("\n1. Testing service availability...")
try:
    response = requests.get(f"{ML_URL}/", timeout=10)
    print(f"   ✅ Service is online: {response.json()}")
except Exception as e:
    print(f"   ❌ Service is offline: {e}")
    exit(1)

# Step 2: Check model info
print("\n2. Testing model info...")
try:
    response = requests.get(f"{ML_URL}/model-info", timeout=10)
    model_info = response.json()
    print(f"   ✅ Model loaded: {model_info.get('model_type')}")
    print(f"   ✅ Number of classes: {model_info.get('num_classes')}")
    print(f"   ✅ Classes: {model_info.get('model_classes')}")
except Exception as e:
    print(f"   ❌ Model info failed: {e}")
    exit(1)

# Step 3: Test detection with your image
print("\n3. Testing detection with YOUR image...")
print("   Make sure test.jpg exists in current directory!")

# Check if test.jpg exists
if not os.path.exists('test.jpg'):
    print("   ❌ ERROR: test.jpg not found!")
    print("   → Copy your test image to this directory and rename it to 'test.jpg'")
    exit(1)

try:
    with open('test.jpg', 'rb') as f:
        files = {'image': f}
        data = {'crop_type': 'corn'}  # Change to 'corn' if needed
        
        print(f"   📤 Sending request to {ML_URL}/detect")
        response = requests.post(
            f"{ML_URL}/detect",
            files=files,
            data=data,
            timeout=120
        )
    
    print(f"   📥 Response status: {response.status_code}")
    result = response.json()
    
    print("\n" + "="*80)
    print("DETECTION RESULT:")
    print("="*80)
    print(f"pest_name: '{result.get('pest_name', '')}'")
    print(f"confidence: {result.get('confidence', 0.0)}")
    print(f"num_detections: {result.get('num_detections', 0)}")
    print(f"severity: {result.get('severity', '')}")
    
    if result.get('error'):
        print(f"\n❌ ERROR: {result.get('error')}")
    
    print("\n" + "="*80)
    print("FULL RESPONSE:")
    print("="*80)
    import json
    print(json.dumps(result, indent=2))
    
    # Analysis
    print("\n" + "="*80)
    print("DIAGNOSIS:")
    print("="*80)
    
    if result.get('num_detections', 0) == 0:
        print("❌ ML Service found ZERO detections in the image")
        print("\nPossible reasons:")
        print("1. Image doesn't contain the pests the model was trained on")
        print("2. Confidence threshold too high (currently 0.25)")
        print("3. Image quality/size issues")
        print("4. Wrong model file on HuggingFace")
        print("\nWhat you can try:")
        print("- Lower confidence threshold in app.py: model.conf = 0.15")
        print("- Upload a different test image with clearer pest")
        print("- Verify best.pt on HuggingFace is the same as local")
    elif not result.get('pest_name') or result.get('pest_name') == '':
        print("❌ Detections found but pest_name is empty")
        print("This means app.py still has the bug!")
        print("Check line 218-220 in HuggingFace app.py")
    else:
        print(f"✅ Detection successful!")
        print(f"   Pest: {result.get('pest_name')}")
        print(f"   Confidence: {result.get('confidence')*100:.1f}%")
        
except Exception as e:
    print(f"   ❌ Detection request failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("NEXT STEPS:")
print("="*80)
print("""
If num_detections = 0:
  → The model isn't detecting anything in your image
  → Try a different image or lower the confidence threshold

If pest_name is empty but num_detections > 0:
  → HuggingFace app.py still has the old bug
  → Re-upload your fixed app.py to HuggingFace

If you see detections with valid pest_name:
  → ML service is working!
  → Check backend validation logs
""")