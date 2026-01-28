"""
Test what your ML service actually returns via the API endpoint
"""

import requests
import json

ML_URL = "https://capstonegpt0-pestcheck-ml.hf.space"

def test_ml_api(image_path, crop_type='rice'):
    """Test the /detect endpoint"""
    print(f"\n{'='*80}")
    print(f"Testing ML API Endpoint")
    print(f"{'='*80}\n")
    
    print(f"Image: {image_path}")
    print(f"Crop: {crop_type}")
    print(f"URL: {ML_URL}/detect\n")
    
    try:
        with open(image_path, "rb") as f:
            files = {"image": f}
            data = {"crop_type": crop_type}
            
            print("📤 Sending request...")
            response = requests.post(
                f"{ML_URL}/detect",
                files=files,
                data=data,
                timeout=120
            )
        
        print(f"📥 Status: {response.status_code}\n")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Full API Response:")
            print(json.dumps(result, indent=2))
            
            print(f"\n{'='*80}")
            print("Key Fields:")
            print(f"{'='*80}")
            print(f"pest_name: '{result.get('pest_name', 'NOT FOUND')}'")
            print(f"pest_key: '{result.get('pest_key', 'NOT FOUND')}'")
            print(f"confidence: {result.get('confidence', 'NOT FOUND')}")
            print(f"severity: '{result.get('severity', 'NOT FOUND')}'")
            print(f"num_detections: {result.get('num_detections', 'NOT FOUND')}")
            
            print(f"\n{'='*80}")
            print("Backend Validation:")
            print(f"{'='*80}")
            
            pest_name = result.get('pest_name', '')
            confidence = result.get('confidence', 0)
            
            print(f"pest_name check: ", end='')
            if not pest_name or pest_name == '':
                print(f"❌ FAIL - Empty")
            elif pest_name == 'Unknown Pest':
                print(f"❌ FAIL - 'Unknown Pest'")
            else:
                print(f"✅ PASS - '{pest_name}'")
            
            print(f"confidence check: ", end='')
            if confidence < 0.1:
                print(f"❌ FAIL - {confidence} < 0.1")
            else:
                print(f"✅ PASS - {confidence}")
            
            is_valid = pest_name and pest_name != 'Unknown Pest' and confidence >= 0.1
            
            print(f"\n{'='*80}")
            if is_valid:
                print("✅✅✅ RESULT: Backend WILL ACCEPT this detection")
            else:
                print("❌❌❌ RESULT: Backend WILL REJECT this detection")
            print(f"{'='*80}\n")
            
            return result
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
            return None
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    print("\n" + "="*80)
    print("ML SERVICE API TEST")
    print("="*80)
    
    # Test with your image
    image_path = input("\nEnter image path (or press Enter for 'test.jpg'): ").strip() or "test.jpg"
    
    print("\n1. Testing with RICE crop type:")
    result1 = test_ml_api(image_path, 'rice')
    
    print("\n\n2. Testing with CORN crop type:")
    result2 = test_ml_api(image_path, 'corn')
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print("\nIf both tests show '✅✅✅ Backend WILL ACCEPT', then:")
    print("  → The problem is in your FRONTEND")
    print("  → Use the Detection_FIXED.jsx file I provided")
    print("\nIf tests show '❌❌❌ Backend WILL REJECT', then:")
    print("  → The ML service is not returning proper pest names")
    print("  → Check your ML service code")
    print("\n")