import torch
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

model = torch.hub.load(
    repo_or_dir=os.path.join(BASE_DIR, "yolov5"),
    model="custom",
    path=os.path.join(BASE_DIR, "yolov5", "yolov5s.pt"),
    source="local"
)

model.conf = 0.25  # confidence threshold

def detect_pest(image_path):
    results = model(image_path)

    detections = results.pandas().xyxy[0]

    if detections.empty:
        return None

    top = detections.iloc[0]

    return {
        "pest_name": top["name"],
        "confidence": float(top["confidence"]),
        "bbox": [
            int(top["xmin"]),
            int(top["ymin"]),
            int(top["xmax"]),
            int(top["ymax"]),
        ],
    }
