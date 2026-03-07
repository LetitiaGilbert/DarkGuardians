import torch
from transformers import CLIPProcessor, CLIPModel
from PIL import Image
import requests
from io import BytesIO
import json

TEST_CIDS = [
    "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui",
    "bafybeia4dr36hwlw5pweiglkrvitxb3kxepf5oenm25wgurgfwljcr5jdq",
    "bafkreibyrraiggav25rd7djxk7ekbgd62tflbzel2oxrzw3amrjmlsn6te",
]

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"hanji -> WhisperGuard Engine Active on {device.upper()} XD")

# Load AI Model (CLIP)
model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(device)
processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")

def scan_cid(cid):
    url = f"https://green-voluntary-wolf-674.mypinata.cloud/ipfs/{cid}"
    try:
        resp = requests.get(url, timeout=10)
        img = Image.open(BytesIO(resp.content)).convert("RGB")
        
        labels = [
            "a photo of an animal or nature",         
            "a generic social media screenshot",       
            "a clean digital art piece or NFT",       
            "a cryptocurrency wallet login interface",  
            "a banking website login form"              
        ]
        inputs = processor(text=labels, images=img, return_tensors="pt", padding=True).to(device)
        
        with torch.no_grad():
            probs = model(**inputs).logits_per_image.softmax(dim=1).cpu().numpy()[0]

        malicious_indices = [3, 4]
        winning_idx = probs.argmax()
        threat_score = float(probs[3] + probs[4])

        is_malicious = (winning_idx in malicious_indices) and (threat_score > 0.85)

        if is_malicious:
            analysis_text = "Crypto-Drainer Signature Detected" if winning_idx == 3 else "Financial UI Detected"
        else:
            analysis_text = "Verified Safe (Common Asset/Object)"

        return {
            "cid": cid,
            "status": "MALICIOUS" if is_malicious else "SAFE",
            "threat_confidence": f"{threat_score:.2%}",
            "analysis": analysis_text,
            "engine": "WhisperGuard-CLIP-V1"
        }
        
    except Exception as e:
        return {"cid": cid, "status": "SCAN_ERROR", "error": str(e)}

if __name__ == "__main__":
    results = [scan_cid(c) for c in TEST_CIDS]
    print(json.dumps(results, indent=2))