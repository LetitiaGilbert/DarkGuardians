import torch
from transformers import CLIPProcessor, CLIPModel
from PIL import Image
import requests
from io import BytesIO
import json

TEST_CIDS = [
    "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui",
    "bafybeia4dr36hwlw5pweiglkrvitxb3kxepf5oenm25wgurgfwljcr5jdq",
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
        
        # We ask the AI to compare the image against these labels
        # labels = ["a safe digital asset", "a crypto wallet login page", "a phishing scam website"]
        # labels = [
        #     "a safe digital asset", 
        #     "a crypto wallet login page", 
        #     "a deceptive phishing website",
        #     "a generic photo or everyday object" 
        # ]
        labels = [
            "a photo of an animal or nature",           # Anchor for the dog
            "a generic social media screenshot",        # Anchor for random UI
            "a clean digital art piece or NFT",         # Anchor for actual assets
            "a cryptocurrency wallet login interface",  # TARGET
            "a banking website login form"              # TARGET
        ]
        inputs = processor(text=labels, images=img, return_tensors="pt", padding=True).to(device)
        
        # with torch.no_grad():
        #     probs = model(**inputs).logits_per_image.softmax(dim=1).cpu().numpy()[0]
        
        # threat_score = float(max(probs[1], probs[2]))
        # return {
        #     "cid": cid,
        #     "status": "MALICIOUS" if threat_score > 0.7 else "SAFE",
        #     "score": f"{threat_score:.2%}",
        #     "analysis": labels[probs.argmax()]
        # }
        with torch.no_grad():
            probs = model(**inputs).logits_per_image.softmax(dim=1).cpu().numpy()[0]

        # Malicious indices in the new list: 3 and 4
        malicious_indices = [3, 4]
        winning_idx = probs.argmax()
        threat_score = float(probs[3] + probs[4])

        # Only flag if a malicious label actually WON the classification
        is_malicious = (winning_idx in malicious_indices) and (threat_score > 0.85)
        
        return {
            "cid": cid,
            "status": "MALICIOUS" if is_malicious else "SAFE",
            "threat_confidence": f"{threat_score:.2%}",
            "analysis": labels[winning_idx] if is_malicious else "Content verified as safe/non-phishing"
        }
    except Exception as e:
        return {"cid": cid, "status": "SCAN_ERROR", "error": str(e)}

if __name__ == "__main__":
    results = [scan_cid(c) for c in TEST_CIDS]
    print(json.dumps(results, indent=2))