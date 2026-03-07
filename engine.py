import torch
torch.set_num_threads(4)
from transformers import CLIPProcessor, CLIPModel, AutoTokenizer, AutoModel
from PIL import Image
import requests
from io import BytesIO
import json

TEST_CIDS = [
    "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui",
    "bafybeia4dr36hwlw5pweiglkrvitxb3kxepf5oenm25wgurgfwljcr5jdq",
    "bafkreibyrraiggav25rd7djxk7ekbgd62tflbzel2oxrzw3amrjmlsn6te",
    "bafkreibxnbxru74752ktlbfqh4wtco6wx57dlgiijfbqb6wgodvcj6ugai",
    "QmZ9ZeAH15ybHpZa9Em1YjGf3b9h8UkYoLze46HyxZcHX9"
]

if torch.backends.mps.is_available():
    device = "mps"
elif torch.cuda.is_available():
    device = "cuda"
else:
    device = "cpu"

print(f"hanji -> WhisperGuard Engine Active on {device.upper()} XD")

# Load CLIP model
model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(device)
processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")

# Load CodeBERT model
code_tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
code_model = AutoModel.from_pretrained("microsoft/codebert-base").to(device)


def analyze_script(code, content_type=""):
    try:
        stripped = code.strip()
        is_json_like = stripped.startswith("{") or stripped.startswith("[")
        is_config_type = any(t in content_type for t in ["json", "yaml", "xml", "plain"])

        if is_json_like and is_config_type:
            return {
                "status": "SAFE",
                "analysis": "Benign data/config file (JSON/YAML/XML)",
                "confidence": 0.0,
                "engine": "WhisperGuard-CodeBERT-V1"
            }

        drainer_patterns = [
            "eth_sendTransaction",
            "setApprovalForAll",
            "approve(",
            "transferFrom(",
            "wallet_switchEthereumChain",
            "permit("
        ]
        matched_patterns = [p for p in drainer_patterns if p in code]
        rule_trigger = len(matched_patterns) > 0

        inputs = code_tokenizer(
            code,
            return_tensors="pt",
            truncation=True,
            max_length=512
        ).to(device)

        with torch.no_grad():
            outputs = code_model(**inputs)

        attention_mask = inputs["attention_mask"]
        token_embeddings = outputs.last_hidden_state
        mask_expanded = attention_mask.unsqueeze(-1).float()
        embedding = (token_embeddings * mask_expanded).sum(dim=1) / mask_expanded.sum(dim=1).clamp(min=1e-9)
        score = round(torch.norm(embedding).item(), 6)

        if rule_trigger:
            return {
                "status": "MALICIOUS",
                "analysis": f"Wallet Drainer Pattern(s) Detected: {matched_patterns}",
                "confidence": score,
                "engine": "WhisperGuard-CodeBERT-V1"
            }

        return {
            "status": "SAFE",
            "analysis": "No malicious script patterns detected",
            "confidence": score,
            "engine": "WhisperGuard-CodeBERT-V1"
        }

    except Exception as e:
        return {
            "status": "SCAN_ERROR",
            "error": str(e)
        }


def scan_cid(cid):
    url = f"https://ipfs.io/ipfs/{cid}"
    try:
        resp = requests.get(url, timeout=10)
        content_type = resp.headers.get("content-type", "")

        # Debug log — shows exactly what Pinata served so routing is transparent
        print(f"[DEBUG] CID={cid[:20]}... | content-type='{content_type}' | size={len(resp.content)}B")

        # IMAGE → CLIP
        if "image" in content_type:
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
        elif "javascript" in content_type or "text" in content_type or "html" in content_type:
            code = resp.text[:5000]
            result = analyze_script(code, content_type)
            result["cid"] = cid
            return result

        else:
            return {
                "cid": cid,
                "status": "UNKNOWN",
                "analysis": f"Unsupported content type: '{content_type}'",
                "engine": "WhisperGuard"
            }

    except Exception as e:
        return {"cid": cid, "status": "SCAN_ERROR", "error": str(e)}


if __name__ == "__main__":
    results = [scan_cid(c) for c in TEST_CIDS]
    print(json.dumps(results, indent=2))