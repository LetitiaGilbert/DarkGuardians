import torch
torch.set_num_threads(4)
from transformers import CLIPProcessor, CLIPModel, AutoTokenizer, AutoModel
from PIL import Image
import requests
from io import BytesIO
import json
import os
import argparse

TEST_CIDS = [
    "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui",
    "bafybeia4dr36hwlw5pweiglkrvitxb3kxepf5oenm25wgurgfwljcr5jdq",
    "bafkreibyrraiggav25rd7djxk7ekbgd62tflbzel2oxrzw3amrjmlsn6te",
    "bafkreibxnbxru74752ktlbfqh4wtco6wx57dlgiijfbqb6wgodvcj6ugai",
    "QmZ9ZeAH15ybHpZa9Em1YjGf3b9h8UkYoLze46HyxZcHX9"
]

# Output path — ZKP watcher reads from ../scan_results.json relative to circuits/
SCAN_RESULTS_PATH = os.path.join(os.path.dirname(__file__), "scan_results.json")

# MPS is disabled — Anaconda Python has a known mutex lock crash with MPS on macOS.
# CPU is stable and sufficient for CLIP + CodeBERT inference.
# To re-enable MPS later, switch to a non-Anaconda Python (pyenv or brew install python).
device = "cpu"

print(f"hanji -> WhisperGuard Engine Active on {device.upper()} XD")

# Load CLIP model
model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32").to(device)
processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")

# Load CodeBERT model
code_tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
code_model = AutoModel.from_pretrained("microsoft/codebert-base").to(device)


def normalize_confidence(score: float, max_expected: float = 25.0) -> str:
    """
    Convert a raw CodeBERT L2 norm score to a 0–100% confidence string
    so it matches the format the ZKP watcher expects (e.g. "91.23%").
    Clamps to 100% max.
    """
    pct = min((score / max_expected) * 100, 100.0)
    return f"{pct:.2f}%"


def analyze_script(code, content_type=""):
    try:
        # --- Early exit for clearly benign data formats ---
        stripped = code.strip()
        is_json_like = stripped.startswith("{") or stripped.startswith("[")
        is_config_type = any(t in content_type for t in ["json", "yaml", "xml", "plain"])

        if is_json_like and is_config_type:
            return {
                "status": "SAFE",
                "analysis": "Benign data/config file (JSON/YAML/XML)",
                "threat_confidence": "0.00%",
                "engine": "WhisperGuard-CodeBERT-V1"
            }

        # --- Rule-based pattern matching ---
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

        # --- CodeBERT attention-masked mean pooling ---
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
        raw_score = round(torch.norm(embedding).item(), 6)
        threat_confidence = normalize_confidence(raw_score)

        if rule_trigger:
            return {
                "status": "MALICIOUS",
                "analysis": f"Wallet Drainer Pattern(s) Detected: {matched_patterns}",
                "threat_confidence": threat_confidence,
                "engine": "WhisperGuard-CodeBERT-V1"
            }

        return {
            "status": "SAFE",
            "analysis": "No malicious script patterns detected",
            "threat_confidence": threat_confidence,
            "engine": "WhisperGuard-CodeBERT-V1"
        }

    except Exception as e:
        return {
            "status": "SCAN_ERROR",
            "threat_confidence": "0.00%",
            "error": str(e)
        }


def scan_cid(cid):
    url = f"https://ipfs.io/ipfs/{cid}"
    try:
        resp = requests.get(url, timeout=10)
        content_type = resp.headers.get("content-type", "")

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

            analysis_text = (
                ("Crypto-Drainer Signature Detected" if winning_idx == 3 else "Financial UI Detected")
                if is_malicious else "Verified Safe (Common Asset/Object)"
            )

            return {
                "cid": cid,
                "status": "MALICIOUS" if is_malicious else "SAFE",
                "threat_confidence": f"{threat_score * 100:.2f}%",  # normalized to match ZKP format
                "analysis": analysis_text,
                "engine": "WhisperGuard-CLIP-V1"
            }

        # SCRIPT → CodeBERT
        elif "javascript" in content_type or "text" in content_type or "html" in content_type:
            code = resp.text[:5000]
            result = analyze_script(code, content_type)
            result["cid"] = cid
            return result

        else:
            return {
                "cid": cid,
                "status": "UNKNOWN",
                "threat_confidence": "0.00%",
                "analysis": f"Unsupported content type: '{content_type}'",
                "engine": "WhisperGuard"
            }

    except Exception as e:
        return {
            "cid": cid,
            "status": "SCAN_ERROR",
            "threat_confidence": "0.00%",
            "error": str(e)
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WhisperGuard CID scanning engine")
    parser.add_argument("--cid", action="append", help="CID to scan. Repeat flag for multiple CIDs")
    args = parser.parse_args()

    cids_to_scan = args.cid if args.cid else TEST_CIDS
    results = [scan_cid(c) for c in cids_to_scan]

    # Pretty print to console
    print(json.dumps(results, indent=2))

    # Write scan_results.json for the ZKP watcher to consume
    with open(SCAN_RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n✅ scan_results.json written to {SCAN_RESULTS_PATH}")
    print("👀 ZKP watcher will pick this up within 10 seconds")