# DarkGuardians

DarkGuardians detects risky IPFS content using a blockchain-first policy, AI classification, and ZK-backed reporting.

This README is the single source of truth for running the project and doing a live demo.

## What It Does

- Checks CID reputation from Sepolia first.
- If CID is already stored on-chain, returns result immediately (no AI re-scan).
- If CID is new, runs realtime backend pipeline:
  - AI scan
  - AI decision (`block` or `allow`) for immediate frontend action
  - ZK proof generation
  - CID hash map update
  - on-chain submission for future lookups

## Project Components

- `engine.py`: AI scan engine.
- `circuits/generate_proofs.js`: ZK proof generation.
- `scripts/updateCidHashes.js`: updates extension CID-hash map.
- `whisperguard-blockchain/scripts/realtimePipelineServer.js`: realtime API backend.
- `whisperguard-extension/`: browser extension (content + background + popup).

## Prerequisites

- Node.js 18+ (Node 20+ recommended)
- Python 3.10+
- npm
- Sepolia credentials in `whisperguard-blockchain/.env`

Expected env values in `whisperguard-blockchain/.env`:

```env
SEPOLIA_RPC=<your_rpc_url>
PRIVATE_KEY=<your_wallet_private_key>
```

## One-Time Setup

Run these from repository root:

```powershell
pip install -r requirements.txt
npm install --prefix circuits
npm install --prefix whisperguard-blockchain
npm install --prefix whisperguard-extension
```

## Start Realtime Backend API

From repository root:

```powershell
node whisperguard-blockchain/scripts/realtimePipelineServer.js
```

Expected log:

```text
Realtime pipeline server listening at http://127.0.0.1:8787
```

If server does not start:

- If port is already used, stop old process or reuse existing server.
- Verify with:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8787/health"
```

## Browser Extension Setup

1. Open Chrome/Edge extensions page.
2. Enable Developer Mode.
3. Load unpacked extension from `whisperguard-extension`.
4. Reload extension after code changes.

Frontend behavior:

- For stored CID: immediate blockchain verdict.
- For new CID: shows realtime status, decides block/allow once AI result arrives.
- Backend continues proof + blockchain storage asynchronously.

## Demo API (Postman)

Base URL:

```text
http://127.0.0.1:8787
```

### 1) Health Check

- Method: `GET`
- URL: `/health`

### 2) Single Endpoint for Demo Logic

- Method: `POST`
- URL: `/evaluate`
- Body:

```json
{
  "cid": "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui",
  "waitMs": 12000
}
```

Behavior of `/evaluate`:

- If CID exists on-chain:
  - Returns `source: "blockchain"`
  - Returns immediate `decision: "block" | "allow"`
- If CID is new:
  - Starts/reuses backend job
  - Waits up to `waitMs` for AI decision
  - Returns:
    - `source: "ai"` with `decision` when AI is ready, or
    - `source: "pipeline"` + `decision: "pending"` with `jobId`

### 3) Track Realtime Job

- Method: `GET`
- URL: `/jobs/{jobId}`

Shows stages:

- `queued`
- `scanning`
- `ai_decision`
- `proof`
- `mapping`
- `submitting`
- `completed` or `failed`

## Useful Commands

Compile contracts:

```powershell
npm --prefix whisperguard-blockchain run compile
```

One-off full flow for a CID (manual script path):

```powershell
Set-Location whisperguard-blockchain
$env:CID="<cid>"
npx hardhat run scripts/fullFlow.js --network sepolia
```

## Important Notes

- CID hash mapping is read from `whisperguard-extension/cidHashes.json`.
- Keep realtime API running during extension demo.
- Stored CIDs are always blockchain-first and skip AI re-check.
