const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

const SCAN_RESULTS_FILE = path.join(__dirname, "../scan_results.json");
const PROCESSED_FILE = path.join(__dirname, "processed_cids.json");

function cidToNumber(cidString) {
    const hex = Buffer.from(cidString).toString("hex").slice(0, 30);
    return BigInt("0x" + hex);
}

function loadProcessed() {
    if (!fs.existsSync(PROCESSED_FILE)) return {};
    return JSON.parse(fs.readFileSync(PROCESSED_FILE));
}

function markProcessed(cid) {
    const processed = loadProcessed();
    processed[cid] = Date.now();
    fs.writeFileSync(PROCESSED_FILE, JSON.stringify(processed, null, 2));
}

async function generateProofFromScan(scanResult) {
    if (scanResult.status === "SCAN_ERROR") {
        console.log(`Skipping ${scanResult.cid} — scan error`);
        return;
    }

    const processed = loadProcessed();
    if (processed[scanResult.cid]) {
        console.log(`Skipping ${scanResult.cid} — already processed`);
        return;
    }

    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const CID = cidToNumber(scanResult.cid);
    const reporterSecret = BigInt(Math.floor(Math.random() * 1e15));
    const isMalicious = scanResult.status === "MALICIOUS" ? "1" : "0";

    const cidHash = F.toString(poseidon([CID]));
    const nullifier = F.toString(poseidon([CID, reporterSecret]));

    console.log(`\nGenerating proof for CID: ${scanResult.cid}`);
    console.log(`Status: ${scanResult.status} | Confidence: ${scanResult.threat_confidence}`);

    const input = {
        CID: CID.toString(),
        reporterSecret: reporterSecret.toString(),
        cidHash,
        scanResult: isMalicious,
        nullifier
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        path.join(__dirname, "cidProof_js/cidProof.wasm"),
        path.join(__dirname, "cidProof_final.zkey")
    );

    const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
    const [a, b, c, pubInputs] = JSON.parse("[" + calldata + "]");

    const output = {
        cid: scanResult.cid,
        status: scanResult.status,
        proof: { a, b, c },
        publicInputs: pubInputs,
        cidHash,
        nullifier,
        scanResult: isMalicious,
        timestamp: Date.now()
    };

    const outFile = path.join(__dirname, `proof_${scanResult.cid.slice(-8)}.json`);
    fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
    console.log(`✅ Proof saved to ${path.basename(outFile)}`);

    markProcessed(scanResult.cid);
}

async function checkForNewScans() {
    if (!fs.existsSync(SCAN_RESULTS_FILE)) {
        console.log("Waiting for scan_results.json...");
        return;
    }

    let results;
    try {
        results = JSON.parse(fs.readFileSync(SCAN_RESULTS_FILE));
    } catch (e) {
        console.log("scan_results.json not ready yet, waiting...");
        return;
    }

    for (const result of results) {
        await generateProofFromScan(result);
    }
}

// Watch for new results every 10 seconds
console.log("👀 WhisperGuard ZKP Watcher running...");
console.log(`Watching for: ${SCAN_RESULTS_FILE}`);
console.log("Press Ctrl+C to stop\n");

checkForNewScans();
setInterval(checkForNewScans, 10000);