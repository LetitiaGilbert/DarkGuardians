const fs = require("fs");
const path = require("path");
const https = require("https");

const OUTPUT_FILE = path.join(__dirname, "scan_queue.json");
const SEEN_FILE = path.join(__dirname, "seen_cids.json");

// ─── Source 1: Simulated dark web known-bad CID list ──────────────────────────
// In production this would be a Tor feed or threat intel API
const KNOWN_BAD_CIDS = [
    "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui",
    "bafkreibyrraiggav25rd7djxk7ekbgd62tflbzel2oxrzw3amrjmlsn6te",
    "bafkreig4hkb5bmbysjjlpbcpgqsyqmydtfrxo7ambomd7jx4tdxlb4dqcq",
    "bafkreihzabgzngkxnclwkkzfzjmjuhmvsdqhkyvxoigzxggfpwzrqcqjce",
];

// ─── Source 2: Public IPFS gateway CIDs to check ─────────────────────────────
// In production this would be IPNI discovery — for MVP we poll known gateways
const PUBLIC_GATEWAY_CIDS = [
    "bafybeia4dr36hwlw5pweiglkrvitxb3kxepf5oenm25wgurgfwljcr5jdq",
    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
    "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354",
];

// ─── Source 3: IPFS network discovery via public IPNI endpoint ────────────────
async function fetchFromIPNI() {
    return new Promise((resolve) => {
        const options = {
            hostname: "cid.contact",
            path: "/random",  // simulated — real IPNI uses /find/cid/<cid>
            method: "GET",
            timeout: 5000
        };

        const req = https.request(options, (res) => {
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => {
                try {
                    // In production parse real IPNI response
                    // For MVP we return empty and rely on other sources
                    resolve([]);
                } catch {
                    resolve([]);
                }
            });
        });

        req.on("error", () => resolve([]));
        req.on("timeout", () => { req.destroy(); resolve([]); });
        req.end();
    });
}

// ─── Seen CID tracker (don't re-queue what we've already scanned) ─────────────
function loadSeen() {
    if (!fs.existsSync(SEEN_FILE)) return {};
    try { return JSON.parse(fs.readFileSync(SEEN_FILE)); }
    catch { return {}; }
}

function markSeen(cids) {
    const seen = loadSeen();
    for (const cid of cids) seen[cid] = Date.now();
    fs.writeFileSync(SEEN_FILE, JSON.stringify(seen, null, 2));
}

// ─── Load existing queue without overwriting unprocessed CIDs ─────────────────
function loadQueue() {
    if (!fs.existsSync(OUTPUT_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(OUTPUT_FILE)); }
    catch { return []; }
}

// ─── Main fetch loop ──────────────────────────────────────────────────────────
async function fetchNewCIDs() {
    console.log(`\n[${new Date().toISOString()}] Fetching new CIDs...`);

    const seen = loadSeen();

    // Gather from all 3 sources
    const fromDarkWeb = KNOWN_BAD_CIDS;
    const fromGateway = PUBLIC_GATEWAY_CIDS;
    const fromIPNI = await fetchFromIPNI();

    const allCIDs = [...new Set([...fromDarkWeb, ...fromGateway, ...fromIPNI])];

    // Filter out already seen CIDs
    const newCIDs = allCIDs.filter(cid => !seen[cid]);

    if (newCIDs.length === 0) {
        console.log("No new CIDs found this cycle.");
        return;
    }

    console.log(`Found ${newCIDs.length} new CIDs to scan:`);
    newCIDs.forEach(cid => console.log(`  + ${cid}`));

    // Append to queue (don't overwrite — engine.py may still be processing)
    const existingQueue = loadQueue();
    const updatedQueue = [...existingQueue, ...newCIDs.map(cid => ({ cid, source: getSource(cid), discovered_at: Date.now() }))];
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(updatedQueue, null, 2));

    markSeen(newCIDs);
    console.log(`✅ Queue updated — ${updatedQueue.length} total pending`);
}

function getSource(cid) {
    if (KNOWN_BAD_CIDS.includes(cid)) return "dark_web_feed";
    if (PUBLIC_GATEWAY_CIDS.includes(cid)) return "public_gateway";
    return "ipni_discovery";
}

// ─── Run every 30 seconds ─────────────────────────────────────────────────────
console.log("🔍 WhisperGuard CID Fetcher running...");
console.log("Polling every 30 seconds. Press Ctrl+C to stop.\n");

fetchNewCIDs();
setInterval(fetchNewCIDs, 30000);