const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

function cidToNumber(cidString) {
    const hex = Buffer.from(cidString).toString("hex").slice(0, 30);
    return BigInt("0x" + hex);
}

async function generateProofFromScan(scanResult) {
    if (scanResult.status === "SCAN_ERROR") {
        console.log("Skipping — scan errored out");
        return;
    }

    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const CID = cidToNumber(scanResult.cid);
    const reporterSecret = BigInt(Math.floor(Math.random() * 1e15));
    const isMalicious = scanResult.status === "MALICIOUS" ? "1" : "0";

    const cidHash = F.toString(poseidon([CID]));
    const nullifier = F.toString(poseidon([CID, reporterSecret]));

    console.log(`\nGenerating ZK proof for CID: ${scanResult.cid}`);
    console.log(`Status: ${scanResult.status}`);
    console.log(`Confidence: ${scanResult.threat_confidence}`);
    console.log(`cidHash: ${cidHash}`);
    console.log(`nullifier: ${nullifier}`);

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
        scanResult: isMalicious
    };

    const outFile = `proof_${scanResult.cid.slice(-8)}.json`;
    fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
    console.log(`\n✅ Proof saved to ${outFile}`);
    console.log("Ready to submit to Reputation Oracle on-chain!");
}

const engineOutputs = [
    { cid: "bafkreiahcebggvpoaetkf34dwqgjs36edagngk7iji2xewv66ebxzqsiui", status: "MALICIOUS", threat_confidence: "91.23%" },
    { cid: "bafybeia4dr36hwlw5pweiglkrvitxb3kxepf5oenm25wgurgfwljcr5jdq", status: "SAFE", threat_confidence: "12.00%" },
    { cid: "bafkreibyrraiggav25rd7djxk7ekbgd62tflbzel2oxrzw3amrjmlsn6te", status: "MALICIOUS", threat_confidence: "88.50%" }
];

Promise.all(engineOutputs.map(generateProofFromScan)).catch(console.error);