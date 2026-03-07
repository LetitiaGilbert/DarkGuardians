const snarkjs = require("snarkjs");
const fs = require("fs");
const { buildPoseidon } = require("circomlibjs");

async function main() {
    // Build poseidon hasher
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const CID = BigInt("123456789");
    const reporterSecret = BigInt("987654321");

    // Compute cidHash = Poseidon(CID)
    const cidHashRaw = poseidon([CID]);
    const cidHash = F.toString(cidHashRaw);

    // Compute nullifier = Poseidon(CID, reporterSecret)
    const nullifierRaw = poseidon([CID, reporterSecret]);
    const nullifier = F.toString(nullifierRaw);

    console.log("cidHash:", cidHash);
    console.log("nullifier:", nullifier);

    const input = {
        CID: CID.toString(),
        reporterSecret: reporterSecret.toString(),
        cidHash: cidHash,
        scanResult: "1",
        nullifier: nullifier
    };

    console.log("Generating proof...");
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        "cidProof_js/cidProof.wasm",
        "cidProof_final.zkey"
    );

    console.log("Public signals:", publicSignals);

    const vkey = JSON.parse(fs.readFileSync("verification_key.json"));
    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    console.log("Proof valid:", isValid);
}

main().catch(console.error);