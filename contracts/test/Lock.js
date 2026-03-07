const { expect } = require("chai");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const path = require("path");
const fs = require("fs");

describe("CIDProof Verifier", function () {
    let verifier;

    beforeEach(async function () {
        const Verifier = await ethers.getContractFactory("Groth16Verifier");
        verifier = await Verifier.deploy();
        await verifier.waitForDeployment();
    });

    it("should verify a valid proof on-chain", async function () {
        const poseidon = await buildPoseidon();
        const F = poseidon.F;

        const CID = BigInt("123456789");
        const reporterSecret = BigInt("987654321");

        const cidHash = F.toString(poseidon([CID]));
        const nullifier = F.toString(poseidon([CID, reporterSecret]));

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            {
                CID: CID.toString(),
                reporterSecret: reporterSecret.toString(),
                cidHash,
                scanResult: "1",
                nullifier
            },
            path.join(__dirname, "../../circuits/cidProof_js/cidProof.wasm"),
            path.join(__dirname, "../../circuits/cidProof_final.zkey")
        );

        const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
        const [a, b, c, input] = JSON.parse("[" + calldata + "]");

        const result = await verifier.verifyProof(a, b, c, input);
        expect(result).to.equal(true);
        console.log("✅ On-chain verification passed!");
    });

    it("should reject a fake proof", async function () {
        const fakeA = ["0x0000000000000000000000000000000000000000000000000000000000000001",
                       "0x0000000000000000000000000000000000000000000000000000000000000002"];
        const fakeB = [
            ["0x0000000000000000000000000000000000000000000000000000000000000001",
             "0x0000000000000000000000000000000000000000000000000000000000000002"],
            ["0x0000000000000000000000000000000000000000000000000000000000000003",
             "0x0000000000000000000000000000000000000000000000000000000000000004"]
        ];
        const fakeC = ["0x0000000000000000000000000000000000000000000000000000000000000001",
                       "0x0000000000000000000000000000000000000000000000000000000000000002"];
        const fakeInput = ["0x0000000000000000000000000000000000000000000000000000000000000000",
                           "0x0000000000000000000000000000000000000000000000000000000000000001",
                           "0x0000000000000000000000000000000000000000000000000000000000000000"];

        const result = await verifier.verifyProof(fakeA, fakeB, fakeC, fakeInput);
        expect(result).to.equal(false);
        console.log("✅ Fake proof correctly rejected!");
    });
});