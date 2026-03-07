const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ORACLE_ADDRESS = "0x0403556d47162c91346C5Da245C966df283C0444";
const ABI = ["function getReputation(bytes32 cidHash) view returns(uint256,uint256,string)"];

function runCommand(command, args, cwd) {
  console.log(`\n> ${command} ${args.join(" ")}`);
  execFileSync(command, args, { cwd, stdio: "inherit" });
}

function parseArgs(argv) {
  const cidArg = argv.find((a) => a.startsWith("--cid="));
  const send = argv.includes("--send");
  const maxArg = argv.find((a) => a.startsWith("--max="));
  const envCid = process.env.CID;
  const envSend = process.env.SEND === "1" || process.env.SEND === "true";
  const envMax = process.env.MAX ? Number(process.env.MAX) : undefined;

  if (!cidArg && !envCid) {
    throw new Error("Missing required argument: --cid=<ipfs_cid>");
  }

  const cid = cidArg ? cidArg.split("=")[1] : envCid;
  if (!cid) {
    throw new Error("CID cannot be empty");
  }

  const shouldSend = send || envSend;
  let max = maxArg ? Number(maxArg.split("=")[1]) : (envMax ?? (shouldSend ? 1 : 0));
  if (!Number.isFinite(max) || max < 0) {
    throw new Error("Invalid --max value. Use non-negative integer.");
  }

  return { cid, send: shouldSend, max };
}

function cidToNumber(cidString) {
  const hex = Buffer.from(cidString).toString("hex").slice(0, 30);
  return BigInt("0x" + hex);
}

async function computeCidHashFromProofMap(cid, repoRoot) {
  const mapPath = path.join(repoRoot, "whisperguard-extension", "cidHashes.json");
  let map = {};
  try {
    map = JSON.parse(fs.readFileSync(mapPath, "utf-8"));
  } catch {
    map = {};
  }

  if (map[cid]) {
    return ethers.toBeHex(BigInt(map[cid]), 32);
  }

  // Fallback only if mapping is missing.
  return ethers.toBeHex(cidToNumber(cid), 32);
}

async function main() {
  const { cid, send, max } = parseArgs(process.argv.slice(2));
  const chainName = hre.network.name;

  const repoRoot = path.resolve(__dirname, "../..");
  const circuitsDir = path.join(repoRoot, "circuits");
  const blockchainDir = path.join(repoRoot, "whisperguard-blockchain");

  const cidHash = await computeCidHashFromProofMap(cid, repoRoot);
  const provider = ethers.provider;
  const oracle = new ethers.Contract(ORACLE_ADDRESS, ABI, provider);

  const rep = await oracle.getReputation(cidHash);
  const reports = Number(rep[1]);

  if (reports > 0) {
    console.log("CID already present on-chain. Nothing to submit.");
    console.log(`score=${rep[0].toString()} reports=${rep[1].toString()} category=${rep[2]}`);
    return;
  }

  console.log("CID not present on-chain. Running scan -> proof -> map update pipeline.");

  runCommand("python", ["engine.py", `--cid=${cid}`], repoRoot);
  runCommand("node", ["generate_proofs.js", "--once", `--cid=${cid}`], circuitsDir);
  runCommand("node", [path.join("scripts", "updateCidHashes.js")], repoRoot);

  if (!send) {
    console.log("Dry run complete. No transaction sent. Use --send to submit.");
    return;
  }

  const signers = await ethers.getSigners();
  if (!signers.length) {
    throw new Error("No signer available. Inject PRIVATE_KEY in current terminal session and retry with --send.");
  }

  if (max === 0) {
    console.log("Max submissions is 0, so no transaction will be sent.");
    return;
  }

  const proofFiles = fs.readdirSync(circuitsDir).filter((f) => f.startsWith("proof_") && f.endsWith(".json"));
  const targetProofFile = proofFiles.find((f) => {
    const proof = JSON.parse(fs.readFileSync(path.join(circuitsDir, f), "utf-8"));
    return proof.cid === cid;
  });

  if (!targetProofFile) {
    throw new Error("No proof file found for CID after proof generation step.");
  }

  const proofData = JSON.parse(fs.readFileSync(path.join(circuitsDir, targetProofFile), "utf-8"));
  const scanResults = JSON.parse(fs.readFileSync(path.join(repoRoot, "scan_results.json"), "utf-8"));
  const scan = scanResults.find((r) => r.cid === cid);
  if (!scan) {
    throw new Error("No scan result found for CID.");
  }

  const score = Math.floor(parseFloat(scan.threat_confidence));
  const category = scan.status === "MALICIOUS" ? "malicious" : "safe";
  const proofBytes = ethers.hexlify(ethers.toUtf8Bytes(JSON.stringify(proofData.proof)));
  const nullifier = ethers.toBeHex(BigInt(proofData.nullifier), 32);
  const chainCidHash = ethers.toBeHex(BigInt(proofData.cidHash), 32);

  const signer = signers[0];
  const writableOracle = new ethers.Contract(
    ORACLE_ADDRESS,
    [
      "function submitReport(bytes32 cid,uint256 score,string category,bytes proof,bytes32 nullifier)"
    ],
    signer
  );

  const tx = await writableOracle.submitReport(
    chainCidHash,
    score,
    category,
    proofBytes,
    nullifier
  );
  console.log(`Submitted tx: ${tx.hash}`);
  await tx.wait();
  console.log("Submission step complete.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
